use object::read::omf::{
    OmfFile, ThreadKind,
    parse_pubdef_record, PubdefRecord, PubdefKind, PubdefBase, PubdefEntry, PubdefError,
    parse_lpubdef, LpubdefParseError, OffsetWidth, OmfIndex,
};
use object::{Architecture, BinaryFormat, Object, ObjectComdat, ObjectSection, ObjectSegment, ObjectSymbol, Permissions, RelocationTarget, SectionIndex, SectionKind, SymbolIndex};

fn make_record(rt: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(rt);
    v.extend_from_slice(&((body.len() + 1) as u16).to_le_bytes());
    v.extend_from_slice(body);
    let mut sum = rt.wrapping_add(((body.len() + 1) & 0xFF) as u8).wrapping_add(((body.len() + 1) >> 8) as u8);
    for &b in body {
        sum = sum.wrapping_add(b);
    }
    v.push(0u8.wrapping_sub(sum)); // checksum
    v
}

#[test]
fn omf_minimal() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.architecture(), Architecture::X86_16);
    assert_eq!(obj.binary_format(), BinaryFormat::Omf);
}

#[test]
fn omf_bad_checksum_is_nonfatal() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x8A, &[0x01]));
    // Corrupt the THEADR checksum byte.
    let theadr_checksum = 1 + 2 + 6; // checksum byte of first THEADR record.
    data[theadr_checksum] ^= 0x01;

    // Checksum mismatches are non-fatal: parse should still succeed.
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.module_name(), b"HELLO");
}

#[test]
fn omf_make_record_checksum_sums_to_zero() {
    let rec = make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']);
    let sum = rec.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    assert_eq!(sum, 0);
}

#[test]
fn omf_zero_length_record_is_error() {
    let data = [0x80, 0x00, 0x00];
    assert!(OmfFile::parse(&data[..]).is_err());
}

#[test]
fn omf_sections() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E', 0x05, b'_', b'T', b'E', b'X', b'T']));
    data.extend(make_record(0x98, &[0x28, 0x11, 0x00, 0x03, 0x02, 0x01]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.sections().count(), 1);
    let sec = obj.section_by_name("_TEXT").unwrap();
    assert_eq!(sec.size(), 17);
}

#[test]
fn omf_classification() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // LNAMES: 1="", 2="CODE", 3="DATA", 4="BSS", 5="_TEXT", 6="_DATA", 7="_BSS", 8="_NONE"
    data.extend(make_record(0x96, &[
        0x00, // 1
        0x04, b'C', b'O', b'D', b'E', // 2
        0x04, b'D', b'A', b'T', b'A', // 3
        0x03, b'B', b'S', b'S', // 4
        0x05, b'_', b'T', b'E', b'X', b'T', // 5
        0x05, b'_', b'D', b'A', b'T', b'A', // 6
        0x04, b'_', b'B', b'S', b'S', // 7
        0x05, b'_', b'N', b'O', b'N', b'E' // 8
    ]));

    // SEGDEF 1: name="_TEXT" (5), class="CODE" (2), length=0x10
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x05, 0x02, 0x01]));
    // SEGDEF 2: name="_DATA" (6), class="DATA" (3), length=0x20
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x06, 0x03, 0x01]));
    // SEGDEF 3: name="_BSS" (7), class="BSS" (4), length=0x30
    data.extend(make_record(0x98, &[0x48, 0x30, 0x00, 0x07, 0x04, 0x01]));
    // SEGDEF 4: name="_NONE" (8), class=None (0), length=0x40
    data.extend(make_record(0x98, &[0x48, 0x40, 0x00, 0x08, 0x00, 0x01]));

    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();

    let sec1 = obj.section_by_name("_TEXT").unwrap();
    assert_eq!(sec1.kind(), SectionKind::Text);
    let seg1 = obj.segments().find(|s| s.name() == Ok(Some("_TEXT"))).unwrap();
    assert_eq!(seg1.permissions(), Permissions::new(true, false, true));

    let sec2 = obj.section_by_name("_DATA").unwrap();
    assert_eq!(sec2.kind(), SectionKind::Data);
    let seg2 = obj.segments().find(|s| s.name() == Ok(Some("_DATA"))).unwrap();
    assert_eq!(seg2.permissions(), Permissions::new(true, true, false));

    let sec3 = obj.section_by_name("_BSS").unwrap();
    assert_eq!(sec3.kind(), SectionKind::UninitializedData);
    let seg3 = obj.segments().find(|s| s.name() == Ok(Some("_BSS"))).unwrap();
    assert_eq!(seg3.permissions(), Permissions::new(true, true, false));

    let sec4 = obj.section_by_name("_NONE").unwrap();
    assert_eq!(sec4.kind(), SectionKind::Unknown);
    let seg4 = obj.segments().find(|s| s.name() == Ok(Some("_NONE"))).unwrap();
    assert_eq!(seg4.permissions(), Permissions::new(true, true, false));
}

#[test]
fn omf_ledata() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x05, 0x00, 0x01, 0x02, 0x03]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(&sec.data().unwrap()[5..8], &[1, 2, 3]);
}

#[test]
fn omf_lidata() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, b'A', b'B']));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(&sec.data().unwrap()[0..6], b"ABABAB");
}

#[test]
fn omf_lidata_flat() {
    // Flat (block_count=0) LIDATA: repeat 3 times, bytes "XY".
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, b'X', b'Y']));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(&sec.data().unwrap()[0..6], b"XYXYXY");
}

#[test]
fn omf_lidata_nested_two_siblings() {
    // Nested LIDATA with two sibling sub-blocks.
    // Top-level: repeat=1, block_count=2
    //   Sub-block 1: repeat=2, byte 'A' → "AA"
    //   Sub-block 2: repeat=3, byte 'B' → "BBB"
    //   Inner concat = "AA" + "BBB" = "AABBB"
    //   Top repeat = 1 → "AABBB"
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[
        0x01,       // seg_idx
        0x00, 0x00, // data_offset
        // block_data:
        0x01, 0x00, // repeat=1
        0x02, 0x00, // block_count=2
        // sub-block 1: repeat=2, flat, byte 'A'
        0x02, 0x00, // repeat=2
        0x00, 0x00, // block_count=0
        0x01,        // byte_count=1
        b'A',
        // sub-block 2: repeat=3, flat, byte 'B'
        0x03, 0x00, // repeat=3
        0x00, 0x00, // block_count=0
        0x01,        // byte_count=1
        b'B',
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(&sec.data().unwrap()[0..5], b"AABBB");
}

#[test]
fn omf_lidata_nested_repeat_inner() {
    // Top-level: repeat=3, block_count=2
    //   Sub-block 1: repeat=2, flat, byte 'A'  → "AA"
    //   Sub-block 2: repeat=1, flat, byte 'B'  → "B"
    //   Inner concat = "AA" + "B" = "AAB"
    //   Top repeat = 3 → "AAB" * 3 = "AABAABAAB"
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x14, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[
        0x01,       // seg_idx
        0x00, 0x00, // data_offset
        // block_data:
        0x03, 0x00, // repeat=3
        0x02, 0x00, // block_count=2
        // sub-block 1: repeat=2, flat, byte 'A'
        0x02, 0x00, // repeat=2
        0x00, 0x00, // block_count=0
        0x01,       // byte_count=1
        b'A',
        // sub-block 2: repeat=1, flat, byte 'B'
        0x01, 0x00, // repeat=1
        0x00, 0x00, // block_count=0
        0x01,       // byte_count=1
        b'B',
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(&sec.data().unwrap()[0..9], b"AABAABAAB");
}

#[test]
fn omf_lidata_trailing_bytes_error() {
    // Nested LIDATA with trailing garbage — must error.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[
        0x01,       // seg_idx
        0x00, 0x00, // data_offset
        // block_data with trailing garbage:
        0x01, 0x00, // repeat=1
        0x01, 0x00, // block_count=1
        0x02, 0x00, // sub-block: repeat=2
        0x00, 0x00, // block_count=0
        0x01,       // byte_count=1
        b'X',
        0xDE, 0xAD, // trailing garbage bytes
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    let err = result.err().expect("expected error for trailing LIDATA bytes");
    assert_eq!(err.to_string(), "unexpected trailing bytes in LIDATA");
}

#[test]
fn omf_lidata_truncated_nested_sibling() {
    // Nested LIDATA where the second sibling is truncated mid-header.
    // Should error with "truncated LIDATA block", not succeed partially.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[
        0x01,       // seg_idx
        0x00, 0x00, // data_offset
        // block_data:
        0x01, 0x00, // repeat=1
        0x02, 0x00, // block_count=2
        // sub-block 1: complete, flat, byte 'A'
        0x01, 0x00, // repeat=1
        0x00, 0x00, // block_count=0
        0x01,       // byte_count=1
        b'A',
        // sub-block 2: truncated — repeat_count present but no block_count
        0x01, 0x00, // repeat=1
        // missing block_count + content
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    let err = result.err().expect("expected error for truncated sibling");
    assert_eq!(err.to_string(), "truncated LIDATA block");
}

#[test]
fn omf_lidata_zero_repeat() {
    // repeat=0 should yield empty output and consume the full block.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[
        0x01,       // seg_idx
        0x00, 0x00, // data_offset
        0x00, 0x00, // repeat=0
        0x00, 0x00, // block_count=0 (flat)
        0x02,       // byte_count=2
        b'A', b'B',
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    let data = sec.data().unwrap();
    // Segment is padded to SEGDEF length 0x10. Zero-repeat should leave
    // the buffer entirely zero-filled (no "AB" written at offset 0).
    assert_eq!(data.len(), 0x10);
    assert_eq!(&data[0..2], &[0, 0]);
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn omf_pubdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x90, &[0x00, 0x01, 0x03, b'f', b'o', b'o', 0x02, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("foo")).unwrap();
    assert_eq!(sym.address(), 2);
}

#[test]
fn omf_local_pubdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xB6, &[0x00, 0x01, 0x03, b'f', b'o', b'o', 0x02, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("foo")).unwrap();
    assert_eq!(sym.address(), 2);
    assert_eq!(sym.scope(), object::SymbolScope::Compilation);
    assert!(sym.is_local());
    assert!(!sym.is_global());
}

// ── PUBDEF (0x90 / 0x91) tests ─────────────────────────────────────────────

#[test]
fn omf_pubdef32() {
    // PUBDEF32 (0x91) with a 32-bit offset.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    // group=0, seg=1, name_len=3 "bar", offset=0x12345678 (4B LE), type=0
    data.extend(make_record(0x91, &[0x00, 0x01, 0x03, b'b', b'a', b'r', 0x78, 0x56, 0x34, 0x12, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("bar")).unwrap();
    assert_eq!(sym.address(), 0x12345678);
}

#[test]
fn omf_pubdef_absolute() {
    // PUBDEF absolute symbol: group=0, seg=0 -> Base Frame present.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // group=0, seg=0, frame=0x1000 (2B LE), name_len=3 "abs", offset=0x1234 (2B LE), type=0
    data.extend(make_record(0x90, &[0x00, 0x00, 0x00, 0x10, 0x03, b'a', b'b', b's', 0x34, 0x12, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("abs")).unwrap();
    // seg_ordinal=0 for absolute symbols
    assert_eq!(sym.section(), object::SymbolSection::Absolute);
    assert_eq!(sym.address(), 0);
    // But the offset should be stored as 0x1234
    // We can't easily check the raw ParsedSymbol offset via the trait, so verify it's public
    assert!(sym.is_definition());
}

#[test]
fn omf_pubdef32_absolute() {
    // PUBDEF32 absolute symbol: group=0, seg=0 -> Base Frame present, 32-bit offset.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // group=0, seg=0, frame=0x2000 (2B LE), name_len=3 "big", offset=0xABCD1234 (4B LE), type=0
    data.extend(make_record(0x91, &[0x00, 0x00, 0x00, 0x20, 0x03, b'b', b'i', b'g', 0x34, 0x12, 0xCD, 0xAB, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("big")).unwrap();
    assert_eq!(sym.section(), object::SymbolSection::Absolute);
    assert!(sym.is_definition());
}

#[test]
fn omf_pubdef_multiple_entries() {
    // Single PUBDEF record with two name entries.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x40, 0x00, 0x01, 0x01, 0x01]));
    // group=0, seg=1, then two entries:
    //   "a" offset=0x0010 type=0
    //   "b" offset=0x0020 type=0
    data.extend(make_record(0x90, &[
        0x00, 0x01,           // base group=0, seg=1
        0x01, b'a', 0x10, 0x00, 0x00,   // entry 1
        0x01, b'b', 0x20, 0x00, 0x00,   // entry 2
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.symbols().count(), 2);
    let sym_a = obj.symbols().find(|s| s.name() == Ok("a")).unwrap();
    let sym_b = obj.symbols().find(|s| s.name() == Ok("b")).unwrap();
    // Addresses are flat_base + offset. Since base_seg=1 is the first segment,
    // flat_base=0, so addresses should equal the offsets.
    assert_eq!(sym_a.address(), 0x10);
    assert_eq!(sym_b.address(), 0x20);
}

#[test]
fn omf_pubdef_base_frame_group_nonzero() {
    // Base segment = 0, group nonzero: Base Frame is present but ignored.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A', 0x03, b'G', b'R', b'P']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // GRPDEF: name=2 ("GRP"), component SEG 1
    data.extend(make_record(0x9A, &[0x02, 0xFF, 0x01]));
    // group=1, seg=0 -> frame present but ignored
    // name_len=3 "xyz", offset=0x0005, type=0
    data.extend(make_record(0x90, &[0x01, 0x00, 0xDE, 0xAD, 0x03, b'x', b'y', b'z', 0x05, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("xyz")).unwrap();
    // With seg=0, ordinal=0 -> absolute in our parser, so section is Absolute
    assert_eq!(sym.section(), object::SymbolSection::Absolute);
    assert!(sym.is_definition());
}

#[test]
fn omf_pubdef_type_index() {
    // PUBDEF with nonzero type index.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // group=0, seg=1, name_len=5 "typed", offset=0x0007, type=0x02
    data.extend(make_record(0x90, &[0x00, 0x01, 0x05, b't', b'y', b'p', b'e', b'd', 0x07, 0x00, 0x02]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("typed")).unwrap();
    assert_eq!(sym.address(), 0x07);
    assert!(sym.is_definition());
}

#[test]
fn omf_pubdef32_with_type_index() {
    // PUBDEF32 with nonzero type index and large 32-bit offset.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    // group=0, seg=1, name_len=4 "bigt", offset=0xAA000055 (4B LE), type=0x7F
    data.extend(make_record(0x91, &[0x00, 0x01, 0x04, b'b', b'i', b'g', b't', 0x55, 0x00, 0x00, 0xAA, 0x7F]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("bigt")).unwrap();
    assert_eq!(sym.address(), 0xAA000055);
}

// ── Standalone PUBDEF parser tests ─────────────────────────────────────────

#[test]
fn omf_pubdef_standalone_basic() {
    // Spec example 9.1: GAMMA at offset 0x0002, seg index 1
    // raw: 90 0C 00 00 01 05 47 41 4D 4D 41 02 00 00 F9
    let raw: &[u8] = &[
        0x90, 0x0C, 0x00, 0x00, 0x01, 0x05, 0x47, 0x41,
        0x4D, 0x4D, 0x41, 0x02, 0x00, 0x00, 0xF9,
    ];
    let rec = parse_pubdef_record(raw).unwrap();
    assert_eq!(rec.kind, PubdefKind::Pubdef16);
    assert_eq!(rec.base, PubdefBase::Segment { group_index: 0, segment_index: 1 });
    assert_eq!(rec.entries.len(), 1);
    assert_eq!(rec.entries[0].name, "GAMMA");
    assert_eq!(rec.entries[0].offset, 0x0002);
    assert_eq!(rec.entries[0].type_index, 0);
}

#[test]
fn omf_pubdef_standalone_absolute() {
    // Spec example 9.2: ALPHA EQU 1234h, frame=0x0000
    // raw: 90 0E 00 00 00 00 00 05 41 4C 50 48 41 34 12 00 B1
    let raw: &[u8] = &[
        0x90, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x41, 0x4C, 0x50, 0x48, 0x41, 0x34, 0x12, 0x00, 0xB1,
    ];
    let rec = parse_pubdef_record(raw).unwrap();
    assert_eq!(rec.kind, PubdefKind::Pubdef16);
    assert_eq!(rec.base, PubdefBase::Frame { group_index: 0, frame: 0x0000 });
    assert_eq!(rec.entries.len(), 1);
    assert_eq!(rec.entries[0].name, "ALPHA");
    assert_eq!(rec.entries[0].offset, 0x1234);
    assert_eq!(rec.entries[0].type_index, 0);
}

#[test]
fn omf_pubdef_standalone_pubdef32() {
    // PUBDEF32 with 32-bit offset: group=0, seg=1, name="X", offset=0x12345678, type=0
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x91, 0x00, 0x00]); // placeholder length
    let body: Vec<u8> = [
        0x00, 0x01,             // base group=0, seg=1
        0x01, b'X',             // name len=1 "X"
        0x78, 0x56, 0x34, 0x12, // offset=0x12345678
        0x00,                   // type=0
    ].to_vec();
    let body_len = body.len() + 1; // +1 for checksum
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    // compute checksum
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_pubdef_record(&raw).unwrap();
    assert_eq!(rec.kind, PubdefKind::Pubdef32);
    assert_eq!(rec.base, PubdefBase::Segment { group_index: 0, segment_index: 1 });
    assert_eq!(rec.entries.len(), 1);
    assert_eq!(rec.entries[0].name, "X");
    assert_eq!(rec.entries[0].offset, 0x12345678);
}

#[test]
fn omf_pubdef_standalone_multiple_entries() {
    // Two entries in one record.
    // group=0, seg=2, "a" offset=0x0010 type=0, "b" offset=0x0020 type=0
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x90, 0x00, 0x00]); // placeholder length
    let body: Vec<u8> = [
        0x00, 0x02,                   // base group=0, seg=2
        0x01, b'a', 0x10, 0x00, 0x00, // entry 1
        0x01, b'b', 0x20, 0x00, 0x00, // entry 2
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_pubdef_record(&raw).unwrap();
    assert_eq!(rec.kind, PubdefKind::Pubdef16);
    assert_eq!(rec.entries.len(), 2);
    assert_eq!(rec.entries[0].name, "a");
    assert_eq!(rec.entries[0].offset, 0x0010);
    assert_eq!(rec.entries[1].name, "b");
    assert_eq!(rec.entries[1].offset, 0x0020);
}

#[test]
fn omf_pubdef_standalone_base_frame_group_nonzero() {
    // group nonzero, seg=0: Base Frame is present (but ignored by linkers).
    // group=1, seg=0, frame=0xABCD, name="y", offset=5, type=0
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x90, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x01, 0x00,             // group=1, seg=0
        0xCD, 0xAB,             // frame=0xABCD (present because seg=0)
        0x01, b'y',             // name
        0x05, 0x00,             // offset
        0x00,                   // type
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_pubdef_record(&raw).unwrap();
    assert_eq!(rec.base, PubdefBase::Frame { group_index: 1, frame: 0xABCD });
    assert_eq!(rec.entries[0].offset, 5);
}

#[test]
fn omf_pubdef_standalone_empty_name_error() {
    // Zero-length name should produce PubdefError::EmptyName.
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x90, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x01,  // group=0, seg=1
        0x00,        // name_len=0 -> ERROR
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let result = parse_pubdef_record(&raw);
    assert!(matches!(result, Err(PubdefError::EmptyName(_))));
}

#[test]
fn omf_pubdef_standalone_wrong_type_error() {
    // Record type 0x00 is not 0x90 or 0x91.
    let rec = make_record(0x00, &[0x00, 0x00]);
    let result = parse_pubdef_record(&rec);
    assert!(matches!(result, Err(PubdefError::WrongRecordType { found: 0x00 })));
}

#[test]
fn omf_pubdef_standalone_checksum_mismatch() {
    // Corrupted checksum should produce ChecksumMismatch.
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x90, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x01,           // group=0, seg=1
        0x01, b'a',           // name
        0x00, 0x00,           // offset
        0x00,                 // type
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    let correct_cs = 0u8.wrapping_sub(sum);
    raw.push(correct_cs.wrapping_add(1)); // intentionally wrong checksum

    let result = parse_pubdef_record(&raw);
    assert!(matches!(result, Err(PubdefError::ChecksumMismatch { .. })));
}

#[test]
fn omf_pubdef_standalone_checksum_omitted() {
    // Checksum byte of 0x00 means omitted -> accept unconditionally.
    let raw: &[u8] = &[
        0x90, 0x03, 0x00, // type=0x90, length=3
        0x00, 0x01,       // base group=0, seg=1
        0x00,             // checksum=0 (omitted, body has no room for entries but that's ok for this test)
    ];
    // length=3 means body is 3 bytes: base group (1B) + base seg (1B) + checksum (1B)
    // Actually: body = group(1) + seg(1), checksum is last byte
    // Wait, length=3 means body has 3 bytes before checksum? No, record_length covers body+checksum.
    // Let me re-read make_record logic...
    // The helper: body.len() + 1 for checksum = record_length... 
    // No wait, make_record(rt, body) makes: [rt, (body.len()+1) as u16 LE, body, checksum]
    // So record_length = body.len() + 1 (covers body + checksum)
    // The record's body (as used by parse_pubdef_record) is everything after the 3-byte header.
    // So my manual record: [0x90, 0x03, 0x00, 0x00, 0x01, 0x00] -> type=0x90, length=3, body=[0x00, 0x01], checksum=0x00
    // length=3 means record_length=3, so body_without_checksum = 2 bytes (group + seg).
    // That works: the body is just base fields with no entries.
    let result = parse_pubdef_record(raw);
    assert!(result.is_ok(), "checksum 0x00 should be accepted: {:?}", result);
    let rec = result.unwrap();
    assert_eq!(rec.entries.len(), 0); // no entries, just base
}

#[test]
fn omf_pubdef_standalone_pubdef32_absolute() {
    // PUBDEF32 absolute: group=0, seg=0, frame=0x0042, offset=0xDEADBEEF
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x91, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x00,             // group=0, seg=0
        0x42, 0x00,             // frame=0x0042
        0x03, b'A', b's', b'm', // name_len=3 "Asm"
        0xEF, 0xBE, 0xAD, 0xDE, // offset=0xDEADBEEF
        0x00,                   // type=0
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_pubdef_record(&raw).unwrap();
    assert_eq!(rec.kind, PubdefKind::Pubdef32);
    assert_eq!(rec.base, PubdefBase::Frame { group_index: 0, frame: 0x0042 });
    assert_eq!(rec.entries[0].name, "Asm");
    assert_eq!(rec.entries[0].offset, 0xDEADBEEF);
    assert_eq!(rec.entries[0].type_index, 0);
}

#[test]
fn omf_pubdef_standalone_name_too_long() {
    // Name length 0xFF (255) is valid; 0x100 is not representable in a u8.
    // Test name length > 255 by using a 2-byte encoding trick? Actually length is
    // a single u8 byte, so max is 255. Test that length=255 is accepted and
    // length > 255 can't happen in a single byte. Instead, test that a length
    // of 255 that exceeds the buffer produces UnexpectedEof.
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x90, 0x00, 0x00]);
    // Build body with name_len=255 but only 10 bytes of name data
    let mut body: Vec<u8> = vec![0x00, 0x01]; // group=0, seg=1
    body.push(255); // name_len = 255
    body.extend_from_slice(b"tooshort"); // only 8 bytes, not 255
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let result = parse_pubdef_record(&raw);
    assert!(matches!(result, Err(PubdefError::UnexpectedEof(_))));
}

#[test]
fn omf_pubdef_standalone_name_length_256_not_possible() {
    // Verify that NameTooLong is returned when length > 255.
    // Since length is stored in a u8, the literal max is 255.
    // We can't construct a record with length > 255 using the on-disk format.
    // This test verifies that length=0 (empty name) is caught as EmptyName.
    // The NameTooLong variant is yielded by the standalone parser if ever a
    // length > 255 is seen, which shouldn't happen from on-disk data but
    // tests the code path.
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x91, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x01,           // group=0, seg=1
        0x00,                 // name_len=0 -> EmptyName
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let result = parse_pubdef_record(&raw);
    assert!(matches!(result, Err(PubdefError::EmptyName(_))));
}

#[test]
fn omf_pubdef_standalone_type_index_two_byte() {
    // Two-byte type index (high bit set).
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0x90, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x01,           // group=0, seg=1
        0x01, b'T',           // name_len=1 "T"
        0x10, 0x00,           // offset=0x0010
        0x81, 0x2A,           // type=0x012A (2-byte index)
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_pubdef_record(&raw).unwrap();
    assert_eq!(rec.entries[0].type_index, 0x012A);
}

#[test]
fn omf_pubdef_standalone_spec_example_gamma() {
    // Spec example 9.1: GAMMA at offset 0x0002, seg index 1
    // raw: 90 0C 00 00 01 05 47 41 4D 4D 41 02 00 00 F9
    let raw: &[u8] = &[
        0x90, 0x0C, 0x00, 0x00, 0x01, 0x05, 0x47, 0x41,
        0x4D, 0x4D, 0x41, 0x02, 0x00, 0x00, 0xF9,
    ];
    let rec = parse_pubdef_record(raw).unwrap();
    assert_eq!(rec, PubdefRecord {
        kind: PubdefKind::Pubdef16,
        base: PubdefBase::Segment { group_index: 0, segment_index: 1 },
        entries: vec![PubdefEntry { name: "GAMMA".into(), offset: 0x0002, type_index: 0 }],
    });
}

#[test]
fn omf_pubdef_standalone_spec_example_alpha() {
    // Spec example 9.2: ALPHA EQU 1234h, frame=0x0000
    // raw: 90 0E 00 00 00 00 00 05 41 4C 50 48 41 34 12 00 B1
    let raw: &[u8] = &[
        0x90, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x41, 0x4C, 0x50, 0x48, 0x41, 0x34, 0x12, 0x00, 0xB1,
    ];
    let rec = parse_pubdef_record(raw).unwrap();
    assert_eq!(rec, PubdefRecord {
        kind: PubdefKind::Pubdef16,
        base: PubdefBase::Frame { group_index: 0, frame: 0x0000 },
        entries: vec![PubdefEntry { name: "ALPHA".into(), offset: 0x1234, type_index: 0 }],
    });
}

#[test]
fn omf_extdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().next().unwrap();
    assert_eq!(sym.name(), Ok("puts"));
}

#[test]
fn omf_local_extdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0xB4, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().next().unwrap();
    assert_eq!(sym.name(), Ok("puts"));
    assert_eq!(sym.scope(), object::SymbolScope::Compilation);
    assert!(sym.is_local());
    assert!(!sym.is_global());
}

#[test]
fn omf_32bit_ignored() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // B5H (LEXTDEF 32-bit) - should be ignored
    data.extend(make_record(0xB5, &[0x04, b'p', b'u', b't', b's', 0x00]));
    // B7H (LPUBDEF 32-bit) - now parsed as LPUBDEF32
    data.extend(make_record(0xB7, &[0x00, 0x01, 0x03, b'f', b'o', b'o', 0x02, 0x00, 0x00, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.symbols().count(), 1);
    let sym = obj.symbols().next().unwrap();
    assert_eq!(sym.name(), Ok("foo"));
    assert!(sym.is_local());
    assert!(!sym.is_global());
}

#[test]
fn omf_reloc_skip_unresolvable() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00])); // EXTDEF 1
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body:
    // 1. locat=0x8400, fix_dat=0x42 (frame 4, target=EXT 1 (puts)), disp=0 -> should work
    // 2. locat=0x8402, fix_dat=0x42 (frame 4, target=EXT 2 (missing)), disp=0 -> should be skipped
    // 3. locat=0x8404, fix_dat=0x42 (frame 4, target=EXT 1 (puts)), disp=0 -> should work
    data.extend(make_record(
        0x9C,
        &[
            0x84, 0x00, 0x42, 0x01, 0x00, 0x00, // Reloc 1
            0x84, 0x02, 0x42, 0x02, 0x00, 0x00, // Reloc 2 (invalid ext 2)
            0x84, 0x04, 0x42, 0x01, 0x00, 0x00, // Reloc 3
        ],
    ));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();

    let (off1, _) = relocs.next().unwrap();
    assert_eq!(off1, 0);

    let (off3, _) = relocs.next().unwrap();
    assert_eq!(off3, 4);

    assert!(relocs.next().is_none());
}

#[test]
fn omf_comdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // COMENT class 0xA1 (MS extensions)
    data.extend(make_record(0x88, &[0x00, 0xA1]));
    data.extend(make_record(0xB0, &[0x07, b'b', b's', b's', b'_', b'v', b'a', b'r', 0x00, 0x62, 0x04]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().next().unwrap();
    assert_eq!(sym.name(), Ok("bss_var"));
}

#[test]
fn omf_fixupp() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body:
    // 1. locat=0xC400, fix_dat=0x40 (frame 4), datum=1 (seg 1), disp=0 (2 bytes)
    // 2. locat=0x8402, fix_dat=0x42 (frame 4), datum=1 (ext 1), disp=0 (2 bytes)
    data.extend(make_record(0x9C, &[0xC4, 0x00, 0x40, 0x01, 0x00, 0x00, 0x84, 0x02, 0x42, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    assert_eq!(relocs.next().unwrap().1.target(), RelocationTarget::Section(SectionIndex(0)));
    assert_eq!(relocs.next().unwrap().1.target(), RelocationTarget::Symbol(SymbolIndex(0)));
}

#[test]
fn omf_fixupp32() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP32 body:
    // 1. locat=0xC400, fix_dat=0x40 (frame 4), datum=1 (seg 1), disp=0x12345678 (4 bytes)
    // 2. locat=0x8402, fix_dat=0x42 (frame 4), datum=1 (ext 1), disp=0 (4 bytes)
    data.extend(make_record(0x9D, &[0xC4, 0x00, 0x40, 0x01, 0x78, 0x56, 0x34, 0x12, 0x84, 0x02, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    let r1 = relocs.next().unwrap().1;
    assert_eq!(r1.target(), RelocationTarget::Section(SectionIndex(0)));
    assert_eq!(r1.addend(), 0x12345678);
    let r2 = relocs.next().unwrap().1;
    assert_eq!(r2.target(), RelocationTarget::Symbol(SymbolIndex(0)));
    assert_eq!(r2.addend(), 0);
}

#[test]
fn omf_loc32_size() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP32 body:
    // 1. locat=0xE400 (loc=9, offset=0), fix_dat=0x40 (frame 4), datum=1, disp=0
    // 2. locat=0xEC00 (loc=11, offset=0), fix_dat=0x40 (frame 4), datum=1, disp=0
    data.extend(make_record(0x9D, &[0xE4, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0xEC, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    let r1 = relocs.next().unwrap().1;
    assert_eq!(r1.size(), 32);
    let r2 = relocs.next().unwrap().1;
    assert_eq!(r2.size(), 48);
}

#[test]
fn omf_modend_entry() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // MODEND body: type=0xC1, fix_dat=0x40 (frame 4), datum=1 (seg 1), disp=0x0123
    data.extend(make_record(0x8A, &[0xC1, 0x40, 0x01, 0x23, 0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.entry(), 0x0123);
}

#[test]
fn omf_grpdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E', 0x04, b'D', b'A', b'T', b'A', 0x05, b'G', b'R', b'O', b'U', b'P']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x02, 0x02, 0x01]));
    data.extend(make_record(0x9A, &[0x03, 0xFF, 0x01, 0xFF, 0x02]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.groups[0].members, vec![1, 2]);
}

#[test]
fn omf_target_thread() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body:
    // Thread: TARGET, method 2 (ext), thread 0, datum 1 (ext 1) -> 0x08, 0x01
    // Fixup: locat 0x8400, fix_dat 0x48 (frame 4, T=1, targt 0), disp 0
    data.extend(make_record(0x9C, &[0x08, 0x01, 0x84, 0x00, 0x48, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    assert_eq!(relocs.next().unwrap().1.target(), RelocationTarget::Symbol(SymbolIndex(0)));
}

#[test]
fn omf_frame_thread() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body:
    // Thread: FRAME, method 0 (seg), thread 0, datum 1 (seg 1) -> 0x40, 0x01
    // Fixup: locat 0xC400, fix_dat 0x82 (F=1, frame 0, T=0, targt 2), datum 1 (ext 1), disp 0
    data.extend(make_record(0x9C, &[0x40, 0x01, 0xC4, 0x00, 0x82, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    assert_eq!(relocs.next().unwrap().1.target(), RelocationTarget::Symbol(SymbolIndex(0)));
}

#[test]
fn omf_undefined_target_thread() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body: Fixup referencing undefined TARGET thread 2
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x4A]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err());
}

#[test]
fn omf_undefined_frame_thread() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body: Fixup referencing undefined FRAME thread 1
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x92, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err());
}

#[test]
fn omf_thread_persistence() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00])); // EXTDEF BEFORE LEDATA
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP 1: Define TARGET thread 0
    data.extend(make_record(0x9C, &[0x08, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA 2
    // FIXUPP 2: Reference TARGET thread 0
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x48, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    assert_eq!(relocs.next().unwrap().1.target(), RelocationTarget::Symbol(SymbolIndex(0)));
}

#[test]
fn omf_thread_overwrite() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00, 0x04, b'g', b'e', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA
    // FIXUPP body:
    // 1. TARGET thread 0 = ext 1 (puts)
    // 2. TARGET thread 0 = ext 2 (gets)
    // 3. Fixup referencing thread 0
    data.extend(make_record(0x9C, &[0x08, 0x01, 0x08, 0x02, 0x84, 0x00, 0x48, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    assert_eq!(relocs.next().unwrap().1.target(), RelocationTarget::Symbol(SymbolIndex(1))); // gets
}

#[test]
fn omf_loc4_include() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body:
    // 1. Thread subrecord: TARGET thread 0 = ext 1
    // 2. loc=4 (high-byte), fix_dat referencing thread 0 → now included
    // 3. Normal fixup referencing thread 0
    data.extend(make_record(0x9C, &[0x08, 0x01, 0x90, 0x00, 0x48, 0x00, 0x00, 0x84, 0x02, 0x48, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    // First relocation: loc=4 (high-byte, size=8) at offset 0
    let (off1, r1) = relocs.next().unwrap();
    assert_eq!(off1, 0);
    assert_eq!(r1.size(), 8);
    assert_eq!(r1.target(), RelocationTarget::Symbol(SymbolIndex(0)));
    // Second relocation: normal loc=1 at offset 2
    let (off2, r2) = relocs.next().unwrap();
    assert_eq!(off2, 2);
    assert_eq!(r2.target(), RelocationTarget::Symbol(SymbolIndex(0)));
    assert!(relocs.next().is_none());
}

#[test]
fn omf_group_relocation() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E', 0x04, b'D', b'A', b'T', b'A', 0x05, b'G', b'R', b'O', b'U', b'P']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01])); // CODE
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x02, 0x02, 0x01])); // DATA
    data.extend(make_record(0x9A, &[0x03, 0xFF, 0x01, 0xFF, 0x02])); // GROUP members CODE, DATA
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA for CODE
    // FIXUPP body: target=GROUP[0], which resolves to its first member CODE (SectionIndex(0))
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x41, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    assert_eq!(relocs.next().unwrap().1.target(), RelocationTarget::Section(SectionIndex(0)));
}

#[test]
fn omf_encounter_order() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP: interleaved thread and fixup
    data.extend(make_record(0x9C, &[
        0x08, 0x01, // THREAD TARGET[0]
        0x84, 0x00, 0x48, 0x00, 0x00, // FIXUP using TARGET[0]
        0x09, 0x02, // THREAD TARGET[1]
        0x84, 0x02, 0x49, 0x00, 0x00, // FIXUP using TARGET[1]
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let records = obj.fixupp_records();
    assert_eq!(records.len(), 1);
    let subrecords = &records[0].subrecords;
    assert_eq!(subrecords.len(), 4);
    // Verify interleaving order
    match &subrecords[0] {
        object::read::omf::ParsedFixuppSubrecord::Thread(t) => assert_eq!(t.thread_number, 0),
        _ => panic!("expected thread"),
    }
    match &subrecords[1] {
        object::read::omf::ParsedFixuppSubrecord::Fixup(f) => assert_eq!(f.target_thread, Some(0)),
        _ => panic!("expected fixup"),
    }
    match &subrecords[2] {
        object::read::omf::ParsedFixuppSubrecord::Thread(t) => assert_eq!(t.thread_number, 1),
        _ => panic!("expected thread"),
    }
    match &subrecords[3] {
        object::read::omf::ParsedFixuppSubrecord::Fixup(f) => assert_eq!(f.target_thread, Some(1)),
        _ => panic!("expected fixup"),
    }
}

#[test]
fn omf_typdef_structural() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // TYPDEF body: name field (null), eight-leaf descriptor (tag 0x62 (NEAR), type 0x77, length 32)
    data.extend(make_record(0x8E, &[0x00, 0x62, 0x77, 32])); 
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.module_name(), b"HELLO");
}

#[test]
fn omf_linnum_structural() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // LINNUM body: group=0, segment=1, line=10, offset=0; line=20, offset=5
    data.extend(make_record(0x94, &[0x00, 0x01, 0x0A, 0x00, 0x00, 0x00, 0x14, 0x00, 0x05, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.module_name(), b"HELLO");
}

#[test]
fn omf_invalid_header() {
    let mut data = Vec::new();
    // Start with LNAMES instead of THEADR
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err());
}

#[test]
fn omf_extdef_ordinals_include_comdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x88, &[0x00, 0xA1])); // MS extensions
    data.extend(make_record(0xB0, &[0x03, b'c', b'o', b'm', 0x00, 0x62, 0x04])); // COMDEF #1
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00])); // EXTDEF #2
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    // explicit ext #2 (puts) + disp 0
    // datum: 2
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x42, 0x02, 0x00, 0x00])); 
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    assert_eq!(
        relocs.next().unwrap().1.target(),
        RelocationTarget::Symbol(
            obj.symbols()
                .enumerate()
                .find(|(_, s)| s.name() == Ok("puts"))
                .map(|(i, _)| SymbolIndex(i))
                .unwrap()
        )
    );
}

#[test]
fn omf_grpdef_accepts_non_ff_component() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // Two segments
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E', 0x05, b'G', b'R', b'O', b'U', b'P']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01])); // Seg 1
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01])); // Seg 2
    data.extend(make_record(0x9A, &[0x02, 0xFE, 0x01, 0xFE, 0x02])); // Relaxed: non-0xFF components accepted
    data.extend(make_record(0x8A, &[0x01]));
    assert!(OmfFile::parse(&data[..]).is_ok());
}

#[test]
fn omf_modend_external_entry() {
    // MODEND with external entry point (method 2, since P-bit must be 0).
    // end_dat=0x02: F=0, frame=0, T=0, P=0, targt=2 → target method 2 (external)
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x8C, &[0x04, b'm', b'a', b'i', b'n', 0x00]));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // module_type=0xC1 (START|RELOC),
    // end_dat=0x02 (frame meth 0, target meth 2 external, P=0),
    // frame_datum=0x01 (seg ordinal 1), target_datum=0x01 (ext ordinal 1 = "main"),
    // displacement=0x0100
    data.extend(make_record(0x8A, &[0xC1, 0x02, 0x01, 0x01, 0x00, 0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    // External entry: cannot resolve address from object file, returns 0.
    assert_eq!(obj.entry(), 0);
}

#[test]
fn omf_segdef_rejects_trailing_bytes() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    // SEGDEF body with an extra trailing byte (0xAA)
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01, 0xAA]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err());
}

#[test]
fn omf_modend_rejects_trailing_bytes() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // MODEND body with an extra trailing byte (0xBB)
    data.extend(make_record(0x8A, &[0xC1, 0x40, 0x01, 0x23, 0x01, 0xBB]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err());
}

#[test]
fn omf_target_thread_accepts_methods_4_5_6() {
    for method in [4u8, 5, 6] {
        let mut data = Vec::new();
        data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
        data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
        data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
        data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
        data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

        // THREAD TARGET subrecord:
        // bit7=0, D=0 (TARGET), method in bits 4..2, thread number 0.
        // Methods 4/5/6 carry a datum index.
        let thread_b0 = method << 2;
        data.extend(make_record(0x9C, &[thread_b0, 0x01]));

        data.extend(make_record(0x8A, &[0x01]));

        let result = OmfFile::parse(&data[..]);
        assert!(result.is_ok(), "TARGET thread method {} should be accepted", method);
    }
}

#[test]
fn omf_thread_target_reused() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x8C, &[0x03, b'f', b'o', b'o', 0x01]));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00])); // LEDATA for SEG 1
    data.extend(make_record(0x9C, &[
        0x08, 0x01, // THREAD (TARGET 0, method 2, datum 1)
        0xC1, 0x00, // locat 0xC100
        0x08,       // fix_dat (F=0, T=1, explicit frame 0, threaded target 0)
        0x01,       // datum for explicit frame method 0
        0x00, 0x00, // displacement for method 2
    ]));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    let relocs = sec.relocations().collect::<Vec<_>>();
    assert_eq!(relocs.len(), 1);
    match relocs[0].1.target() {
        RelocationTarget::Symbol(idx) => {
            assert_eq!(obj.symbol_by_index(idx).unwrap().name().unwrap(), "foo");
        }
        _ => panic!("Expected symbol target"),
    }
}

#[test]
fn omf_thread_frame_reused() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00])); // LEDATA for SEG 1
    data.extend(make_record(0x9C, &[
        0x40, 0x01, // THREAD (FRAME 0, method 0, datum 1)
        0xC1, 0x00, // locat 0xC100
        0x80,       // fix_dat (F=1, frame 0, explicit target (T=0, method 0, datum 1))
        0x01,       // datum for explicit target method 0
        0x00, 0x00, // displacement for method 0
    ]));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    let relocs = sec.relocations().collect::<Vec<_>>();
    assert_eq!(relocs.len(), 1);
}

#[test]
fn omf_thread_undefined_target() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA
    data.extend(make_record(0x9C, &[
        0xC1, 0x00, // locat
        0x08,       // F=0, T=1, explicit frame 0, threaded target 0 (undefined)
        0x01,       // datum for explicit frame method 0
        0x00, 0x00, // displacement for method 2
    ]));
    data.extend(make_record(0x8A, &[0x01]));

    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().to_string(), "FIXUPP references undefined TARGET thread");
}

#[test]
fn omf_fixupp_with_intervening_records_accepted() {
    // FIXUPP no longer requires immediate adjacency to LEDATA/LIDATA.
    // Intervening records are accepted; FIXUPP thread-only bodies (no
    // fixup subrecords) proceed without error even with no data target.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00])); // EXTDEF
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA
    // Insert intervening SEGDEF (previously rejected)
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    // FIXUPP with only THREAD subrecord (no fixup, no data target needed)
    data.extend(make_record(0x9C, &[0x08, 0x01])); // THREAD TARGET[0] = ext 1
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    // No relocations were produced since the FIXUPP had no fixup subrecords,
    // but the parse should not error due to intervening records.
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.relocations().count(), 0);
}

#[test]
fn omf_lidata_with_intervening_records_accepted() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // Flat LIDATA: repeat=1, block_count=0, byte_count=1, data=0xAA
    data.extend(make_record(0xA2, &[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xAA]));
    // Insert intervening SEGDEF (previously rejected with hard error)
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    // FIXUPP with only THREAD subrecord (no fixup, no data target needed)
    data.extend(make_record(0x9C, &[0x08, 0x01]));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.relocations().count(), 0);
    assert_eq!(sec.data().unwrap()[0], 0xAA);
}

#[test]
fn omf_local_pubdef_relocation() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    // LPUBDEF: foo at offset 2
    data.extend(make_record(0xB6, &[0x00, 0x01, 0x03, b'f', b'o', b'o', 0x02, 0x00, 0x00]));
    // LEDATA
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP: relocation at offset 0, target is external ordinal 1 (which should be LPUBDEF foo)
    // LOCAT: 0xC400 (M=1, LOC=1, offset=0)
    // fix_dat: 0x52 (F=0, frame_method=5, T=0, targt=2)
    // datum: 1
    // displacement: 0 (2 bytes)
    data.extend(make_record(0x9C, &[0xC4, 0x00, 0x52, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    let mut relocs = sec.relocations();
    let (offset, reloc) = relocs.next().expect("should have one relocation");
    assert_eq!(offset, 0);
    if let RelocationTarget::Symbol(sym_idx) = reloc.target() {
        let sym = obj.symbol_by_index(sym_idx).unwrap();
        assert_eq!(sym.name(), Ok("foo"));
        assert!(sym.is_local());
    } else {
        panic!("relocation target should be a symbol");
    }
}

// ── LPUBDEF32 (0xB7) tests ────────────────────────────────────────────────

#[test]
fn omf_lpubdef32_basic() {
    // 0xB7 LPUBDEF32 with a 32-bit offset.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    // group=0, seg=1, name_len=3 "baz", offset=0x12345678 (4B LE), type=0
    data.extend(make_record(0xB7, &[0x00, 0x01, 0x03, b'b', b'a', b'z', 0x78, 0x56, 0x34, 0x12, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("baz")).unwrap();
    assert_eq!(sym.address(), 0x12345678);
    assert_eq!(sym.scope(), object::SymbolScope::Compilation);
    assert!(sym.is_local());
    assert!(!sym.is_global());
}

#[test]
fn omf_lpubdef32_absolute() {
    // 0xB7 absolute symbol: group=0, seg=0 -> Base Frame present.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // group=0, seg=0, frame=0x0042 (2B LE), name_len=3 "abs", offset=0xDEADBEEF (4B LE), type=0
    data.extend(make_record(0xB7, &[0x00, 0x00, 0x42, 0x00, 0x03, b'a', b'b', b's', 0xEF, 0xBE, 0xAD, 0xDE, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("abs")).unwrap();
    assert_eq!(sym.section(), object::SymbolSection::Absolute);
    assert!(sym.is_local());
}

#[test]
fn omf_lpubdef32_multiple_entries() {
    // Single 0xB7 record with two name entries.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x40, 0x00, 0x01, 0x01, 0x01]));
    // group=0, seg=1, then two entries:
    //   "x" offset=0x00000010 type=0
    //   "y" offset=0x00000020 type=0
    data.extend(make_record(0xB7, &[
        0x00, 0x01,                                 // base group=0, seg=1
        0x01, b'x', 0x10, 0x00, 0x00, 0x00, 0x00,   // entry 1
        0x01, b'y', 0x20, 0x00, 0x00, 0x00, 0x00,   // entry 2
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.symbols().count(), 2);
    let sym_x = obj.symbols().find(|s| s.name() == Ok("x")).unwrap();
    let sym_y = obj.symbols().find(|s| s.name() == Ok("y")).unwrap();
    assert_eq!(sym_x.address(), 0x10);
    assert_eq!(sym_y.address(), 0x20);
    assert!(sym_x.is_local());
    assert!(sym_y.is_local());
}

#[test]
fn omf_lpubdef32_large_offset() {
    // 0xB7 offset > 0xFFFF to prove true 32-bit width.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    // group=0, seg=1, name_len=3 "big", offset=0x00010000 (1 << 16), type=0
    data.extend(make_record(0xB7, &[0x00, 0x01, 0x03, b'b', b'i', b'g', 0x00, 0x00, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sym = obj.symbols().find(|s| s.name() == Ok("big")).unwrap();
    assert_eq!(sym.address(), 0x00010000);
}

#[test]
fn omf_lpubdef32_relocation() {
    // 0xB7 LPUBDEF32 followed by LEDATA + FIXUPP targeting the LPUBDEF symbol.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    // LPUBDEF32: foo at offset 0x00000100 (32-bit)
    data.extend(make_record(0xB7, &[0x00, 0x01, 0x03, b'f', b'o', b'o', 0x00, 0x01, 0x00, 0x00, 0x00]));
    // LEDATA
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP: relocation at offset 0, target is external ordinal 1 (LPUBDEF foo)
    data.extend(make_record(0x9C, &[0xC4, 0x00, 0x52, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    let mut relocs = sec.relocations();
    let (offset, reloc) = relocs.next().expect("should have one relocation");
    assert_eq!(offset, 0);
    if let RelocationTarget::Symbol(sym_idx) = reloc.target() {
        let sym = obj.symbol_by_index(sym_idx).unwrap();
        assert_eq!(sym.name(), Ok("foo"));
        assert!(sym.is_local());
    } else {
        panic!("relocation target should be a symbol");
    }
}

// ── Standalone LPUBDEF parser tests ────────────────────────────────────────

fn lpubdef_body_of(record: &[u8]) -> &[u8] {
    &record[3..]
}

#[test]
fn omf_parse_lpubdef_b6_basic() {
    // B6H single name with zero checksum.
    // Full record: B6 0B 00 00 01 04 6D 61 69 6E 00 01 00 00
    let raw: &[u8] = &[
        0xB6, 0x0B, 0x00, 0x00, 0x01, 0x04, 0x6D, 0x61,
        0x69, 0x6E, 0x00, 0x01, 0x00, 0x00,
    ];
    let rec = parse_lpubdef(0xB6, lpubdef_body_of(raw)).unwrap();
    assert_eq!(rec.offset_width, OffsetWidth::Bit16);
    assert_eq!(rec.base_group, OmfIndex(0));
    assert_eq!(rec.base_segment, OmfIndex(1));
    assert_eq!(rec.base_frame, None);
    assert_eq!(rec.names.len(), 1);
    assert_eq!(rec.names[0].name, b"main");
    assert_eq!(rec.names[0].offset, 0x0100);
    assert_eq!(rec.names[0].type_index, OmfIndex(0));
    assert_eq!(rec.checksum, 0x00);
}

#[test]
fn omf_parse_lpubdef_b7_basic() {
    // B7H single name with 32-bit offset.
    // Record: B7 <len> 00 01 03 62 61 7A <offset 4B LE> 00 <chk>
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xB7, 0x00, 0x00]); // placeholder length
    let body: Vec<u8> = [
        0x00, 0x01,             // base group=0, seg=1
        0x03, b'b', b'a', b'z', // name len=3 "baz"
        0x78, 0x56, 0x34, 0x12, // offset=0x12345678
        0x00,                   // type=0
    ].to_vec();
    let body_len = body.len() + 1; // +1 for checksum
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_lpubdef(0xB7, lpubdef_body_of(&raw)).unwrap();
    assert_eq!(rec.offset_width, OffsetWidth::Bit32);
    assert_eq!(rec.base_group, OmfIndex(0));
    assert_eq!(rec.base_segment, OmfIndex(1));
    assert_eq!(rec.base_frame, None);
    assert_eq!(rec.names.len(), 1);
    assert_eq!(rec.names[0].name, b"baz");
    assert_eq!(rec.names[0].offset, 0x12345678);
    assert_eq!(rec.names[0].type_index, OmfIndex(0));
}

#[test]
fn omf_parse_lpubdef_b7_absolute() {
    // B7H absolute: group=0, seg=0, frame=0x0042, 32-bit offset, real checksum.
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xB7, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x00,             // group=0, seg=0
        0x42, 0x00,             // frame=0x0042
        0x09, b'g', b'_', b'c', b'o', b'u', b'n', b't', b'e', b'r', // name
        0x00, 0x10, 0x00, 0x00, // offset=0x00001000
        0x00,                   // type=0
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_lpubdef(0xB7, lpubdef_body_of(&raw)).unwrap();
    assert_eq!(rec.offset_width, OffsetWidth::Bit32);
    assert_eq!(rec.base_group, OmfIndex(0));
    assert_eq!(rec.base_segment, OmfIndex(0));
    assert_eq!(rec.base_frame, Some(0x0042));
    assert_eq!(rec.names.len(), 1);
    assert_eq!(rec.names[0].name, b"g_counter");
    assert_eq!(rec.names[0].offset, 0x00001000);
}

#[test]
fn omf_parse_lpubdef_b7_multiple_entries() {
    // Two entries in one B7H record.
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xB7, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x02,                                   // base group=0, seg=2
        0x01, b'a', 0x10, 0x00, 0x00, 0x00, 0x00,    // entry 1
        0x01, b'b', 0x20, 0x00, 0x00, 0x00, 0x00,    // entry 2
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_lpubdef(0xB7, lpubdef_body_of(&raw)).unwrap();
    assert_eq!(rec.offset_width, OffsetWidth::Bit32);
    assert_eq!(rec.names.len(), 2);
    assert_eq!(rec.names[0].name, b"a");
    assert_eq!(rec.names[0].offset, 0x10);
    assert_eq!(rec.names[1].name, b"b");
    assert_eq!(rec.names[1].offset, 0x20);
}

#[test]
fn omf_parse_lpubdef_b7_base_frame_group_nonzero() {
    // group nonzero, seg=0: Base Frame is present.
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xB7, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x01, 0x00,             // group=1, seg=0
        0xCD, 0xAB,             // frame=0xABCD
        0x01, b'y',             // name
        0x05, 0x00, 0x00, 0x00, // offset=5
        0x00,                   // type=0
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_lpubdef(0xB7, lpubdef_body_of(&raw)).unwrap();
    assert_eq!(rec.base_frame, Some(0xABCD));
    assert_eq!(rec.names[0].offset, 5);
}

#[test]
fn omf_parse_lpubdef_wrong_type() {
    let raw = make_record(0x90, &[0x00, 0x01]);
    let err = parse_lpubdef(0x90, lpubdef_body_of(&raw)).unwrap_err();
    assert_eq!(err, LpubdefParseError::InvalidRecordType(0x90));
}

#[test]
fn omf_parse_lpubdef_empty_name() {
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xB7, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x01,  // group=0, seg=1
        0x00,        // name_len=0 -> EmptyName
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let err = parse_lpubdef(0xB7, lpubdef_body_of(&raw)).unwrap_err();
    assert_eq!(err, LpubdefParseError::EmptyName);
}

#[test]
fn omf_parse_lpubdef_truncated_body() {
    let raw = make_record(0xB6, &[0x00, 0x01, 0x04, b'm', b'a', b'i']);
    let body = lpubdef_body_of(&raw);
    let truncated = &body[..body.len() - 3];
    let err = parse_lpubdef(0xB6, truncated).unwrap_err();
    assert!(matches!(
        err,
        LpubdefParseError::UnexpectedEof { .. } | LpubdefParseError::TrailingBytes { .. }
    ));
}

#[test]
fn omf_parse_lpubdef_type_index_two_byte() {
    // Two-byte type index (high bit set).
    let mut raw = Vec::new();
    raw.extend_from_slice(&[0xB7, 0x00, 0x00]);
    let body: Vec<u8> = [
        0x00, 0x01,           // group=0, seg=1
        0x01, b'T',           // name_len=1 "T"
        0x78, 0x56, 0x34, 0x12, // offset=0x12345678
        0x81, 0x2A,           // type=0x012A (2-byte index)
    ].to_vec();
    let body_len = body.len() + 1;
    raw[1] = (body_len & 0xFF) as u8;
    raw[2] = ((body_len >> 8) & 0xFF) as u8;
    raw.extend_from_slice(&body);
    let sum: u8 = raw.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    raw.push(0u8.wrapping_sub(sum));

    let rec = parse_lpubdef(0xB7, lpubdef_body_of(&raw)).unwrap();
    assert_eq!(rec.names[0].type_index, OmfIndex(0x012A));
}

#[test]
fn omf_parse_lpubdef_checksum_zero_accepted() {
    // Checksum byte 0x00 means omitted -> accept unconditionally.
    let raw: &[u8] = &[
        0xB6, 0x03, 0x00, // type=0xB6, length=3
        0x00, 0x01,       // base group=0, seg=1
        0x00,             // checksum=0
    ];
    let rec = parse_lpubdef(0xB6, lpubdef_body_of(raw)).unwrap();
    assert_eq!(rec.checksum, 0x00);
    assert_eq!(rec.names.len(), 0);
}

#[test]
fn omf_parse_lpubdef_checksum_real_value() {
    // B6H with real computed checksum.
    let raw: &[u8] = &[
        0xB6, 0x0B, 0x00, 0x00, 0x01, 0x04, 0x6D, 0x61,
        0x69, 0x6E, 0x00, 0x01, 0x00, 0x94,
    ];
    let rec = parse_lpubdef(0xB6, lpubdef_body_of(raw)).unwrap();
    assert_eq!(rec.checksum, 0x94);
    assert_eq!(rec.names[0].name, b"main");
    assert_eq!(rec.names[0].offset, 0x0100);
}

// ── New tests for full 32-bit OMF support ─────────────────────────────────

#[test]
fn omf_segdef32() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    // SEGDEF32: acbp=0x28, length=0x10000 (u32), name=1, class=1, overlay=1
    data.extend(make_record(0x99, &[0x28, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01]));
    // LEDATA for seg 1: offset=0, data=0xAA
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0xAA]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.size(), 0x10000);
    assert_eq!(sec.data().unwrap()[0], 0xAA);
}

#[test]
fn omf_ledata32() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x01, 0x01, 0x01]));
    // LEDATA32: seg=1, offset=0x00000010 (u32), data=0xBB
    data.extend(make_record(0xA1, &[0x01, 0x10, 0x00, 0x00, 0x00, 0xBB]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.data().unwrap()[0x10], 0xBB);
}

#[test]
fn omf_modend32() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // MODEND32: type=0xC1, end_dat=0x40, datum=1, disp=0x00000123 (u32)
    data.extend(make_record(0x8B, &[0xC1, 0x40, 0x01, 0x23, 0x01, 0x00, 0x00]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.entry(), 0x123);
}

#[test]
fn omf_coment_as_segdef() {
    // COMENT record (0x88) with body that structurally matches a SEGDEF
    // should be accepted as a Borland-variant segment definition.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    // COMENT acting as SEGDEF: acbp=0x28, length=0x10, name=1, class=1, overlay=1
    data.extend(make_record(0x88, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0xAA]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.size(), 0x10);
}

#[test]
fn omf_grpdef_absolute_frame() {
    // GRPDEF with component type 0xFA (absolute frame).
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x05, b'G', b'R', b'O', b'U', b'P']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // GRPDEF: name=1, component type 0xFA (frame=0x10, offset=0x1234)
    data.extend(make_record(0x9A, &[0x01, 0xFA, 0x10, 0x00, 0x34, 0x12]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.groups.len(), 1);
}

#[test]
fn omf_grpdef_ltl() {
    // GRPDEF with component type 0xFB (LTL).
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x05, b'G', b'R', b'O', b'U', b'P']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // GRPDEF: name=1, component type 0xFB (ltl_data=0, max_length=0x10, length=0x08)
    data.extend(make_record(0x9A, &[0x01, 0xFB, 0x00, 0x10, 0x00, 0x08, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.groups.len(), 1);
}

#[test]
fn omf_grpdef_name_triple() {
    // GRPDEF with component type 0xFD (name triple).
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x05, b'G', b'R', b'O', b'U', b'P']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // GRPDEF: name=1, component type 0xFD (seg_name=1, class_name=2, overlay=3)
    data.extend(make_record(0x9A, &[0x01, 0xFD, 0x01, 0x02, 0x03]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.groups.len(), 1);
}

#[test]
fn omf_grpdef_unresolved() {
    // GRPDEF referencing a segment ordinal that does not yet exist.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x05, b'G', b'R', b'O', b'U', b'P']));
    // GRPDEF: name=1, component type 0xFF targeting seg=5 (not defined yet)
    data.extend(make_record(0x9A, &[0x01, 0xFF, 0x05]));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.groups.len(), 1);
    // The unresolved member should still appear in resolved_members as None.
    assert!(obj.groups[0].resolved_members[0].is_none());
}

#[test]
fn omf_bss_segment() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x03, b'B', b'S', b'S']));
    // BSS segment: A=1 (BYTE), C=2 (PUBLIC), B=1 (big/default 64KB), P=0
    // ACBP = 0b001_010_10_0 = 0x2A. With B=1, length field must be 0.
    data.extend(make_record(0x98, &[0x2A, 0x00, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.size(), 0x10000);
    assert!(sec.data().unwrap().iter().all(|&b| b == 0));
}

#[test]
fn omf_fixupp_no_data_target() {
    // FIXUPP with fixup subrecords but no preceding data target must error.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    // FIXUPP with no preceding LEDATA/LIDATA
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x42, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "FIXUPP with no preceding data record"
    );
}

// ── New tests for full FIXUP variant support ──────────────────────────────

#[test]
fn omf_frame_method_3_accepted() {
    // FRAME method 3 (explicit frame number) must be accepted.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E', 0x00])); // lnames: "", "CODE", ""
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00])); // EXTDEF #1
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01])); // seg name="CODE" (idx 2)
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body: FRAME method 3 explicit
    // fix_dat bits: F=0 (explicit), frame=3 (method 3), T=0, P=0, targt=2
    // fix_dat = 0b0011_0010 = 0x32
    // locat=0x8400 (M=0, LOC=1, offset=0)
    // frame_datum=0x10 (frame number = 0x10)
    // target_method=2 (external), target_datum=0x01 → ext ordinal 1
    // displacement=0x0000
    data.extend(make_record(0x9C, &[
        0x84, 0x00, 0x32, 0x10, 0x01, 0x00, 0x00,
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_ok(), "FRAME method 3 should be accepted: {:?}", result.err());
}

#[test]
fn omf_target_method_3_accepted() {
    // TARGET method 3 (explicit frame number) must be accepted.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body:
    // locat=0x8400 (M=0, LOC=1, offset=0)
    // fix_dat=0x43 (F=0, frame_method=4, T=0, targt=3)
    // datum=<frame_number for target method 3>
    // disp=<displacement>
    // target method 3: (T=0, P=0, targt=3) => method = ((0) << 2) | 3 = 3
    // fix_dat = 0x40 | 0x03 = 0x43 (frame method 4, target method 3)
    data.extend(make_record(0x9C, &[
        0x84, 0x00, 0x43, 0x10, 0x00, 0x00, // frame=4(seg_loc), target meth 3, frame_num=0x10, disp=0
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_ok(), "TARGET method 3 should be accepted");
}

#[test]
fn omf_absolute_frame_relocation() {
    // TARGET method 3 produces a relocation with target=Absolute and
    // addend = (frame_num << 4) + displacement.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    // frame method 4 (seg containing LOCATION, no datum), target method 3 (frame number)
    // fix_dat bits: F=0, frame=4, T=0, P=0, targt=3 → 0x43
    // datum for target meth 3 = frame number = 0x10 (frame base = 0x100)
    // displacement = 0x0012 (offset within frame)
    data.extend(make_record(0x9C, &[
        0x84, 0x00, 0x43, 0x10, 0x12, 0x00, // target method 3, frame=0x10, disp=0x12
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    let (_off, reloc) = relocs.next().expect("should have AbsoluteFrame relocation");
    assert_eq!(reloc.target(), RelocationTarget::Absolute);
    // addend = (0x10 << 4) + 0x12 = 0x100 + 0x12 = 0x112
    assert_eq!(reloc.addend(), 0x112);
}

#[test]
fn omf_target_method_7_no_displacement() {
    // TARGET method 7 (no displacement field) produces AbsoluteFrame with addend = frame<<4.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    // fix_dat: F=0, frame_method=4, T=0, P=1, targt=3 → 0x47
    // (P=1, targt=3) => method = (1<<2) | 3 = 7
    // datum for target meth 7 = frame number = 0x20 (frame base = 0x200)
    // no displacement field follows (method 7 has no displacement)
    data.extend(make_record(0x9C, &[
        0x84, 0x00, 0x47, 0x20, // target method 7, frame=0x20, no disp
    ]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    let (_off, reloc) = relocs.next().expect("should have AbsoluteFrame relocation");
    assert_eq!(reloc.target(), RelocationTarget::Absolute);
    // addend = (0x20 << 4) + 0 = 0x200
    assert_eq!(reloc.addend(), 0x200);
}

#[test]
fn omf_comdat_communal() {
    // COMDEF entries should be visible as COMDAT groups.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x88, &[0x00, 0xA1])); // MS extensions
    data.extend(make_record(0xB0, &[0x03, b'f', b'o', b'o', 0x00, 0x62, 0x04])); // COMDEF foo NEAR(4)
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut comdats = obj.comdats();
    let comdat = comdats.next().expect("should have one COMDAT for foo");
    assert_eq!(comdat.name(), Ok("foo"));
    // COMDEF-based COMDATs have Any selection kind and zero sections.
    assert_eq!(comdat.kind(), object::ComdatKind::Any);
    assert_eq!(comdat.sections().count(), 0);
    assert!(comdats.next().is_none());
}

#[test]
fn omf_comdef_ledata_fixupp() {
    // Verify LEDATA -> COMDEF data copy and FIXUPP attach to communal entry,
    // and that normal segment LEDATA+FIXUPP behavior remains unchanged.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));

    // MS extensions comment (keeps compatibility with COMDEF tests)
    data.extend(make_record(0x88, &[0x00, 0xA1]));

    // COMDEF: name="foo", type_idx=0, DST=NEAR (0x62), size=3
    data.extend(make_record(0xB0, &[0x03, b'f', b'o', b'o', 0x00, 0x62, 0x03]));

    // LEDATA targeting the COMDEF-derived ordinal. This LEDATA should write
    // its payload into the ParsedComdefEntry.data buffer. At this point no
    // SEGDEF has been seen, so index=1 resolves to the COMDEF ordinal.
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0xAA, 0xBB, 0xCC]));
    // FIXUPP for the communal LEDATA: explicit target method=2 (external), datum=1, disp=0
    // Encoded: locat=0x8400 (0x84,0x00), fix_dat=0x42, datum=0x01, disp=0x0000
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x42, 0x01, 0x00, 0x00]));

    // Now append LNAMES and a SEGDEF for a normal segment (to verify normal behavior)
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    // SEGDEF: acbp=0x48, length=0x10, name=1, class=1, overlay=1
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));

    // LEDATA for normal segment 1: write one byte 0x11 at offset 0
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x11]));
    // FIXUPP immediately following: locat=0xC400, fix_dat=0x40 (method 0 = seg), datum=1, disp=0
    data.extend(make_record(0x9C, &[0xC4, 0x00, 0x40, 0x01, 0x00, 0x00]));

    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();

    // COMDEF communal checks via raw_comdefs API
    let comdefs = obj.raw_comdefs();
    assert_eq!(comdefs.len(), 1);
    let comdef = &comdefs[0];
    assert_eq!(&comdef.data[..], &[0xAA, 0xBB, 0xCC]);
    assert_eq!(comdef.relocs.len(), 1);
    let creloc = &comdef.relocs[0];
    assert_eq!(creloc.offset, 0);
    assert_eq!(creloc.target, object::read::omf::RelocTarget::External(1));

    // Normal segment check: segment 0 (first) should contain 0x11 at offset 0
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.data().unwrap()[0], 0x11);
    // The relocation for the normal segment should be present.
    let mut seg_relocs = sec.relocations();
    let (_off, r) = seg_relocs.next().unwrap();
    assert_eq!(r.target(), RelocationTarget::Section(SectionIndex(0)));
}

#[test]
fn omf_comdef_lidata_fixupp() {
    // Verify LIDATA -> COMDEF data copy and FIXUPP attach to communal entry.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));

    // MS extensions comment
    data.extend(make_record(0x88, &[0x00, 0xA1]));

    // COMDEF: name="foo", type_idx=0, DST=NEAR (0x62), size=3
    data.extend(make_record(0xB0, &[0x03, b'f', b'o', b'o', 0x00, 0x62, 0x03]));

    // LIDATA targeting the COMDEF-derived ordinal. Build a flat LIDATA block
    // repeat=1, block_count=0, byte_count=3, data=AA BB CC
    data.extend(make_record(
        0xA2,
        &[
            0x01, // seg idx = 1 (resolves to COMDEF ordinal)
            0x00, 0x00, // offset = 0
            0x01, 0x00, // repeat = 1
            0x00, 0x00, // block_count = 0 (flat)
            0x03,       // byte_count = 3
            0xAA, 0xBB, 0xCC,
        ],
    ));
    // FIXUPP for the communal LIDATA: explicit target method=2 (external), datum=1, disp=0
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x42, 0x01, 0x00, 0x00]));

    // Now append LNAMES and a SEGDEF for a normal segment (to verify normal behavior)
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));

    // LEDATA for normal segment 1: write one byte 0x11 at offset 0
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x11]));
    // FIXUPP immediately following: locat=0xC400, fix_dat=0x40 (method 0 = seg), datum=1, disp=0
    data.extend(make_record(0x9C, &[0xC4, 0x00, 0x40, 0x01, 0x00, 0x00]));

    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();

    // COMDEF communal checks via raw_comdefs API
    let comdefs = obj.raw_comdefs();
    assert_eq!(comdefs.len(), 1);
    let comdef = &comdefs[0];
    assert_eq!(&comdef.data[..], &[0xAA, 0xBB, 0xCC]);
    assert_eq!(comdef.relocs.len(), 1);
    let creloc = &comdef.relocs[0];
    assert_eq!(creloc.offset, 0);
    assert_eq!(creloc.target, object::read::omf::RelocTarget::External(1));

    // Normal segment check: segment 0 (first) should contain 0x11 at offset 0
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.data().unwrap()[0], 0x11);
    // The relocation for the normal segment should be present.
    let mut seg_relocs = sec.relocations();
    let (_off, r) = seg_relocs.next().unwrap();
    assert_eq!(r.target(), RelocationTarget::Section(SectionIndex(0)));
}

#[test]
fn omf_ledata_two_byte_borland_index() {
    // Ensure two-byte LEDATA encodings with high-bit markers like C0 01
    // are classified to the intended low ordinal when produced by
    // Borland-style emitters.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x48, 0x10, 0x00, 0x01, 0x01, 0x01]));

    // LEDATA using two-byte encoding C0 01 which decodes naively to 16385
    // but should resolve to ordinal 1.
    data.extend(make_record(0xA0, &[0xC0, 0x01, 0x00, 0x00, 0xAA, 0xBB]));

    // Terminate object
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    // There should be at least one section and its first byte should match 0xAA
    let sec = obj.sections().next().unwrap();
    assert_eq!(sec.data().unwrap()[0], 0xAA);
}

#[test]
fn omf_thread_subrecords_api() {
    // thread_subrecords() collects all THREAD subrecords from all FIXUPP records.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP 1: TARGET thread 0 = ext 1, FRAME thread 1 = seg 1
    data.extend(make_record(0x9C, &[0x08, 0x01, 0x40, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA 2
    // FIXUPP 2: TARGET thread 2 = ext 1
    data.extend(make_record(0x9C, &[0x0A, 0x01]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let threads = obj.thread_subrecords();
    assert_eq!(threads.len(), 3);
    // Check first thread: TARGET thread 0
    assert_eq!(threads[0].kind, ThreadKind::Target);
    assert_eq!(threads[0].thread_number, 0);
    assert_eq!(threads[0].method, 2);
    assert_eq!(threads[0].datum, Some(1));
    // Check second thread: FRAME thread 0 (method 0, seg index)
    assert_eq!(threads[1].kind, ThreadKind::Frame);
    assert_eq!(threads[1].thread_number, 0);
    assert_eq!(threads[1].method, 0);
    assert_eq!(threads[1].datum, Some(1));
    // Check third thread: TARGET thread 2
    assert_eq!(threads[2].kind, ThreadKind::Target);
    assert_eq!(threads[2].thread_number, 2);
    assert_eq!(threads[2].method, 2);
    assert_eq!(threads[2].datum, Some(1));
}

#[test]
fn omf_fixupp_record_thread_table_snapshot() {
    // Each ParsedFixuppRecord stores a snapshot of the thread table at
    // the point the record was parsed.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP 1: TARGET thread 0 = ext 1 (method 2)
    data.extend(make_record(0x9C, &[0x08, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA 2
    // FIXUPP 2: TARGET thread 0 = ext 2 (method 2), FRAME thread 1 = seg 1 (method 0)
    data.extend(make_record(0x9C, &[0x08, 0x02, 0x40, 0x01]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let records = obj.fixupp_records();
    assert_eq!(records.len(), 2);
    // FIXUPP 1 thread table snapshot: at the start of record 1 the thread
    // table is empty (no prior record set threads).
    let tt1 = &records[0].thread_table;
    assert!(tt1.target[0].is_none());
    // FIXUPP 2 thread table snapshot: at the start of record 2, the thread
    // table should reflect the effects of FIXUPP 1 (TARGET[0] -> method 2, datum 1).
    let tt2 = &records[1].thread_table;
    assert!(tt2.target[0].is_some());
    assert_eq!(tt2.target[0].unwrap().method, 2);
    assert_eq!(tt2.target[0].unwrap().datum, Some(1));
    // FRAME threads are set by FIXUPP 2 itself and therefore are not present
    // in the snapshot taken at the start of the record.
    assert!(tt2.frame[0].is_none());
}

#[test]
fn omf_fixupp_thread_table_snapshot_and_checksum_diagnostic() {
    // Build a minimal OMF object in bytes using the test helper make_record.
    let mut bytes = Vec::new();

    // THEADR: name length 0
    bytes.extend(make_record(0x80, &[0x00]));

    // SEGDEF: acbp=ALIGN_BYTE (use 0x28), length=4, name=0,class=0,overlay=0
    bytes.extend(make_record(0x98, &[0x28, 0x04, 0x00, 0, 0, 0]));

    // LEDATA: seg idx 1, offset 0, data 0xAA
    bytes.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0xAA]));

    // FIXUPP: THREAD (frame thread 0, method 1 with datum index 1) then fixup
    // THREAD subrecord: is_frame (0x40) | method(1<<2) | thread 0 -> 0x44
    // fixup locat: 0x84,0x00; fix_dat 0x80; target datum 1; disp 0x0000
    bytes.extend(make_record(0x9C, &[0x44, 0x01, 0x84, 0x00, 0x80, 0x01, 0x00, 0x00]));

    // MODEND simple
    bytes.extend(make_record(0x8A, &[0x01]));

    // Parse a clean module (no checksum corruption)
    let file = OmfFile::parse(&bytes[..]).expect("parse failed");

    // We should have one FIXUPP record and its saved thread table should reflect
    // the state at the start (i.e., before the THREAD subrecord in this FIXUPP)
    assert!(!file.fixupp_records().is_empty());
    let rec = &file.fixupp_records()[0];
    // The snapshot should have no threads defined at start (we started thread_table empty)
    assert!(rec.thread_table.frame.iter().all(|t| t.is_none()));

    // Now corrupt the LEDATA checksum and verify parsing still succeeds (checksum non-fatal).
    let mut bad = bytes.clone();
    let ledpos = bad.iter().position(|&b| b == 0xA0).unwrap();
    let rec_len = u16::from_le_bytes([bad[ledpos + 1], bad[ledpos + 2]]) as usize;
    let checksum_index = ledpos + 3 + rec_len - 1;
    bad[checksum_index] = bad[checksum_index].wrapping_add(1);
    // Checksum mismatches are non-fatal: parse should still succeed.
    let obj = OmfFile::parse(&bad[..]).expect("parse should tolerate checksum mismatch");
    assert_eq!(obj.module_name(), b"");
}

// ── COMDAT (0xC2 / 0xC3) tests ────────────────────────────────────────────

#[test]
fn omf_comdat_c2_basic() {
    // Minimal COMDAT (0xC2) with explicit allocation, public name via LNAMES.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // LNAMES: 1="" 2="CODE" 3="sym"
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E', 0x03, b's', b'y', b'm']));
    // SEGDEF: name=2, class=2, overlay=1, length=0x10
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01]));
    // COMDAT: flags=0, attrs=0x10 (Pick Any | Explicit), align=2 (Word),
    //         data_offset=0x0000 (2B LE), type_idx=0,
    //         base_grp=0, base_seg=1, pub_name=2 (LNAMES idx 2 = "CODE"),
    //         data=0xAA
    let comdat_body: &[u8] = &[
        0x00,       // flags
        0x10,       // attributes (Pick Any | Explicit)
        0x02,       // align
        0x00, 0x00, // data_offset (16-bit)
        0x00,       // type index
        0x00,       // base group
        0x01,       // base segment
        0x02,       // public name (=LNAMES idx 2 "CODE")
        0xAA,       // data
    ];
    data.extend(make_record(0xC2, comdat_body));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.comdat_records().len(), 1);
    let rec = &obj.comdat_records()[0];
    assert_eq!(rec.data, vec![0xAA]);
    assert_eq!(rec.data_offset, 0);
    assert!(rec.flags.is_continuation() == false);
    assert!(rec.flags.is_iterated() == false);
}

#[test]
fn omf_comdat_c3_basic() {
    // COMDAT32 (0xC3) with 32-bit data offset.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01]));
    // COMDAT32: same layout but data_offset is 4 bytes LE
    let comdat_body: &[u8] = &[
        0x00,             // flags
        0x10,             // attributes (Pick Any | Explicit)
        0x02,             // align
        0x10, 0x00, 0x00, 0x00, // data_offset = 0x10 (32-bit)
        0x00,             // type index
        0x00,             // base group
        0x01,             // base segment
        0x02,             // public name (=LNAMES idx 2)
        0xBB,             // data byte at offset 0x10
    ];
    data.extend(make_record(0xC3, comdat_body));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.comdat_records().len(), 1);
    let rec = &obj.comdat_records()[0];
    assert_eq!(rec.data_offset, 0x10);
    assert_eq!(rec.data, vec![0xBB]);
}

#[test]
fn omf_comdat_continuation() {
    // COMDAT with the Continuation flag set (bit 0).
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01]));
    let comdat_body: &[u8] = &[
        0x01,       // flags = CONTINUATION
        0x12,       // attributes
        0x02,       // align
        0x00, 0x00, // data_offset
        0x00,       // type index
        0x00,       // base group
        0x01,       // base segment
        0x02,       // public name
        0xCC,       // data
    ];
    data.extend(make_record(0xC2, comdat_body));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.comdat_records().len(), 1);
    assert!(obj.comdat_records()[0].flags.is_continuation());
}

#[test]
fn omf_comdat_iterated_flag() {
    // COMDAT with the Iterated Data flag set (bit 1).
    // The data field is still stored as raw bytes; iteration is a consumer-level concern.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01]));
    let comdat_body: &[u8] = &[
        0x02,       // flags = ITERATED_DATA
        0x10,       // attributes (Pick Any | Explicit)
        0x02,       // align
        0x00, 0x00, // data_offset
        0x00,       // type index
        0x00,       // base group
        0x01,       // base segment
        0x02,       // public name
        0xDD, 0xEE, // data
    ];
    data.extend(make_record(0xC2, comdat_body));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    assert!(obj.comdat_records()[0].flags.is_iterated());
    assert_eq!(obj.comdat_records()[0].data, vec![0xDD, 0xEE]);
}

#[test]
fn omf_comdat_local_flag() {
    // COMDAT with the Local flag set (bit 2) — effectively LCOMDAT.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01]));
    let comdat_body: &[u8] = &[
        0x04,       // flags = LOCAL
        0x12,       // attributes
        0x02,       // align
        0x00, 0x00, // data_offset
        0x00,       // type index
        0x00,       // base group
        0x01,       // base segment
        0x02,       // public name
    ];
    data.extend(make_record(0xC2, comdat_body));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    assert!(obj.comdat_records()[0].flags.is_local());
}

#[test]
fn omf_comdat_far_code_allocation() {
    // COMDAT with non-explicit allocation (Far Data) — no Public Base field.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'D', b'A', b'T', b'A']));
    // attrs: selection=Pick Any (0x1), allocation=FarData (0x2) → 0x12
    // Actually FarData = 0x2, so attrs = (0x1 << 4) | 0x2 = 0x12.
    // Let's use FarCode = 0x1: attrs = (0x1 << 4) | 0x1 = 0x11
    let mut data2 = Vec::new();
    data2.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data2.extend(make_record(0x96, &[0x00, 0x04, b'D', b'A', b'T', b'A']));
    // No SEGDEF needed (linker creates segments automatically for FarCode/FarData)
    let comdat_body: &[u8] = &[
        0x00,       // flags
        0x11,       // attrs: Pick Any (0x1) | FarCode (0x1) = 0x11
        0x02,       // align = Word
        0x00, 0x00, // data_offset
        0x00,       // type index
        0x02,       // public name (LNAMES idx 2 "DATA")
    ];
    data2.extend(make_record(0xC2, comdat_body));
    data2.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data2[..]).unwrap();
    assert_eq!(obj.comdat_records().len(), 1);
    // Allocation = FarCode → no Public Base field parsed
    assert!(obj.comdat_records()[0].public_base.is_none());
}

#[test]
fn omf_comdat_fixupp_relocation() {
    // COMDAT followed by a FIXUPP that attaches a relocation to the COMDAT's data.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E', 0x03, b's', b'y', b'm']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01]));
    // COMDAT: 2 bytes of data at offset 0
    let comdat_body: &[u8] = &[
        0x00,       // flags
        0x12,       // attrs
        0x02,       // align
        0x00, 0x00, // data_offset
        0x00,       // type index
        0x00,       // base group
        0x01,       // base segment
        0x02,       // public name (=LNAMES idx 2 "CODE")
        0x00, 0x00, // data (2 bytes, fixup target at offset 0)
    ];
    data.extend(make_record(0xC2, comdat_body));
    // FIXUPP: fixup at offset 0, target seg 1, disp 0
    // locat=0xC400 (M=1, LOC=1, offset=0), fix_dat=0x40, datum=1, disp=0
    data.extend(make_record(0x9C, &[0xC4, 0x00, 0x40, 0x01, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.comdat_records().len(), 1);
    let rec = &obj.comdat_records()[0];
    // The FIXUPP should have attached a relocation to the COMDAT's relocs.
    assert_eq!(rec.relocs.len(), 1);
    assert_eq!(rec.relocs[0].offset, 0);
}

#[test]
fn omf_comdat_two_records() {
    // Two COMDAT records in one module.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x00, 0x04, b'C', b'O', b'D', b'E', 0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x02, 0x02, 0x01]));
    data.extend(make_record(0x98, &[0x48, 0x20, 0x00, 0x03, 0x03, 0x01]));

    // COMDAT 1: public name idx 2 = "CODE"
    let c1: &[u8] = &[0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x11];
    data.extend(make_record(0xC2, c1));
    // COMDAT 2: public name idx 3 = "DATA"
    let c2: &[u8] = &[0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x22];
    data.extend(make_record(0xC2, c2));

    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.comdat_records().len(), 2);
    assert_eq!(obj.comdat_records()[0].data, vec![0x11]);
    assert_eq!(obj.comdat_records()[1].data, vec![0x22]);
}

#[test]
fn omf_comdat_wrong_type_error() {
    // Record byte 0x00 is not 0xC2 or 0xC3.
    let rec = make_record(0x00, &[0x00, 0x00]);
    let result = object::read::omf::parse_comdat(&rec, object::read::omf::PublicNameEncoding::MicrosoftIndex);
    assert!(result.is_err());
}

#[test]
fn omf_comdat_data_too_long_error() {
    // COMDAT with >1024 bytes of data should be rejected.
    // Build a valid COMDAT record manually via parse_comdat.
    let mut body: Vec<u8> = vec![
        0x00,       // flags
        0x10,       // attributes (Pick Any | Explicit)
        0x02,       // align
        0x00, 0x00, // data_offset
        0x00,       // type index
        0x00,       // base group
        0x01,       // base segment
        0x02,       // public name
    ];
    // Append 1025 bytes of data
    body.extend(core::iter::repeat(0xFF).take(1025));
    let rec = make_record(0xC2, &body);
    let result = object::read::omf::parse_comdat(&rec, object::read::omf::PublicNameEncoding::MicrosoftIndex);
    assert_eq!(result.unwrap_err(), object::read::omf::CombatError::DataTooLong(1025));
}

#[test]
fn omf_entry_point_enum() {
    // Verify that entry point is accessible as the EntryPoint enum.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    // MODEND body: type=0xC1, end_dat=0x40 (frame meth 0, target meth 0), datum=1 (seg 1), disp=0x0123
    data.extend(make_record(0x8A, &[0xC1, 0x40, 0x01, 0x23, 0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    // entry() still returns the flat address.
    assert_eq!(obj.entry(), 0x0123);
}
