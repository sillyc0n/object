use object::read::omf::{OmfFile, ThreadKind};
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
    // B7H (LPUBDEF 32-bit) - should be ignored
    data.extend(make_record(0xB7, &[0x00, 0x01, 0x03, b'f', b'o', b'o', 0x02, 0x00, 0x00, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.symbols().count(), 0);
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
fn omf_ledata_must_be_followed_by_fixupp() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])); // LEDATA
    // Insert intervening record (e.g., PUBDEF)
    data.extend(make_record(0x90, &[0x00, 0x01, 0x03, b'f', b'o', b'o', 0x02, 0x00, 0x00]));
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x48, 0x00, 0x00])); // FIXUPP
    data.extend(make_record(0x8A, &[0x01]));
    
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err(), "FIXUPP record MUST immediately follow LEDATA/LIDATA if they have fixups");
}

#[test]
fn omf_lidata_must_be_followed_by_fixupp() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA2, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])); // LIDATA
    // Insert intervening record (e.g., SEGDEF)
    data.extend(make_record(0x96, &[0x04, b'D', b'A', b'T', b'A']));
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x48, 0x00, 0x00])); // FIXUPP
    data.extend(make_record(0x8A, &[0x01]));
    
    let result = OmfFile::parse(&data[..]);
    assert!(result.is_err(), "FIXUPP record MUST immediately follow LEDATA/LIDATA if they have fixups");
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
    // FIXUPP 1 thread table: should have TARGET[0] = (method 2, datum 1)
    let tt1 = &records[0].thread_table;
    assert!(tt1.target[0].is_some());
    assert_eq!(tt1.target[0].unwrap().method, 2);
    assert_eq!(tt1.target[0].unwrap().datum, Some(1));
    // All other threads should be empty in the first record
    assert!(tt1.target[1].is_none());
    assert!(tt1.target[2].is_none());
    assert!(tt1.target[3].is_none());
    assert!(tt1.frame[0].is_none());
    // FIXUPP 2 thread table: TARGET[0] should now be (method 2, datum 2)
    let tt2 = &records[1].thread_table;
    assert!(tt2.target[0].is_some());
    assert_eq!(tt2.target[0].unwrap().method, 2);
    assert_eq!(tt2.target[0].unwrap().datum, Some(2));
    // FRAME[0] should be set
    assert!(tt2.frame[0].is_some());
    assert_eq!(tt2.frame[0].unwrap().method, 0);
    assert_eq!(tt2.frame[0].unwrap().datum, Some(1));
    // Others still empty
    assert!(tt2.frame[1].is_none());
    assert!(tt2.frame[2].is_none());
    assert!(tt2.frame[3].is_none());
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
