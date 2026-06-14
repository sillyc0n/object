use object::read::omf::OmfFile;
use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSegment, ObjectSymbol, Permissions, RelocationTarget, SectionIndex, SectionKind, SymbolIndex};

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
fn omf_loc4_skip_threaded() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP body:
    // 1. Thread subrecord: TARGET thread 0 = ext 1
    // 2. loc=4 (skip), fix_dat referencing thread 0
    // 3. Normal fixup referencing thread 0
    data.extend(make_record(0x9C, &[0x08, 0x01, 0x90, 0x00, 0x48, 0x00, 0x00, 0x84, 0x02, 0x48, 0x00, 0x00]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let mut relocs = obj.sections().next().unwrap().relocations();
    let (off, r) = relocs.next().unwrap();
    assert_eq!(off, 2);
    assert_eq!(r.target(), RelocationTarget::Symbol(SymbolIndex(0)));
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
fn omf_extdef_ordinals_ignore_comdef() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x88, &[0x00, 0xA1])); // MS extensions
    data.extend(make_record(0xB0, &[0x03, b'c', b'o', b'm', 0x00, 0x62, 0x04])); // COMDEF
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00])); // EXTDEF #1
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00]));
    data.extend(make_record(0x9C, &[0x84, 0x00, 0x42, 0x01, 0x00, 0x00])); // explicit ext #1 + disp 0
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
fn omf_modend_external_start_is_error() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x8C, &[0x04, b'm', b'a', b'i', b'n', 0x00]));
    // module_type = START|RELOC, end_dat = explicit frame method 0 + target method 6
    data.extend(make_record(0x8A, &[0xC1, 0x06, 0x01, 0x01]));
    assert!(OmfFile::parse(&data[..]).is_err());
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
        // Methods 4/5/6 do not carry a datum.
        let thread_b0 = method << 2;
        data.extend(make_record(0x9C, &[thread_b0]));

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
