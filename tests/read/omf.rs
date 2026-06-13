use object::read::omf::OmfFile;
use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionIndex, SymbolIndex};

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
    data.extend(make_record(0x8C, &[0x04, b'p', b'u', b't', b's', 0x00]));
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    // FIXUPP 1: Define TARGET thread 0
    data.extend(make_record(0x9C, &[0x08, 0x01]));
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
    data.extend(make_record(0xA0, &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
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
    // TYPDEF body: name="int", index=1; name="", index=2
    data.extend(make_record(0x8E, &[0x03, b'i', b'n', b't', 0x01, 0x00, 0x02]));
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
fn omf_grpdef_rejects_non_ff_component() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    data.extend(make_record(0x96, &[0x04, b'C', b'O', b'D', b'E', 0x05, b'G', b'R', b'O', b'U', b'P']));
    data.extend(make_record(0x98, &[0x28, 0x10, 0x00, 0x01, 0x01, 0x01]));
    data.extend(make_record(0x9A, &[0x02, 0xFE, 0x01])); // bad component marker
    data.extend(make_record(0x8A, &[0x01]));
    assert!(OmfFile::parse(&data[..]).is_err());
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
