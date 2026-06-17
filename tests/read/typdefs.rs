use object::read::omf::OmfFile;

mod common {
    // Import helpers from the existing omf tests via relative path.
    pub use crate::read::omf::{make_record};
}

#[test]
fn typdef_legacy_nullname_near() {
    let mut data = Vec::new();
    data.extend(common::make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // TYPDEF: legacy null name (0x00), NEAR leaf: 0x62, var type 0x77, length 32
    data.extend(common::make_record(0x8E, &[0x00, 0x62, 0x77, 32]));
    data.extend(common::make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    // Parsing should succeed and module name should be present
    assert_eq!(obj.module_name(), b"HELLO");
    // typdefs should contain one entry
    assert_eq!(obj.raw_typdefs().len(), 1);
}

#[test]
fn typdef_far_references_previous_near() {
    let mut data = Vec::new();
    data.extend(common::make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // First TYPDEF: null name + NEAR (tag 0x62, var 0x77, len = 16)
    data.extend(common::make_record(0x8E, &[0x00, 0x62, 0x77, 16]));
    // Second TYPDEF: null name + FAR (tag 0x61, var 0x77, count=2, type index=1)
    // Encode number_of_elements as single byte 2
    data.extend(common::make_record(0x8E, &[0x00, 0x61, 0x77, 2, 0x01]));
    data.extend(common::make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.raw_typdefs().len(), 2);
}

#[test]
fn typdef_unknown_leaf_is_opaque() {
    let mut data = Vec::new();
    data.extend(common::make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // TYPDEF with unknown leaf tag 0x99 followed by some bytes
    data.extend(common::make_record(0x8E, &[0x00, 0x99, 0xAA, 0xBB, 0xCC]));
    data.extend(common::make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    let t = &obj.raw_typdefs()[0];
    match &t.descriptor {
        object::read::omf::ParsedTypDefDescriptor::Opaque(bytes) => {
            assert!(!bytes.is_empty());
        }
        _ => panic!("expected opaque descriptor"),
    }
}
