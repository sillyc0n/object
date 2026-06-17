use object::read::omf::OmfFile;

use crate::read::omf::make_record;

#[test]
fn read_varlen_edge_cases() {
    // Single-byte 0x80 should be accepted as 128 by the reader.
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // COMDEF: name empty, type NEAR (0x62), length=0x80
    data.extend(make_record(0xB0, &[0x00, 0x62, 0x80]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    assert_eq!(obj.module_name(), b"HELLO");
    assert_eq!(obj.raw_comdefs().len(), 1);
    match &obj.raw_comdefs()[0].communal {
        object::read::omf::ParsedCommunalKind::Near { size } => assert_eq!(*size, 0x80),
        _ => panic!("expected near communal with size 128"),
    }
}

#[test]
fn comdef_borland_segment_parsing() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));
    // COMDEF: name "X", type index=0, data type = 0x10 (Borland segment index)
    data.extend(make_record(0xB0, &[0x01, b'X', 0x00, 0x10]));
    data.extend(make_record(0x8A, &[0x01]));
    let obj = OmfFile::parse(&data[..]).unwrap();
    // Should have created a communal symbol for "X"
    let sym = obj.symbols().next().unwrap();
    assert_eq!(sym.name(), Ok("X"));
    assert_eq!(obj.raw_comdefs().len(), 1);
    match &obj.raw_comdefs()[0].communal {
        object::read::omf::ParsedCommunalKind::BorlandSegment { index } => assert_eq!(*index, 0x10),
        _ => panic!("expected BorlandSegment communal kind"),
    }
}
