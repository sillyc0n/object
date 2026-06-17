use object::read::omf::OmfFile;

use crate::read::omf::make_record;

#[test]
fn comdef_worked_example_near_far_borland() {
    let mut data = Vec::new();
    data.extend(make_record(0x80, &[0x05, b'H', b'E', b'L', b'L', b'O']));

    // Build a COMDEF record with three entries:
    // 1) Near: name "N", type=0, DST_NEAR (0x62), size=5
    // 2) Far:  name "F", type=0, DST_FAR  (0x61), count=3, elem_size=2
    // 3) Borland segment: name "B", type=0, DST=0x10
    let mut comdef_body = Vec::new();
    // Entry 1: N
    comdef_body.extend(&[0x01, b'N', 0x00, 0x62, 0x05]);
    // Entry 2: F
    comdef_body.extend(&[0x01, b'F', 0x00, 0x61, 0x03, 0x02]);
    // Entry 3: B (Borland segment index 0x10)
    comdef_body.extend(&[0x01, b'B', 0x00, 0x10]);

    data.extend(make_record(0xB0, &comdef_body));
    data.extend(make_record(0x8A, &[0x01]));

    let obj = OmfFile::parse(&data[..]).unwrap();

    let raws = obj.raw_comdefs();
    assert_eq!(raws.len(), 3);

    // Near entry
    assert_eq!(raws[0].name, b"N");
    assert_eq!(raws[0].type_index, 0);
    match &raws[0].communal {
        object::read::omf::ParsedCommunalKind::Near { size } => assert_eq!(*size, 5),
        _ => panic!("expected NEAR communal for entry 0"),
    }

    // Far entry
    assert_eq!(raws[1].name, b"F");
    assert_eq!(raws[1].type_index, 0);
    match &raws[1].communal {
        object::read::omf::ParsedCommunalKind::Far { count, element_size } => {
            assert_eq!(*count, 3);
            assert_eq!(*element_size, 2);
        }
        _ => panic!("expected FAR communal for entry 1"),
    }

    // Borland segment entry
    assert_eq!(raws[2].name, b"B");
    assert_eq!(raws[2].type_index, 0);
    match &raws[2].communal {
        object::read::omf::ParsedCommunalKind::BorlandSegment { index } => assert_eq!(*index, 0x10),
        _ => panic!("expected BorlandSegment communal for entry 2"),
    }
}
