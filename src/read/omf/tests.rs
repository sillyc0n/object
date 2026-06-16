++ use crate::read::omf::*;
++ use crate::read::OmfFile;

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to compute OMF record checksum byte so that sum of all bytes in
    // record (type, len_lo, len_hi, body..., checksum) has low-order byte == 0.
    fn checksum_for_record(prefix: &[u8]) -> u8 {
        let mut sum: u8 = 0;
        for &b in prefix {
            sum = sum.wrapping_add(b);
        }
        (!sum).wrapping_add(1)
    }

    #[test]
    fn fixupp_thread_table_snapshot_and_checksum_diagnostic() {
        // Build a minimal OMF object in bytes.
        let mut bytes = Vec::new();

        // THEADR: name length 0
        let rec_type = RT_THEADR;
        let body = [0x00u8];
        let len = (body.len() + 1) as u16; // +1 for checksum
        bytes.push(rec_type);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&body);
        let c = checksum_for_record(&bytes);
        bytes.push(c);

        // SEGDEF: acbp=ALIGN_BYTE<<5, length=4, name=0,class=0,overlay=0
        let rec_type = RT_SEGDEF;
        let acbp = (ALIGN_BYTE << ACBP_A_SHIFT) as u8;
        let mut seg_body = Vec::new();
        seg_body.push(acbp);
        seg_body.extend_from_slice(&4u16.to_le_bytes());
        seg_body.push(0); // name idx
        seg_body.push(0); // class idx
        seg_body.push(0); // overlay idx
        let len = (seg_body.len() + 1) as u16;
        bytes.push(rec_type);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&seg_body);
        let c = checksum_for_record(&bytes);
        bytes.push(c);

        // LEDATA: seg idx 1, offset 0, data 0xAA
        let rec_type = RT_LEDATA;
        let mut le_body = Vec::new();
        le_body.push(1); // seg idx
        le_body.extend_from_slice(&0u16.to_le_bytes()); // offset
        le_body.push(0xAA);
        let len = (le_body.len() + 1) as u16;
        bytes.push(rec_type);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&le_body);
        let c = checksum_for_record(&bytes);
        bytes.push(c);

        // FIXUPP: THREAD (frame thread 0, method 1 with datum index 1) then fixup
        let rec_type = RT_FIXUPP;
        let mut fx_body = Vec::new();
        // THREAD subrecord: is_frame (0x40) | method(1<<2) | thread 0
        fx_body.push(0x40 | (1 << 2) | 0);
        fx_body.push(1); // datum index = 1

        // Fixup locat: logical 0x8000 | (1<<10) | offset 0 => stored bytes [0x84,0x00]
        fx_body.push(0x84);
        fx_body.push(0x00);
        // fix_dat: F=1 (frame from thread), no T so target explicit (0)
        fx_body.push(0x80u8);
        // target datum index (explicit)
        fx_body.push(1);
        // displacement u16
        fx_body.extend_from_slice(&0u16.to_le_bytes());

        let len = (fx_body.len() + 1) as u16;
        bytes.push(rec_type);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&fx_body);
        let c = checksum_for_record(&bytes);
        bytes.push(c);

        // MODEND with start: module_type with START|RELOC bits
        let rec_type = RT_MODEND;
        let mut me_body = Vec::new();
        me_body.push(MODEND_START | MODEND_RELOC);
        // end_dat = 0 (inline frame/target methods); frame datum index = 1
        me_body.push(0);
        me_body.push(1); // frame datum
        me_body.push(1); // target datum
        me_body.extend_from_slice(&0u16.to_le_bytes()); // displacement
        let len = (me_body.len() + 1) as u16;
        bytes.push(rec_type);
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&me_body);
        let c = checksum_for_record(&bytes);
        bytes.push(c);

        // Parse a clean module (no checksum corruption)
        let file = OmfFile::parse(&bytes[..]).expect("parse failed");

        // We should have one FIXUPP record and its saved thread table should reflect
        // the state at the start (i.e., before the THREAD subrecord in this FIXUPP)
        assert!(!file.fixupp_records.is_empty());
        let rec = &file.fixupp_records[0];
        // The snapshot should have no threads defined at start (we started thread_table empty)
        assert!(rec.thread_table.frame.iter().all(|t| t.is_none()));

        // Now verify that a checksum mismatch causes parse to fail.
        // Corrupt the LEDATA checksum and expect Err.
        let mut bad = bytes.clone();
        let ledpos = bad.iter().position(|&b| b == RT_LEDATA).unwrap();
        let rec_len = u16::from_le_bytes([bad[ledpos + 1], bad[ledpos + 2]]) as usize;
        let checksum_index = ledpos + 3 + rec_len - 1;
        bad[checksum_index] = bad[checksum_index].wrapping_add(1);
        assert!(OmfFile::parse(&bad[..]).is_err());
    }
}
