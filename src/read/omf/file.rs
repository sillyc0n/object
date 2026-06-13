use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use crate::omf;
use crate::read::{
    self, Architecture, BinaryFormat, Error, FileFlags, Object, ObjectKind, ReadError, ReadRef,
    Result, SectionIndex, SymbolIndex, ObjectSection,
};
use crate::Endianness;

use super::*;

/// An OMF object file.
#[derive(Debug)]
pub struct OmfFile<'data, R: ReadRef<'data> = &'data [u8]> {
    #[allow(unused)]
    data: R,
    pub(super) module_name: &'data [u8],
    pub(super) lnames: Vec<&'data [u8]>,
    /// The segment list of the file.
    pub segments: Vec<ParsedSegment<'data>>,
    /// The group list of the file.
    pub groups: Vec<ParsedGroup>,
    /// The symbol list of the file.
    pub symbols: Vec<ParsedSymbol<'data>>,
    /// Decoded FIXUPP records for dump purposes.
    pub fixupp_records: Vec<ParsedFixuppRecord>,
    pub(super) extdef_symbol_indices: Vec<SymbolIndex>,
    pub(super) entry: Option<(u16, u16)>,
    #[allow(unused)]
    pub(super) has_ms_ext: bool,
    pub(super) marker: PhantomData<&'data ()>,
}

impl<'data, R: ReadRef<'data>> OmfFile<'data, R> {
    /// Parse the raw OMF data.
    pub fn parse(data: R) -> Result<Self> {
        let len = data.len().read_error("Unknown OMF file size")?;
        let bytes = data.read_bytes_at(0, len).read_error("OMF read failed")?;

        let mut file = OmfFile {
            data,
            module_name: &[],
            lnames: Vec::new(),
            segments: Vec::new(),
            groups: Vec::new(),
            symbols: Vec::new(),
            fixupp_records: Vec::new(),
            extdef_symbol_indices: Vec::new(),
            entry: None,
            has_ms_ext: false,
            marker: PhantomData,
        };

        file.scan(bytes)?;
        file.finalize();

        Ok(file)
    }

    fn scan(&mut self, data: &'data [u8]) -> Result<()> {
        let mut pos = 0;
        let mut last_data_seg_ordinal: Option<u16> = None;
        // Tracks whether the most recently processed record was LEDATA/LIDATA.
        let mut prev_was_data_record = false;
        // THREAD state persists across successive FIXUPP records for the duration of module scanning.
        let mut thread_table = ThreadTable::new();
        let mut first_record = true;

        loop {
            if pos >= data.len() {
                if self.module_name.is_empty() && self.segments.is_empty() {
                    return Err(Error("OMF file has no records"));
                }
                return Err(Error("OMF file has no MODEND record"));
            }

            let record_type = data[pos];
            if first_record && record_type != omf::RT_THEADR {
                return Err(Error("not an OMF object file"));
            }
            first_record = false;

            if pos + 3 > data.len() {
                return Err(Error("truncated OMF record header"));
            }
            let record_length = u16::from_le_bytes([data[pos + 1], data[pos + 2]]) as usize;
            if record_length < 1 {
                return Err(Error("invalid OMF record length"));
            }
            if pos + 3 + record_length > data.len() {
                return Err(Error("truncated OMF record"));
            }
            let record_bytes = &data[pos..pos + 3 + record_length];
            Self::verify_record_checksum(record_bytes, pos, record_type);
            let record_body = &data[pos + 3..pos + 3 + record_length - 1];

            match record_type {
                omf::RT_THEADR => {
                    self.parse_theadr(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_LNAMES => {
                    self.parse_lnames(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_SEGDEF => {
                    self.parse_segdef(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_GRPDEF => {
                    self.parse_grpdef(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_EXTDEF => {
                    self.parse_extdef(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_TYPDEF => {
                    self.parse_typdef(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_PUBDEF => {
                    self.parse_pubdef(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_LINNUM => {
                    self.parse_linnum(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_COMDEF => {
                    self.parse_comdef(record_body)?;
                    prev_was_data_record = false;
                }
                omf::RT_LEDATA => {
                    let ord = self.parse_ledata(record_body)?;
                    last_data_seg_ordinal = Some(ord);
                    prev_was_data_record = true;
                }
                omf::RT_LIDATA => {
                    let ord = self.parse_lidata(record_body)?;
                    last_data_seg_ordinal = Some(ord);
                    prev_was_data_record = true;
                }
                omf::RT_FIXUPP => {
                    self.parse_fixupp(record_body, last_data_seg_ordinal, &mut thread_table)?;
                    // A FIXUPP record consumes the "immediately follows" slot;
                    // anything after it (until the next LEDATA/LIDATA) is no
                    // longer adjacent to data.
                    prev_was_data_record = false;
                }
                omf::RT_MODEND => {
                    self.parse_modend(record_body)?;
                    // pos += 3 + record_length; // this is redundant - MODEND record is, by definition, the last record in an object module
                    break;
                }
                omf::RT_COMENT => {
                    // COMENT cannot appear between a FIXUPP record and the
                    // LEDATA/LIDATA it refers to.
                    if prev_was_data_record {
                        return Err(Error(
                            "COMENT record cannot appear between LEDATA/LIDATA and its FIXUPP",
                        ));
                    }
                    self.parse_coment(record_body)?;
                    prev_was_data_record = false;
                }
                _ => {
                    prev_was_data_record = false;
                }
            }

            pos += 3 + record_length;
        }

        Ok(())
    }

    fn finalize(&mut self) {
        let mut base = 0u64;
        for seg in &mut self.segments {
            if seg.is_absolute {
                // Absolute segment: address is fixed by its declared frame number.
                seg.flat_base = (seg.frame as u64) << 4;
            } else {
                let alignment = seg.alignment as u64;
                if alignment > 1 {
                    base = (base + (alignment - 1)) & !(alignment - 1);
                }
                seg.flat_base = base;
                let eff_len = if seg.big { 0x10000 } else { seg.length as u64 };
                base += eff_len;
            }

            let eff_len = if seg.big { 0x10000 } else { seg.length as u64 };
            seg.data.resize(eff_len as usize, 0);
        }
    }

    /// Verify the checksum of a single OMF record.
    ///
    /// OMF defines the checksum so that the low-order byte of the sum of all
    /// bytes in the record, including type, length, body, and checksum, is zero.
    /// Checksum mismatch is treated as non-fatal in `parse()`: it does not stop
    /// structural decoding, but in debug builds it emits a warning.
    fn verify_record_checksum(record_bytes: &[u8], pos: usize, record_type: u8) {
        let mut sum = 0u8;
        for &b in record_bytes {
            sum = sum.wrapping_add(b);
        }

        if sum != 0 {
            #[cfg(debug_assertions)]
            eprintln!(
                "warning: OMF checksum mismatch at record offset {:#x}, type {:#04x}",
                pos, record_type
            );
        }
    }

    fn parse_theadr(&mut self, body: &'data [u8]) -> Result<()> {
        let (name, _) = omf::read_name(body, 0).read_error("truncated THEADR")?;
        self.module_name = name;
        Ok(())
    }

    fn parse_lnames(&mut self, body: &'data [u8]) -> Result<()> {
        let mut pos = 0;
        while pos < body.len() {
            let (name, consumed) = omf::read_name(body, pos).read_error("truncated LNAMES")?;
            self.lnames.push(name);
            pos += consumed;
        }
        Ok(())
    }

    fn parse_segdef(&mut self, body: &'data [u8]) -> Result<()> {
        if body.is_empty() {
            return Err(Error("truncated SEGDEF"));
        }
        let acbp = body[0];
        let a_field = (acbp & omf::ACBP_A_MASK) >> omf::ACBP_A_SHIFT;
        let c_field = (acbp & omf::ACBP_C_MASK) >> omf::ACBP_C_SHIFT;
        let b_bit = (acbp & omf::ACBP_B_MASK) != 0;
        let mut pos = 1;

        let mut frame = 0u16;
        if a_field == omf::ALIGN_ABSOLUTE {
            if pos + 3 > body.len() {
                return Err(Error("truncated SEGDEF absolute fields"));
            }
            frame = u16::from_le_bytes([body[pos], body[pos + 1]]);
            pos += 3; // skips 2 (frame) + 1 (offset, ignored by LINK)
        }

        if pos + 2 > body.len() {
            return Err(Error("truncated SEGDEF length"));
        }
        let length = u16::from_le_bytes([body[pos], body[pos + 1]]);
        pos += 2;

        let (seg_name_idx, c) = omf::read_index(body, pos).read_error("truncated SEGDEF name")?;
        pos += c;
        let (class_name_idx, c) = omf::read_index(body, pos).read_error("truncated SEGDEF class")?;
        pos += c;
        let (_overlay_idx, c) =
            omf::read_index(body, pos).read_error("truncated SEGDEF overlay")?;
        pos += c;

        if pos != body.len() {
            return Err(Error("unexpected trailing bytes in SEGDEF"));
        }

        let alignment = match a_field {
            omf::ALIGN_ABSOLUTE => 1u32,
            omf::ALIGN_BYTE => 1,
            omf::ALIGN_WORD => 2,
            omf::ALIGN_PARA => 16,
            omf::ALIGN_PAGE => 256,
            _ => return Err(Error("unknown SEGDEF alignment")),
        };

        let ordinal = (self.segments.len() + 1) as u16;
        if self.segments.len() >= 255 {
            return Err(Error("SEGDEF count exceeds LINK limit of 255"));
        }

        self.segments.push(ParsedSegment {
            name_idx: if seg_name_idx == 0 {
                u16::MAX
            } else {
                seg_name_idx - 1
            },
            class_idx: if class_name_idx == 0 {
                u16::MAX
            } else {
                class_name_idx - 1
            },
            length,
            big: b_bit,
            alignment,
            combine: c_field,
            frame,
            data: Vec::new(),
            relocs: Vec::new(),
            ordinal,
            is_absolute: a_field == omf::ALIGN_ABSOLUTE,
            flat_base: 0,
            _marker: PhantomData,
        });

        Ok(())
    }

    fn parse_grpdef(&mut self, body: &'data [u8]) -> Result<()> {
        let (name_idx, mut pos) = omf::read_index(body, 0).read_error("truncated GRPDEF name")?;

        if name_idx == 0 || name_idx as usize > self.lnames.len() {
            return Err(Error("GRPDEF name index out of range"));
        }

        let mut members = Vec::new();
        while pos < body.len() {
            // Consume the type byte. Per spec, LINK ignores its value (only 0xFF
            // is officially "segment index", but other Intel-defined types
            // 0xFE/0xFD/0xFB/0xFA are treated the same way by LINK).
            let _component_type = *body.get(pos).read_error("truncated GRPDEF component")?;
            pos += 1;

            let (seg_idx, c) = omf::read_index(body, pos).read_error("truncated GRPDEF member")?;
            pos += c;
            if seg_idx == 0 || seg_idx as usize > self.segments.len() {
                return Err(Error("GRPDEF segment index out of range"));
            }
            members.push(seg_idx);
        }

        if self.groups.len() >= 21 {
            return Err(Error("GRPDEF count exceeds LINK limit of 21"));
        }

        self.groups.push(ParsedGroup {
            name_idx: name_idx - 1,
            members,
        });

        Ok(())
    }

    fn parse_extdef(&mut self, body: &'data [u8]) -> Result<()> {
        let mut pos = 0;
        while pos < body.len() {
            let (name, c) = omf::read_name(body, pos).read_error("truncated EXTDEF name")?;
            pos += c;
            let (_type_idx, c) = omf::read_index(body, pos).read_error("truncated EXTDEF type")?;
            pos += c;

            if self.extdef_symbol_indices.len() >= 1023 {
                return Err(Error("EXTDEF count exceeds LINK limit of 1023"));
            }

            let sym_index = SymbolIndex(self.symbols.len());
            self.symbols.push(ParsedSymbol {
                name,
                kind: ParsedSymbolKind::External,
                seg_ordinal: 0,
                offset: 0,
            });
            self.extdef_symbol_indices.push(sym_index);
        }

        Ok(())
    }

    fn parse_typdef(&mut self, body: &'data [u8]) -> Result<()> {
        let mut pos = 0;

        // The name field is always a single null byte (p.665).
        if pos >= body.len() {
            return Err(Error("truncated TYPDEF name"));
        }
        if body[pos] != 0x00 {
            return Err(Error("TYPDEF name field must be null"));
        }
        pos += 1;

        // Parse the eight-leaf descriptor: a sequence of leaf descriptors.
        while pos < body.len() {
            let tag = body[pos];
            pos += 1;

            match tag {
                0x62 => {
                    // NEAR variable: 62H variable_type length_in_bits
                    if pos >= body.len() {
                        return Err(Error("truncated TYPDEF NEAR variable type"));
                    }
                    let _variable_type = body[pos]; // 77H/79H/7BH, ignored by LINK
                    pos += 1;

                    let (_length_in_bits, c) = omf::read_varlen(body, pos)
                        .read_error("truncated TYPDEF length_in_bits")?;
                    pos += c;
                }
                0x61 => {
                    // FAR variable: 61H variable_type number_of_elements element_type_index
                    if pos >= body.len() {
                        return Err(Error("truncated TYPDEF FAR variable type"));
                    }
                    let _variable_type = body[pos]; // restricted to 77H (array)
                    pos += 1;

                    let (_number_of_elements, c) = omf::read_varlen(body, pos)
                        .read_error("truncated TYPDEF number_of_elements")?;
                    pos += c;

                    let (_element_type_index, c) = omf::read_index(body, pos)
                        .read_error("truncated TYPDEF element_type_index")?;
                    pos += c;
                }
                _ => return Err(Error("unrecognized TYPDEF leaf descriptor tag")),
            }
        }

        Ok(())
    }

    fn parse_pubdef(&mut self, body: &'data [u8]) -> Result<()> {
        let mut pos = 0;
        let (group_idx, c) = omf::read_index(body, pos).read_error("truncated PUBDEF group")?;
        pos += c;
        let (seg_idx, c) = omf::read_index(body, pos).read_error("truncated PUBDEF segment")?;
        pos += c;

        if seg_idx == 0 && group_idx == 0 {
            if pos + 2 > body.len() {
                return Err(Error("truncated PUBDEF frame"));
            }
            // _frame
            pos += 2;
        }

        while pos < body.len() {
            let (name, c) = omf::read_name(body, pos).read_error("truncated PUBDEF name")?;
            pos += c;
            if pos + 2 > body.len() {
                return Err(Error("truncated PUBDEF offset"));
            }
            let pub_offset = u16::from_le_bytes([body[pos], body[pos + 1]]);
            pos += 2;
            let (_type_idx, c) = omf::read_index(body, pos).read_error("truncated PUBDEF type")?;
            pos += c;

            self.symbols.push(ParsedSymbol {
                name,
                kind: ParsedSymbolKind::Public,
                seg_ordinal: seg_idx,
                offset: pub_offset,
            });
        }

        Ok(())
    }

    fn parse_linnum(&mut self, body: &'data [u8]) -> Result<()> {
        let mut pos = 0;

        // group_index is always a single zero byte (p.672).
        let group_index = *body.get(pos).read_error("truncated LINNUM group index")?;
        if group_index != 0 {
            return Err(Error("LINNUM group index must be zero"));
        }
        pos += 1;

        let (_seg_idx, c) = omf::read_index(body, pos).read_error("truncated LINNUM segment")?;
        pos += c;

        while pos < body.len() {
            if pos + 4 > body.len() {
                return Err(Error("truncated LINNUM entry"));
            }
            // _line_number = u16::from_le_bytes([body[pos], body[pos + 1]]);
            // _offset = u16::from_le_bytes([body[pos + 2], body[pos + 3]]);
            pos += 4;
        }
        Ok(())
    }

    fn parse_ledata(&mut self, body: &[u8]) -> Result<u16> {
        let (seg_idx, c) = omf::read_index(body, 0).read_error("truncated LEDATA segment")?;
        if seg_idx == 0 || seg_idx as usize > self.segments.len() {
            return Err(Error("LEDATA segment index out of range"));
        }

        if c + 2 > body.len() {
            return Err(Error("truncated LEDATA offset"));
        }
        let data_offset = u16::from_le_bytes([body[c], body[c + 1]]) as usize;
        let data_bytes = &body[c + 2..];

        // Spec limit: data field max 1024 bytes.
        if data_bytes.len() > 1024 {
            return Err(Error("LEDATA data field exceeds 1024-byte LINK limit"));
        }

        let seg = &mut self.segments[seg_idx as usize - 1];

        let required = data_offset + data_bytes.len();
        if required > 0x10000 {
            return Err(Error("LEDATA data overflow: exceeds 64 KB segment limit"));
        }

        if seg.data.len() < required {
            seg.data.resize(required, 0);
        }
        seg.data[data_offset..required].copy_from_slice(data_bytes);

        Ok(seg_idx)
    }

    fn parse_lidata(&mut self, body: &[u8]) -> Result<u16> {
        let (seg_idx, c) = omf::read_index(body, 0).read_error("truncated LIDATA segment")?;
        if seg_idx == 0 || seg_idx as usize > self.segments.len() {
            return Err(Error("LIDATA segment index out of range"));
        }

        if c + 2 > body.len() {
            return Err(Error("truncated LIDATA offset"));
        }
        let data_offset = u16::from_le_bytes([body[c], body[c + 1]]) as usize;
        let block_data = &body[c + 2..];

        // Spec limit: an iterated data block max 512 bytes.
        if block_data.len() > 512 {
            return Err(Error("LIDATA iterated data block exceeds 512-byte LINK limit"));
        }

        let (expanded, _) = expand_lidata(block_data, 0, 0)?;

        let seg = &mut self.segments[seg_idx as usize - 1];
        let required = data_offset + expanded.len();
        if required > 0x10000 {
            return Err(Error("LIDATA data overflow"));
        }
        if seg.data.len() < required {
            seg.data.resize(required, 0);
        }
        seg.data[data_offset..required].copy_from_slice(&expanded);

        Ok(seg_idx)
    }

    fn parse_fixupp(
        &mut self,
        body: &[u8],
        last_seg_ordinal: Option<u16>,
        thread_table: &mut ThreadTable,
    ) -> Result<()> {
        let mut pos = 0;
        let mut subrecords = Vec::new();

        while pos < body.len() {
            let b0 = body[pos];

            if b0 & 0x80 == 0 {
                let thread = parse_thread_subrecord(body, &mut pos, thread_table)?;
                subrecords.push(ParsedFixuppSubrecord::Thread(thread));
            } else {
                // Fixup field
                if pos + 2 > body.len() {
                    return Err(Error("truncated FIXUPP locat"));
                }
                let locat = (body[pos] as u16) << 8 | (body[pos + 1] as u16);
                pos += 2;

                let is_seg_rel = (locat & omf::LOCAT_M_BIT) != 0;
                let loc_raw = ((locat & omf::LOCAT_LOC_MASK) >> omf::LOCAT_LOC_SHIFT) as u8;
                let rec_offset = (locat & omf::LOCAT_OFFSET_MASK) as u16;

                let loc = match loc_raw as u16 {
                    omf::LOC_LOADER_OFFSET => omf::LOC_OFFSET as u8,
                    other => other as u8,
                };

                if pos >= body.len() {
                    return Err(Error("truncated FIXUPP fix_dat"));
                }
                let fix_dat = body[pos];
                pos += 1;

                let mut sub_pos = pos;
                let frame = resolve_frame_from_fixdat(body, &mut sub_pos, fix_dat, thread_table)?
                    .ok_or(Error("FIXUPP frame method unsupported"))?;
                let target = resolve_target_from_fixdat(body, &mut sub_pos, fix_dat, thread_table)?
                    .ok_or(Error("FIXUPP target method unsupported"))?;

                let mut target_displacement = None;
                if (target.method & 0x04) == 0 {
                    if sub_pos + 2 > body.len() {
                        return Err(Error("truncated FIXUPP displacement"));
                    }
                    target_displacement = Some(u16::from_le_bytes([body[sub_pos], body[sub_pos + 1]]));
                    sub_pos += 2;
                }
                pos = sub_pos;

                subrecords.push(ParsedFixuppSubrecord::Fixup(ParsedFixupSubrecord {
                    record_offset: rec_offset,
                    loc_raw,
                    loc,
                    is_seg_rel,
                    fixdat: fix_dat,
                    frame_thread: frame.thread_num,
                    frame_method: frame.method,
                    frame_datum: frame.datum,
                    target_thread: target.thread_num,
                    target_method: target.method,
                    target_datum: target.datum.unwrap_or(0),
                    target_displacement,
                }));

                if loc != 4 {
                    let reloc_target = match target.method & 0x03 {
                        0 => RelocTarget::Segment(target.datum.unwrap_or(0)),
                        1 => RelocTarget::Group(target.datum.unwrap_or(0)),
                        2 => RelocTarget::External(target.datum.unwrap_or(0)),
                        _ => continue,
                    };
                    let seg_ordinal =
                        last_seg_ordinal.ok_or(Error("FIXUPP with no preceding data record"))?;
                    let seg = &mut self.segments[seg_ordinal as usize - 1];
                    seg.relocs.push(ParsedReloc {
                        offset: rec_offset,
                        loc,
                        is_seg_rel,
                        target: reloc_target,
                        displacement: target_displacement.unwrap_or(0),
                    });
                }
            }
        }

        self.fixupp_records.push(ParsedFixuppRecord {
            attached_seg_ordinal: last_seg_ordinal,
            subrecords,
        });

        Ok(())
    }

    fn parse_modend(&mut self, body: &[u8]) -> Result<()> {
        if body.is_empty() {
            return Err(Error("truncated MODEND"));
        }
        let module_type = body[0];

        if module_type & omf::MODEND_START == 0 {
            self.entry = None;
            return Ok(());
        }

        if module_type & omf::MODEND_RELOC == 0 {
            return Err(Error(
                "MODEND START bit set but RELOC bit clear; absolute start unsupported",
            ));
        }

        let mut pos = 1;
        let end_dat = *body.get(pos).read_error("truncated MODEND start address")?;
        pos += 1;

        // Spec: bit 2 (the P bit) of end_dat must be zero in MODEND.
        if end_dat & omf::FIXDAT_P_BIT != 0 {
            return Err(Error("MODEND end_dat P bit must be zero"));
        }

        let empty_threads = ThreadTable::new();
        let _frame = resolve_frame_from_fixdat(body, &mut pos, end_dat, &empty_threads)?;
        let target = resolve_target_from_fixdat(body, &mut pos, end_dat, &empty_threads)?
            .ok_or(Error("MODEND target method unsupported"))?;

        let displacement = if (target.method & 0x04) == 0 {
            if pos + 2 > body.len() {
                return Err(Error("truncated MODEND target displacement"));
            }
            let d = u16::from_le_bytes([body[pos], body[pos + 1]]);
            pos += 2;
            d
        } else {
            0
        };

        self.entry = match target.method {
            0 | 4 => Some((target.datum.unwrap_or(0), displacement)),
            1 | 5 => {
                let grp = self
                    .groups
                    .get(target.datum.unwrap_or(0) as usize - 1)
                    .ok_or(Error("MODEND group index out of range"))?;
                let seg = grp
                    .members
                    .first()
                    .copied()
                    .ok_or(Error("MODEND group has no member segments"))?;
                Some((seg, displacement))
            }
            2 | 6 => {
                return Err(Error("MODEND external start address is unsupported"));
            }
            _ => {
                return Err(Error("MODEND target method unsupported"));
            }
        };

        if pos != body.len() {
            return Err(Error("unexpected trailing bytes in MODEND"));
        }

        Ok(())
    }

    fn parse_comdef(&mut self, body: &'data [u8]) -> Result<()> {
        if !self.has_ms_ext {
            return Err(Error("COMDEF record without preceding MS extensions COMENT"));
        }
        let mut pos = 0;
        while pos < body.len() {
            let (name, c) = omf::read_name(body, pos).read_error("truncated COMDEF name")?;
            pos += c;
            let (_type_idx, c) = omf::read_index(body, pos).read_error("truncated COMDEF type")?;
            pos += c;
            if pos >= body.len() {
                return Err(Error("truncated COMDEF DST"));
            }
            let dst = body[pos];
            pos += 1;

            match dst {
                omf::DST_NEAR => {
                    let (_, c) = omf::read_varlen(body, pos).read_error("truncated COMDEF size")?;
                    pos += c;
                }
                omf::DST_FAR => {
                    let (_, c) =
                        omf::read_varlen(body, pos).read_error("truncated COMDEF num elements")?;
                    pos += c;
                    let (_, c) =
                        omf::read_varlen(body, pos).read_error("truncated COMDEF element size")?;
                    pos += c;
                }
                _ => return Err(Error("COMDEF: unknown data segment type byte")),
            }

            self.symbols.push(ParsedSymbol {
                name,
                kind: ParsedSymbolKind::Communal,
                seg_ordinal: 0,
                offset: 0,
            });
        }
        Ok(())
    }

    fn parse_coment(&mut self, body: &[u8]) -> Result<()> {
        if body.is_empty() {
            return Err(Error("truncated COMENT"));
        }
        let class = body.get(1).copied().unwrap_or(0);
        if class == omf::CC_MS_EXTENSIONS {
            self.has_ms_ext = true;
        }
        Ok(())
    }

    /// Get the symbol index for an external symbol ordinal.
    pub fn extdef_symbol_index(&self, ordinal: u16) -> Result<SymbolIndex> {
        self.extdef_symbol_indices
            .get(ordinal as usize - 1)
            .copied()
            .ok_or(Error("EXTDEF index out of range"))
    }

    pub(super) fn flat_base(&self, seg_ordinal: u16) -> u64 {
        self.segments
            .get(seg_ordinal as usize - 1)
            .map_or(0, |s| s.flat_base)
    }

    /// Get the binary format of the file.
    pub fn binary_format(&self) -> BinaryFormat {
        BinaryFormat::Omf
    }

    /// Get the decoded FIXUPP records.
    pub fn fixupp_records(&self) -> &[ParsedFixuppRecord] {
        &self.fixupp_records
    }

    /// Get the module name.
    pub fn module_name(&self) -> &'data [u8] {
        self.module_name
    }

    /// Get the list of names.
    pub fn lnames(&self) -> &[&'data [u8]] {
        &self.lnames
    }

    /// Get a name from the list of names.
    pub fn lname(&self, index: u16) -> Option<&'data [u8]> {
        self.lnames.get(index as usize).copied()
    }

    /// Get the number of external symbols.
    pub fn extdef_count(&self) -> usize {
        self.extdef_symbol_indices.len()
    }
}

fn parse_thread_subrecord(
    body: &[u8],
    pos: &mut usize,
    thread_table: &mut ThreadTable,
) -> Result<ParsedThreadSubrecord> {
    let b0 = *body.get(*pos).read_error("truncated THREAD subrecord")?;
    *pos += 1;

    let is_frame = (b0 & 0x40) != 0; // 1=FRAME, 0=TARGET
    let method = (b0 & 0x1C) >> 2;
    let thread_num = (b0 & 0x03) as u8;

    let valid = if is_frame {
        matches!(method, 0 | 1 | 2 | 4 | 5)
    } else {
        // TARGET threads store only the base target kind:
        // 0=segment, 1=group, 2=external.
        // The consuming fixup's P bit supplies the high method bit later
        // when reconstructing the effective target method.
        matches!(method, 0 | 1 | 2 | 4 | 5 | 6)
    };
    if !valid {
        return Err(Error("invalid THREAD method"));
    }

    let datum = if method <= 2 {
        let (idx, c) = omf::read_index(body, *pos).read_error("truncated THREAD datum")?;
        *pos += c;
        Some(idx)
    } else {
        None
    };

    let entry = ThreadEntry { method, datum };
    let kind = if is_frame {
        thread_table.frame[thread_num as usize] = Some(entry);
        ThreadKind::Frame
    } else {
        thread_table.target[thread_num as usize] = Some(entry);
        ThreadKind::Target
    };

    Ok(ParsedThreadSubrecord {
        kind,
        thread_number: thread_num,
        method,
        datum,
    })
}

struct ResolvedFrame {
    method: u8,
    datum: Option<u16>,
    thread_num: Option<u8>,
}

fn resolve_frame_from_fixdat(
    body: &[u8],
    pos: &mut usize,
    fixdat: u8,
    thread_table: &ThreadTable,
) -> Result<Option<ResolvedFrame>> { // Returns None for unsupported methods
    let f_bit = (fixdat & omf::FIXDAT_F_BIT) != 0;
    let frame_f = (fixdat & omf::FIXDAT_FRAME_MASK) >> omf::FIXDAT_FRAME_SHIFT;

    if !f_bit {
        let method = frame_f;
        if method == 3 {
            return Err(Error("FIXUPP explicit-frame-number frame (method 3) is unsupported"));
        }
        let datum = if method <= 2 {
            let (idx, c) = omf::read_index(body, *pos).read_error("truncated fixup frame datum")?;
            *pos += c;
            Some(idx)
        } else {
            None
        };
        Ok(Some(ResolvedFrame {
            method,
            datum,
            thread_num: None,
        }))
    } else {
        let thread_num = frame_f as u8;
        let te = thread_table.frame[thread_num as usize]
            .ok_or(Error("FIXUPP references undefined FRAME thread"))?;
        if te.method == 3 {
            return Err(Error("FIXUPP explicit-frame-number frame (method 3) is unsupported"));
        }
        if te.method <= 2 && te.datum.is_none() {
            return Err(Error("FIXUPP frame thread missing datum"));
        }
        Ok(Some(ResolvedFrame {
            method: te.method,
            datum: te.datum,
            thread_num: Some(thread_num),
        }))
    }
}

struct ResolvedTarget {
    method: u8,
    datum: Option<u16>, // Changed to Option to handle skip cases
    thread_num: Option<u8>,
}

fn resolve_target_from_fixdat(
    body: &[u8],
    pos: &mut usize,
    fixdat: u8,
    thread_table: &ThreadTable,
) -> Result<Option<ResolvedTarget>> { // Returns None for unsupported methods
    let t_bit = (fixdat & omf::FIXDAT_T_BIT) != 0;
    let p_bit = (fixdat & omf::FIXDAT_P_BIT) != 0;
    let targt = fixdat & omf::FIXDAT_TARGT_MASK;

    if !t_bit {
        let method = ((p_bit as u8) << 2) | targt;
        if matches!(method, 3 | 7) {
            return Err(Error("FIXUPP explicit-frame-number target (method 3/7) is unsupported"));
        }
        let (idx, c) = omf::read_index(body, *pos).read_error("truncated fixup target datum")?;
        *pos += c;
        Ok(Some(ResolvedTarget {
            method,
            datum: Some(idx),
            thread_num: None,
        }))
    } else {
        let thread_num = targt as u8;
        let te = thread_table.target[thread_num as usize]
            .ok_or(Error("FIXUPP references undefined TARGET thread"))?;
        let method = ((p_bit as u8) << 2) | te.method;
        if matches!(method, 3 | 7) {
            return Err(Error("FIXUPP explicit-frame-number target (method 3/7) is unsupported"));
        }
        let datum = te.datum.ok_or(Error("FIXUPP target thread missing datum"))?;
        Ok(Some(ResolvedTarget {
            method,
            datum: Some(datum),
            thread_num: Some(thread_num),
        }))
    }
}

fn expand_lidata(data: &[u8], mut pos: usize, depth: usize) -> Result<(Vec<u8>, usize)> {
    if depth > 8 {
        return Err(Error("LIDATA nesting too deep"));
    }
    if pos + 4 > data.len() {
        return Err(Error("truncated LIDATA block"));
    }

    let repeat_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let block_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let result = if block_count == 0 {
        if pos >= data.len() {
            return Err(Error("truncated LIDATA content"));
        }
        let byte_count = data[pos] as usize;
        pos += 1;
        if pos + byte_count > data.len() {
            return Err(Error("truncated LIDATA content bytes"));
        }
        let content = data[pos..pos + byte_count].to_vec();
        pos += byte_count;
        content.repeat(repeat_count)
    } else {
        let mut inner = Vec::new();
        for _ in 0..block_count {
            let (sub, consumed) = expand_lidata(data, pos, depth + 1)?;
            inner.extend_from_slice(&sub);
            pos += consumed;
        }
        inner.repeat(repeat_count)
    };

    Ok((result, pos))
}

impl<'data, R: ReadRef<'data>> read::private::Sealed for OmfFile<'data, R> {}

impl<'data, R: ReadRef<'data>> Object<'data> for OmfFile<'data, R> {
    type Segment<'file> = OmfSegment<'data, 'file, R> where Self: 'file, 'data: 'file;
    type SegmentIterator<'file> = OmfSegmentIterator<'data, 'file, R> where Self: 'file, 'data: 'file;
    type Section<'file> = OmfSection<'data, 'file, R> where Self: 'file, 'data: 'file;
    type SectionIterator<'file> = OmfSectionIterator<'data, 'file, R> where Self: 'file, 'data: 'file;
    type Comdat<'file> = OmfComdat<'data, 'file, R> where Self: 'file, 'data: 'file;
    type ComdatIterator<'file> = OmfComdatIterator<'data, 'file, R> where Self: 'file, 'data: 'file;
    type Symbol<'file> = OmfSymbol<'data, 'file, R> where Self: 'file, 'data: 'file;
    type SymbolIterator<'file> = OmfSymbolIterator<'data, 'file, R> where Self: 'file, 'data: 'file;
    type SymbolTable<'file> = OmfSymbolTable<'data, 'file, R> where Self: 'file, 'data: 'file;
    type DynamicRelocationIterator<'file> = read::NoDynamicRelocationIterator where Self: 'file, 'data: 'file;

    fn architecture(&self) -> Architecture {
        Architecture::X86_16
    }

    fn endianness(&self) -> Endianness {
        Endianness::Little
    }

    fn is_little_endian(&self) -> bool {
        true
    }

    fn is_64(&self) -> bool {
        false
    }

    fn kind(&self) -> ObjectKind {
        ObjectKind::Relocatable
    }

    fn segments(&self) -> Self::SegmentIterator<'_> {
        OmfSegmentIterator {
            file: self,
            iter: self.segments.iter().enumerate(),
        }
    }

    fn section_by_name_bytes<'file>(
        &'file self,
        section_name: &[u8],
    ) -> Option<Self::Section<'file>> {
        self.sections().find(|s| s.name_bytes() == Ok(section_name))
    }

    fn section_by_index(&self, index: SectionIndex) -> Result<Self::Section<'_>> {
        self.segments
            .get(index.0)
            .map(|seg| OmfSection {
                file: self,
                seg,
                index,
            })
            .ok_or(Error("Invalid OMF section index"))
    }

    fn sections(&self) -> Self::SectionIterator<'_> {
        OmfSectionIterator {
            file: self,
            iter: self.segments.iter().enumerate(),
        }
    }

    fn comdats(&self) -> Self::ComdatIterator<'_> {
        OmfComdatIterator {
            file: self,
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol<'_>> {
        self.symbols
            .get(index.0)
            .map(|sym| OmfSymbol {
                file: self,
                sym,
                index,
            })
            .ok_or(Error("Invalid OMF symbol index"))
    }

    fn symbols(&self) -> Self::SymbolIterator<'_> {
        OmfSymbolIterator {
            file: self,
            iter: self.symbols.iter().enumerate(),
        }
    }

    fn symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        if self.symbols.is_empty() {
            None
        } else {
            Some(OmfSymbolTable { file: self })
        }
    }

    fn dynamic_symbol_table(&self) -> Option<Self::SymbolTable<'_>> {
        None
    }

    fn dynamic_symbols(&self) -> Self::SymbolIterator<'_> {
        OmfSymbolIterator {
            file: self,
            iter: [].iter().enumerate(),
        }
    }

    fn dynamic_relocations(&self) -> Option<Self::DynamicRelocationIterator<'_>> {
        None
    }

    fn imports(&self) -> Result<Vec<read::Import<'data>>> {
        Ok(Vec::new())
    }

    fn exports(&self) -> Result<Vec<read::Export<'data>>> {
        Ok(Vec::new())
    }

    fn has_debug_symbols(&self) -> bool {
        false
    }

    fn relative_address_base(&self) -> u64 {
        0
    }

    fn entry(&self) -> u64 {
        match self.entry {
            None => 0,
            Some((seg_ord, offset)) => self.flat_base(seg_ord) + offset as u64,
        }
    }

    fn flags(&self) -> FileFlags {
        FileFlags::None
    }
}
