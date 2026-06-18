use alloc::vec::Vec;
use alloc::string::String;
use core::fmt::Debug;
use core::marker::PhantomData;

use crate::omf;
use crate::read::{
    self, Architecture, BinaryFormat, Error, FileFlags, Object, ObjectKind, ReadError, ReadRef,
    Result, SectionIndex, SymbolIndex, ObjectSection,
};
use crate::Endianness;

use super::*;

// Represents the target of a LEDATA/LIDATA record: either a segment ordinal
// (1-based) or a communal (COMDEF-derived) ordinal (EXTDEF ordinal).
#[derive(Clone, Debug)]
enum DataTarget {
    Segment(u16),
    Communal { comdef_ord: u16 },
    /// A COMDAT (0xC2/0xC3) record identified by its index in
    /// `OmfFile::comdat_records`.
    Comdat { index: usize },
    Unknown,
}

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
    /// Parsed TYPDEF records (obsolete compatibility records).
    pub typdefs: Vec<ParsedTypDefRecord<'data>>,
    /// Parsed COMDEF entries (communal variables) found in the file.
    pub comdefs: Vec<crate::read::omf::ParsedComdefEntry<'data>>,
    /// Decoded FIXUPP records for dump purposes.
    fixupp_records: Vec<ParsedFixuppRecord>,
    /// Parsed COMDAT (0xC2/0xC3) records.
    pub(super) comdat_records: Vec<super::CombatRecord>,
    pub(super) extdef_symbol_indices: Vec<SymbolIndex>,
    pub(super) entry: EntryPoint,
    /// COMDAT groups derived from COMDEF entries.
    /// Each entry is (SymbolIndex, ComdatKind).
        pub(super) comdat_groups: Vec<(SymbolIndex, crate::read::ComdatKind)>,
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
            typdefs: Vec::new(),
            comdefs: Vec::new(),
            fixupp_records: Vec::new(),
            comdat_records: Vec::new(),
            extdef_symbol_indices: Vec::new(),
            entry: EntryPoint::None,
            comdat_groups: Vec::new(),
            has_ms_ext: false,
            marker: PhantomData,
        };

        file.scan(bytes)?;
        file.finalize();

        Ok(file)
    }

    fn scan(&mut self, data: &'data [u8]) -> Result<()> {
        let mut pos = 0;
        // The most recent data record target. Previously this was tracked as
        // an ordinal assuming segment-only targets (last_data_seg_ordinal).
        // Track a richer target so FIXUPP can attach relocations either to a
        // segment or to a communal (COMDEF-derived) entry.
        let mut last_data_target: Option<DataTarget> = None;
        let mut last_data_seg_offset: u32 = 0;
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
            #[cfg(debug_assertions)]
            {
                eprintln!(
                    "RECORD @0x{:X}: type=0x{:02X} len={} (body_len={})",
                    pos,
                    record_type,
                    record_length,
                    record_length.saturating_sub(1)
                );
            }
            // Verify checksum. Mismatches are non-fatal; the verifier may
            // emit a warning but parsing continues to match historical
            // behavior and real-world files.
            let _ = Self::verify_record_checksum(record_bytes, pos, record_type);
            let record_body = &data[pos + 3..pos + 3 + record_length - 1];

            // For targeted debugging of the Watcom file: when scanning past
            // the early headers (0x3D), emit a concise per-record summary
            // after dispatch indicating whether we attempted to parse the
            // body as a Borland-style SEGDEF. This helps identify which
            // records could have contributed additional ParsedSegment
            // entries but did not.
            let is_post_0x3d = pos >= 0x3E;

            match record_type {
                omf::RT_THEADR => {
                    self.parse_theadr(record_body)?;
                    last_data_target = None;
                }
                omf::RT_LNAMES => {
                    self.parse_lnames(record_body)?;
                    last_data_target = None;
                }
                omf::RT_SEGDEF | omf::RT_SEGDEF32 => {
                    if is_post_0x3d {
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "SEGDEF @0x{:X}: will call parse_segdef; segments_before={}",
                            pos,
                            self.segments.len()
                        );
                    }
                    #[cfg(debug_assertions)]
                    {
                        use core::fmt::Write as _;
                        let mut s = String::new();
                        let preview_len = core::cmp::min(record_body.len(), 24);
                        for b in &record_body[..preview_len] {
                            write!(&mut s, "{:02X} ", b).ok();
                        }
                        if record_body.len() > preview_len {
                            write!(&mut s, "...").ok();
                        }
                        eprintln!("About to parse SEGDEF @0x{:X}: body_len={} body_preview={}", pos, record_body.len(), s);
                    }
                    let is_32 = record_type == omf::RT_SEGDEF32;
                    self.parse_segdef(record_body, is_32)?;
                    #[cfg(debug_assertions)]
                    {
                        if let Some(seg) = self.segments.last() {
                            let idx = seg.ordinal;
                            let total = self.segments.len();
                            let name_idx = if seg.name_idx == u16::MAX { None } else { Some(seg.name_idx) };
                            let class_idx = if seg.class_idx == u16::MAX { None } else { Some(seg.class_idx) };
                            eprintln!("SEGDEF parsed @0x{:X}: new_ordinal={} total_segments={} name_idx={:?} class_idx={:?} length=0x{:X}", pos, idx, total, name_idx, class_idx, seg.length);
                        } else {
                            eprintln!("SEGDEF parsed @0x{:X}: no segment recorded (unexpected)", pos);
                        }
                    }
                    last_data_target = None;
                }
                omf::RT_GRPDEF => {
                    #[cfg(debug_assertions)]
                    {
                        // Debug: preview the GRPDEF body and decoded group name index
                        use core::fmt::Write as _;
                        let mut s = String::new();
                        let preview_len = core::cmp::min(record_body.len(), 32);
                        for b in &record_body[..preview_len] {
                            write!(&mut s, "{:02X} ", b).ok();
                        }
                        if record_body.len() > preview_len {
                            write!(&mut s, "...").ok();
                        }
                        if let Some((idx, c)) = omf::read_index(record_body, 0) {
                            eprintln!(
                                "About to parse GRPDEF @0x{:X}: body_len={} name_idx_preview={} encoded_len={} body_preview={}",
                                pos,
                                record_body.len(),
                                idx,
                                c,
                                s
                            );
                        } else {
                            eprintln!(
                                "About to parse GRPDEF @0x{:X}: body_len={} name_idx_preview=<invalid> body_preview={}",
                                pos,
                                record_body.len(),
                                s
                            );
                        }
                    }
                    self.parse_grpdef(record_body)?;
                    last_data_target = None;
                }
                // Other record types fall through below; we will print a per
                // record summary after dispatch when is_post_0x3d is true.
                omf::RT_EXTDEF | omf::RT_LOCAL_EXTDEF => {
                    let is_local = record_type == omf::RT_LOCAL_EXTDEF;
                    self.parse_extdef(record_body, is_local)?;
                    last_data_target = None;
                }
                omf::RT_TYPDEF => {
                    self.parse_typdef(record_body)?;
                    last_data_target = None;
                }
                omf::RT_PUBDEF | omf::RT_PUBDEF32
                | omf::RT_LOCAL_PUBDEF | omf::RT_LOCAL_PUBDEF32 => {
                    let is_local = record_type == omf::RT_LOCAL_PUBDEF
                        || record_type == omf::RT_LOCAL_PUBDEF32;
                    let is_32 = record_type == omf::RT_PUBDEF32
                        || record_type == omf::RT_LOCAL_PUBDEF32;
                    self.parse_pubdef(record_body, is_local, is_32)?;
                    last_data_target = None;
                }
                omf::RT_LINNUM => {
                    self.parse_linnum(record_body)?;
                    last_data_target = None;
                }
                omf::RT_COMDEF => {
                    self.parse_comdef(record_body)?;
                    last_data_target = None;
                }
                omf::RT_LEDATA | omf::RT_LEDATA32 => {
                    #[cfg(debug_assertions)]
                    {
                        // Dump the raw 0xA0 record body preview before attempting
                        // to interpret it as LEDATA. This helps detect Borland
                        // variants that reuse the 0xA0 opcode but have a
                        // different body layout.
                        let preview_len = core::cmp::min(record_body.len(), 16);
                        use core::fmt::Write as _;
                        let mut s = String::new();
                        for b in &record_body[..preview_len] {
                            write!(&mut s, "{:02X} ", b).ok();
                        }
                        if record_body.len() > preview_len {
                            write!(&mut s, "...").ok();
                        }
                        eprintln!("LEDATA raw @0x{:X} body_preview={}", pos, s);
                    }
                    #[cfg(debug_assertions)]
                    {
                        // Preview the encoded segment index and computed ordinal
                        if let Some((idx, c)) = omf::read_index(record_body, 0) {
                            let enc = &record_body[..core::cmp::min(c, record_body.len())];
                            use core::fmt::Write as _;
                            let mut s = String::new();
                            for b in enc {
                                write!(&mut s, "{:02X} ", b).ok();
                            }
                            eprintln!("About to parse LEDATA @0x{:X}: encoded_index=[{}] decoded_index={}", pos, s, idx);
                        } else {
                            eprintln!("About to parse LEDATA @0x{:X}: unable to decode index preview", pos);
                        }
                    }
                    let is_32 = record_type == omf::RT_LEDATA32;
                    let (target, off) = self.parse_ledata(record_body, is_32)?;
                    last_data_target = Some(target);
                    last_data_seg_offset = off as u32;
                }
                omf::RT_LIDATA => {
                    #[cfg(debug_assertions)]
                    {
                        if let Some((idx, c)) = omf::read_index(record_body, 0) {
                            let enc = &record_body[..core::cmp::min(c, record_body.len())];
                            use core::fmt::Write as _;
                            let mut s = String::new();
                            for b in enc {
                                write!(&mut s, "{:02X} ", b).ok();
                            }
                            eprintln!("About to parse LIDATA @0x{:X}: encoded_index=[{}] decoded_index={}", pos, s, idx);
                        } else {
                            eprintln!("About to parse LIDATA @0x{:X}: unable to decode index preview", pos);
                        }
                    }
                    let (target, off) = self.parse_lidata(record_body)?;
                    last_data_target = Some(target);
                    last_data_seg_offset = off as u32;
                }
                omf::RT_FIXUPP | omf::RT_FIXUPP32 => {
                    self.parse_fixupp(
                        record_body,
                        last_data_target.clone(),
                        last_data_seg_offset,
                        &mut thread_table,
                        record_type == omf::RT_FIXUPP32,
                    )?;
                    last_data_target = None;
                }
                omf::RT_COMDAT | omf::RT_COMDAT32 => {
                    let _is_32 = record_type == omf::RT_COMDAT32;
                    let name_encoding = super::PublicNameEncoding::MicrosoftIndex;
                    let record_bytes = &data[pos..pos + 3 + record_length];
                    let comdat = super::parse_comdat(record_bytes, name_encoding)
                        .map_err(|_| Error("invalid COMDAT record"))?;
                    let comdat_index = self.comdat_records.len();
                    self.comdat_records.push(comdat);
                    last_data_target = Some(DataTarget::Comdat { index: comdat_index });
                    last_data_seg_offset = 0;
                }
                omf::RT_MODEND | omf::RT_MODEND32 => {
                    // MODEND (0x8A) and MODEND32 (0x8B) differ only in the
                    // width of the target displacement field. The record body
                    // passed here excludes the checksum byte and the leading
                    // type/length header; parse_modend will validate the body
                    // and set the module entry point appropriately.
                    let is_32 = record_type == omf::RT_MODEND32;
                    self.parse_modend(record_body, is_32)?;
                    break;
                }
                omf::RT_COMENT => {
                    #[cfg(debug_assertions)]
                    {
                        use core::fmt::Write as _;
                        let mut s = String::new();
                        let preview_len = core::cmp::min(record_body.len(), 24);
                        for b in &record_body[..preview_len] {
                            write!(&mut s, "{:02X} ", b).ok();
                        }
                        if record_body.len() > preview_len {
                            write!(&mut s, "...").ok();
                        }
                        eprintln!(
                            "COMENT @0x{:X}: body_len={} body_preview={} segments_before={}",
                            pos,
                            record_body.len(),
                            s,
                            self.segments.len()
                        );
                    }

                    // Try Borland-variant SEGDEF interpretation first. Record
                    // the segments.len() before/after to diagnose why some
                    // 0x88 records do not materialize into ParsedSegment.
                    // Borland variants always use 16-bit SEGDEF (0x98) layout.
                    let segs_before = self.segments.len();
                    let parsed_as_seg = match self.parse_segdef(record_body, false) {
                        Ok(()) => true,
                        Err(_) => false,
                    };

                    #[cfg(debug_assertions)]
                    {
                        if parsed_as_seg {
                            eprintln!(
                                "COMENT @0x{:X}: interpreted as SEGDEF (Borland variant) -> segments_after={} (+{})",
                                pos,
                                self.segments.len(),
                                self.segments.len().saturating_sub(segs_before)
                            );
                        } else {
                            eprintln!(
                                "COMENT @0x{:X}: not a SEGDEF; falling back to normal COMENT parsing; segments_after={} (no change)",
                                pos,
                                self.segments.len()
                            );
                        }
                    }

                    if !parsed_as_seg {
                        // Not a SEGDEF; parse as a normal comment.
                        self.parse_coment(record_body)?;
                    }

                    last_data_target = None;
                }
                _ => {
                    #[cfg(debug_assertions)]
                    {
                        let dump_len = record_body.len().min(16);
                        use core::fmt::Write as _;
                        let mut s = String::new();
                        for b in &record_body[..dump_len] {
                            write!(&mut s, "{:02X} ", b).ok();
                        }
                        if record_body.len() > dump_len {
                            write!(&mut s, "...").ok();
                        }
                        eprintln!(
                            "UNRECOGNIZED RECORD @0x{:X}: type=0x{:02X} len={} (branch: default) body_preview={}",
                            pos, record_type, record_body.len(), s
                        );
                    }
                    // B5H / B7H (32-bit LEXTDEF / LPUBDEF) and other unknown records
                    // are silently skipped. Most 32-bit OMF variants are out of scope
                    // for this OMF16 parser.
                    last_data_target = None;
                }
            }

            if is_post_0x3d {
                #[cfg(debug_assertions)]
                {
                    use core::fmt::Write as _;
                    let mut s = String::new();
                    let preview_len = core::cmp::min(record_body.len(), 16);
                    for b in &record_body[..preview_len] {
                        write!(&mut s, "{:02X} ", b).ok();
                    }
                    if record_body.len() > preview_len {
                        write!(&mut s, "...").ok();
                    }
                    eprintln!(
                        "POST-0x3D RECORD @0x{:X}: type=0x{:02X} len={} body_first={:?} body_preview={} segments_now={}",
                        pos,
                        record_type,
                        record_body.len(),
                        record_body.get(0).copied(),
                        s,
                        self.segments.len()
                    );
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

        // Resolution pass: build a resolved view of group members. For each
        // group member ordinal record whether the referenced segment was
        // materialized by parse time. Consumers (MODEND, FIXUPP) should use
        // this resolved_members view rather than assuming members are always
        // present.
        for grp in &mut self.groups {
            grp.resolved_members = grp
                .members
                .iter()
                .map(|&ord| {
                    if ord != 0 && (ord as usize) <= self.segments.len() {
                        Some(ord)
                    } else {
                        None
                    }
                })
                .collect();
        }
    }

    /// Verify the checksum of a single OMF record and return an optional
    /// diagnostic message when the checksum mismatches.
    fn verify_record_checksum(record_bytes: &[u8], pos: usize, record_type: u8) -> Option<&'static str> {
        // If the stored checksum byte is 0x00, interpret that as "checksum
        // omitted" and accept the record unconditionally (some toolchains do
        // not emit a checksum). Otherwise verify that the sum of all bytes is
        // zero modulo 256; mismatches are reported non-fatally.
        if let Some(&stored) = record_bytes.last() {
            if stored == 0x00 {
                return None;
            }
        }

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
            Some("OMF checksum mismatch")
        } else {
            None
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

    fn parse_segdef(&mut self, body: &'data [u8], is_32bit: bool) -> Result<()> {
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

        let length = if is_32bit {
            if pos + 4 > body.len() {
                return Err(Error("truncated SEGDEF32 length"));
            }
            let l = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
            pos += 4;
            if b_bit && l != 0 {
                return Err(Error("SEGDEF32 B bit set but length field non-zero"));
            }
            l
        } else {
            if pos + 2 > body.len() {
                return Err(Error("truncated SEGDEF length"));
            }
            let l = u16::from_le_bytes([body[pos], body[pos + 1]]) as u32;
            pos += 2;
            if b_bit && l != 0 {
                return Err(Error("SEGDEF B bit set but length field non-zero"));
            }
            l
        };

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
            omf::ALIGN_DWORD => 4,
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

        #[cfg(debug_assertions)]
        {
            // Debug: report the new segment count and ordinal after a
            // SEGDEF is parsed. This helps detect whether later LEDATA/LIDATA
            // records refer to the expected segment ordinals.
            eprintln!(
                "SEGDEF parsed: total_segments={} new_ordinal={} name_idx={:?} class_idx={:?}",
                self.segments.len(),
                ordinal,
                if seg_name_idx == 0 { None } else { Some(seg_name_idx - 1) },
                if class_name_idx == 0 { None } else { Some(class_name_idx - 1) }
            );
        }

        Ok(())
    }

    /// Heuristic-only probe to check whether `body` could be a SEGDEF
    /// without mutating parser state. Returns Ok(()) when the body has the
    /// minimal structural shape of a SEGDEF; Err(reason) when truncated or
    /// clearly not a SEGDEF. This is used only for debug diagnostics.
    fn parse_grpdef(&mut self, body: &'data [u8]) -> Result<()> {
        let (name_idx, mut pos) = omf::read_index(body, 0).read_error("truncated GRPDEF name")?;

        if name_idx == 0 || name_idx as usize > self.lnames.len() {
            return Err(Error("GRPDEF name index out of range"));
        }
        let mut members = Vec::new();
        let mut unresolved = Vec::new();
        let mut components = Vec::new();

        while pos < body.len() {
            let component_type = *body.get(pos).read_error("truncated GRPDEF component type")?;
            pos += 1;

            match component_type {
                0xFF => {
                    let (seg_idx, c) = omf::read_index(body, pos)
                        .read_error("truncated GRPDEF segment component")?;
                    pos += c;

                    if seg_idx == 0 {
                        // Zero is not a valid segment ordinal; record as unresolved
                        // but do not fail the entire parse.
                        #[cfg(debug_assertions)]
                        eprintln!("GRPDEF: segment reference 0 at cursor {} (ignored)", pos - c);
                        unresolved.push(seg_idx);
                    } else if seg_idx as usize > self.segments.len() {
                        // Not yet materialized: record the ordinal but don't fail.
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "GRPDEF: unresolved segment ordinal {} at cursor {} (available={})",
                            seg_idx,
                            pos - c,
                            self.segments.len()
                        );
                        members.push(seg_idx);
                        unresolved.push(seg_idx);
                        components.push(crate::read::omf::ParsedGroupComponent::Segment { seg_index: seg_idx });
                    } else {
                        members.push(seg_idx);
                        components.push(crate::read::omf::ParsedGroupComponent::Segment { seg_index: seg_idx });
                    }
                }

                0xFE => {
                    let (ext_idx, c) = omf::read_index(body, pos)
                        .read_error("truncated GRPDEF external component")?;
                    pos += c;
                    components.push(crate::read::omf::ParsedGroupComponent::External { ext_index: ext_idx });
                }

                0xFD => {
                    let (seg_name_index, c1) = omf::read_index(body, pos)
                        .read_error("truncated GRPDEF name-triple seg name")?;
                    pos += c1;
                    let (class_name_index, c2) = omf::read_index(body, pos)
                        .read_error("truncated GRPDEF name-triple class name")?;
                    pos += c2;
                    let (overlay_name_index, c3) = omf::read_index(body, pos)
                        .read_error("truncated GRPDEF name-triple overlay name")?;
                    pos += c3;

                    components.push(crate::read::omf::ParsedGroupComponent::NameTriple {
                        seg_name_index,
                        class_name_index,
                        overlay_name_index,
                    });
                }

                0xFB => {
                    if pos + 5 > body.len() {
                        return Err(Error("truncated GRPDEF LTL component"));
                    }

                    let ltl_data = body[pos];
                    let max_group_length = u16::from_le_bytes([body[pos + 1], body[pos + 2]]);
                    let group_length = u16::from_le_bytes([body[pos + 3], body[pos + 4]]);
                    pos += 5;

                    components.push(crate::read::omf::ParsedGroupComponent::Ltl {
                        ltl_data,
                        max_group_length,
                        group_length,
                    });
                }

                0xFA => {
                    if pos + 4 > body.len() {
                        return Err(Error("truncated GRPDEF absolute-frame component"));
                    }

                    let frame_number = u16::from_le_bytes([body[pos], body[pos + 1]]);
                    let offset = u16::from_le_bytes([body[pos + 2], body[pos + 3]]);
                    pos += 4;

                    components.push(crate::read::omf::ParsedGroupComponent::AbsoluteFrame {
                        frame_number,
                        offset,
                    });
                }

                _ => {
                    #[cfg(debug_assertions)]
                    {
                        eprintln!(
                            "GRPDEF: unsupported component type 0x{:02X} at cursor {} (body_len={})",
                            component_type,
                            pos - 1,
                            body.len()
                        );
                    }
                    return Err(Error("unsupported GRPDEF component type"));
                }
            }
        }

        if self.groups.len() >= 31 {
            return Err(Error("GRPDEF count exceeds LINK limit of 31"));
        }

        self.groups.push(ParsedGroup {
            name_idx: name_idx - 1,
            members,
            unresolved,
            components,
            resolved_members: Vec::new(),
        });

        Ok(())
    }

    fn parse_extdef(&mut self, body: &'data [u8], is_local: bool) -> Result<()> {
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
                kind: if is_local {
                    ParsedSymbolKind::LocalExternal
                } else {
                    ParsedSymbolKind::External
                },
                seg_ordinal: 0,
                offset: 0,
            });
            self.extdef_symbol_indices.push(sym_index);
        }

        Ok(())
    }

    fn parse_typdef(&mut self, body: &'data [u8]) -> Result<()> {
        let mut pos = 0;

        // Old OMF TYPDEF format: a single null name byte followed by a
        // sequence of leaf descriptors. For compatibility we accept a
        // zero-length count-prefix (0x00) as the name, but continue to parse
        // leafs like the original implementation.
        if pos >= body.len() {
            return Err(Error("truncated TYPDEF body"));
        }

        // The historical parser used a single null byte for the name. Newer
        // toolings sometimes use count-prefixed names; accept both by peeking
        // at the first byte. If it's zero, treat it as an empty name and
        // advance by 1 (legacy); otherwise treat it as a count-prefixed
        // name.
        let (name, consumed) = if body[pos] == 0 {
            (&body[pos + 1..pos + 1], 1)
        } else {
            omf::read_name(body, pos).read_error("truncated TYPDEF name")?
        };
        pos += consumed;

        // EN field is optional in older encodings; if present (enforced by
        // length) read it, otherwise default to 0.
        let en = if pos < body.len() { *body.get(pos).unwrap() } else { 0 };
        if pos < body.len() {
            pos += 1;
        }

        // Parse leaf descriptors until the end of the record. We preserve
        // unknown leaf tags by storing opaque remainder when we cannot
        // interpret a leaf; this mirrors the previous tolerant behavior.
        let mut descriptor: Option<ParsedTypDefDescriptor<'data>> = None;
        while pos < body.len() {
            let tag = body[pos];
            pos += 1;

            match tag {
                0x62 => {
                    // NEAR variable: 62H variable_type length_in_bits
                    let variable_type = *body.get(pos).read_error("truncated TYPDEF NEAR variable type")?;
                    pos += 1;
                    let (length_bits, c) = omf::read_varlen(body, pos)
                        .read_error("truncated TYPDEF length_in_bits")?;
                    pos += c;
                    descriptor = Some(ParsedTypDefDescriptor::Near { variable_type, length_bits });
                }
                0x61 => {
                    // FAR variable: 61H variable_type number_of_elements element_type_index
                    let _variable_type = *body.get(pos).read_error("truncated TYPDEF FAR variable type")?;
                    pos += 1;
                    let (number_of_elements, c) = omf::read_varlen(body, pos)
                        .read_error("truncated TYPDEF number_of_elements")?;
                    pos += c;
                    let (element_type_index, c) = omf::read_index(body, pos)
                        .read_error("truncated TYPDEF element_type_index")?;
                    pos += c;

                    // Validate referenced index if present in already-parsed typdefs.
                    if element_type_index != 0 && element_type_index as usize <= self.typdefs.len() {
                        let referenced = &self.typdefs[element_type_index as usize - 1];
                        match &referenced.descriptor {
                            ParsedTypDefDescriptor::Near { .. } => {}
                            _ => {
                                // Keep tolerant: do not fail hard; just record opaque.
                                descriptor = Some(ParsedTypDefDescriptor::Opaque(&[]));
                                continue;
                            }
                        }
                    }

                    descriptor = Some(ParsedTypDefDescriptor::Far { element_count: number_of_elements, element_type_index });
                }
                // Unknown leaf tag: store remaining bytes as opaque and stop.
                _ => {
                    descriptor = Some(ParsedTypDefDescriptor::Opaque(&body[pos - 1..]));
                    break;
                }
            }
        }

        let descriptor = descriptor.unwrap_or(ParsedTypDefDescriptor::Opaque(&[]));

        self.typdefs.push(ParsedTypDefRecord { name, en, descriptor });

        Ok(())
    }

    fn parse_pubdef(&mut self, body: &'data [u8], is_local: bool, is_32: bool) -> Result<()> {
        let mut pos = 0;
        let (_group_idx, c) = omf::read_index(body, pos).read_error("truncated PUBDEF group")?;
        pos += c;
        let (seg_idx, c) = omf::read_index(body, pos).read_error("truncated PUBDEF segment")?;
        pos += c;

        // Base Frame is present when Base Segment Index = 0 (regardless of group)
        if seg_idx == 0 {
            if pos + 2 > body.len() {
                return Err(Error("truncated PUBDEF frame"));
            }
            // _frame
            pos += 2;
        }

        while pos < body.len() {
            let (name, c) = omf::read_name(body, pos).read_error("truncated PUBDEF name")?;
            pos += c;
            let pub_offset = if is_32 {
                if pos + 4 > body.len() {
                    return Err(Error("truncated PUBDEF32 offset"));
                }
                let off = u32::from_le_bytes([body[pos], body[pos + 1], body[pos + 2], body[pos + 3]]);
                pos += 4;
                off
            } else {
                if pos + 2 > body.len() {
                    return Err(Error("truncated PUBDEF offset"));
                }
                u16::from_le_bytes([body[pos], body[pos + 1]]) as u32
            };
            if !is_32 {
                pos += 2;
            }
            let (_type_idx, c) = omf::read_index(body, pos).read_error("truncated PUBDEF type")?;
            pos += c;

            if is_local && self.extdef_symbol_indices.len() >= 1023 {
                return Err(Error("EXTDEF count exceeds LINK limit of 1023"));
            }

            let sym_index = SymbolIndex(self.symbols.len());
            self.symbols.push(ParsedSymbol {
                name,
                kind: if is_local {
                    ParsedSymbolKind::LocalPublic
                } else {
                    ParsedSymbolKind::Public
                },
                seg_ordinal: seg_idx,
                offset: pub_offset,
            });

            if is_local {
                self.extdef_symbol_indices.push(sym_index);
            }
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

    fn parse_ledata(&mut self, body: &[u8], is_32bit: bool) -> Result<(DataTarget, u32)> {
        let (seg_idx, c) = omf::read_index(body, 0).read_error("truncated LEDATA segment")?;

        let data_offset = if is_32bit {
            if c + 4 > body.len() {
                return Err(Error("truncated LEDATA32 offset"));
            }
            let off = u32::from_le_bytes([body[c], body[c + 1], body[c + 2], body[c + 3]]) as usize;
            off
        } else {
            if c + 2 > body.len() {
                return Err(Error("truncated LEDATA offset"));
            }
            u16::from_le_bytes([body[c], body[c + 1]]) as usize
        };
        let offset_field_bytes: usize = if is_32bit { 4 } else { 2 };
        let data_bytes = &body[c + offset_field_bytes..];

        // Spec limit: data field max 1024 bytes.
        if data_bytes.len() > 1024 {
            return Err(Error("LEDATA data field exceeds 1024-byte LINK limit"));
        }

        let available_segments = self.segments.len();
        let required = data_offset + data_bytes.len();

        #[cfg(debug_assertions)]
        {
            eprintln!(
                "LEDATA: targeting seg_idx={} (available_segments={}) data_offset={} data_len={} required={}",
                seg_idx,
                available_segments,
                data_offset,
                data_bytes.len(),
                required
            );
        }

        // Classify the decoded index into a target kind before acting.
        let mut target = self.classify_data_target(seg_idx);

        // Some toolchains (notably Borland) set extra high bits in the
        // two-byte index encoding. If the nominal decoded index does not
        // resolve, attempt a relaxed re-decode for two-byte encodings by
        // clearing the bit-6 marker and also try the low byte alone. Do
        // this only when the initial classification yields Unknown so we
        // avoid changing behavior for well-formed files.
        if let DataTarget::Unknown = target {
            if c == 2 {
                if let Some(&b0) = body.get(0) {
                    if let Some(&b1) = body.get(1) {
                        // Clear bit 6 (0x40) from the high-order 7 bits and
                        // reassemble. For C0 01 this yields ordinal 1.
                        let alt1 = ((((b0 & 0x7F) & !0x40) as u16) << 8) | (b1 as u16);
                        let t1 = self.classify_data_target(alt1);
                        if !matches!(t1, DataTarget::Unknown) {
                            target = t1;
                        } else {
                            // Try low byte only.
                            let alt2 = b1 as u16;
                            let t2 = self.classify_data_target(alt2);
                            if !matches!(t2, DataTarget::Unknown) {
                                target = t2;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(debug_assertions)]
        {
            use core::fmt::Write as _;
            let mut extra = String::new();
            match &target {
                DataTarget::Segment(o) => {
                    if let Some(seg) = self.segments.get(*o as usize - 1) {
                        if seg.name_idx != u16::MAX {
                            if let Some(n) = self.lname(seg.name_idx) {
                                write!(&mut extra, "target=segment ordinal={} name=", o).ok();
                                for &b in n {
                                    write!(&mut extra, "{:02X}", b).ok();
                                }
                            } else {
                                write!(&mut extra, "target=segment ordinal={} name=<invalid>", o).ok();
                            }
                        } else {
                            write!(&mut extra, "target=segment ordinal={} (unnamed)", o).ok();
                        }
                    } else {
                        write!(&mut extra, "target=segment ordinal={} (missing)", o).ok();
                    }
                }
                DataTarget::Communal { comdef_ord } => {
                    write!(&mut extra, "target=communal ordinal(extdef)={}", comdef_ord).ok();
                }
                DataTarget::Comdat { index } => {
                    write!(&mut extra, "target=COMDAT index={}", index).ok();
                }
                DataTarget::Unknown => {
                    write!(&mut extra, "target=unknown idx={}", seg_idx).ok();
                }
            }
            eprintln!(
                "LEDATA debug: {} data_offset={} data_len={} required={}",
                extra, data_offset, data_bytes.len(), required
            );
        }

        // Branch on the classified target and perform the write.
        match target {
            DataTarget::Segment(ord) => {
                if ord == 0 || (ord as usize) > self.segments.len() {
                    return Err(Error("LEDATA segment index out of range"));
                }
                let seg = &mut self.segments[ord as usize - 1];
                if required > 0x10000 {
                    return Err(Error("LEDATA data overflow: exceeds 64 KB segment limit"));
                }
                if seg.data.len() < required {
                    seg.data.resize(required, 0);
                }
                seg.data[data_offset..required].copy_from_slice(data_bytes);
                return Ok((DataTarget::Segment(ord), data_offset as u32));
            }
            DataTarget::Communal { comdef_ord } => {
                // communal target: write into the comdef buffer
                let ordinal = comdef_ord;
                if ordinal == 0 || (ordinal as usize) > self.extdef_symbol_indices.len() {
                    return Err(Error("LEDATA segment index out of range"));
                }
                let sym_index = self.extdef_symbol_indices[ordinal as usize - 1];
                if let Some((comdat_pos, _)) = self
                    .comdat_groups
                    .iter()
                    .enumerate()
                    .find(|(_i, (sidx, _))| *sidx == sym_index)
                {
                    if comdat_pos < self.comdefs.len() {
                        let comdef = &mut self.comdefs[comdat_pos];
                        let req = data_offset + data_bytes.len();
                        if comdef.data.len() < req {
                            comdef.data.resize(req, 0);
                        }
                        comdef.data[data_offset..req].copy_from_slice(data_bytes);
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "LEDATA -> COMDEF: comdef_idx={} sym_index={} data_offset={} data_len={} required={}",
                            comdat_pos + 1,
                            sym_index.0,
                            data_offset,
                            data_bytes.len(),
                            req
                        );
                        return Ok((DataTarget::Communal { comdef_ord: ordinal }, data_offset as u32));
                    }
                }
                return Err(Error("LEDATA segment index out of range"));
            }
            DataTarget::Comdat { .. } => {
                return Err(Error("LEDATA cannot target COMDAT records"));
            }
            DataTarget::Unknown => return Err(Error("LEDATA segment index out of range")),
        }
    }

    fn parse_lidata(&mut self, body: &[u8]) -> Result<(DataTarget, u32)> {
        let (seg_idx, c) = omf::read_index(body, 0).read_error("truncated LIDATA segment")?;
        // Allow seg_idx==0 to be handled by resolution logic below; do not
        // early-return here so communal (COMDEF) mapping can be attempted.

        if c + 2 > body.len() {
            return Err(Error("truncated LIDATA offset"));
        }
        let data_offset = u16::from_le_bytes([body[c], body[c + 1]]) as usize;
        let block_data = &body[c + 2..];

        // Spec limit: an iterated data block max 512 bytes.
        if block_data.len() > 512 {
            return Err(Error("LIDATA iterated data block exceeds 512-byte LINK limit"));
        }

        let (expanded, consumed) = expand_lidata(block_data, 0, 0)?;
        if consumed != block_data.len() {
            return Err(Error("unexpected trailing bytes in LIDATA"));
        }

        let available_segments = self.segments.len();

        #[cfg(debug_assertions)]
        {
            eprintln!(
                "LIDATA: targeting seg_idx={} (available_segments={}) data_offset={} expanded_len={}",
                seg_idx,
                available_segments,
                data_offset,
                expanded.len()
            );
        }

        // Classify the decoded index into a target kind before acting.
        let target = self.classify_data_target(seg_idx);

        #[cfg(debug_assertions)]
        {
            use core::fmt::Write as _;
            let mut extra = String::new();
            match &target {
                DataTarget::Segment(o) => {
                    if let Some(seg) = self.segments.get(*o as usize - 1) {
                        if seg.name_idx != u16::MAX {
                            if let Some(n) = self.lname(seg.name_idx) {
                                write!(&mut extra, "target=segment ordinal={} name=", o).ok();
                                for &b in n {
                                    write!(&mut extra, "{:02X}", b).ok();
                                }
                            } else {
                                write!(&mut extra, "target=segment ordinal={} name=<invalid>", o).ok();
                            }
                        } else {
                            write!(&mut extra, "target=segment ordinal={} (unnamed)", o).ok();
                        }
                    } else {
                        write!(&mut extra, "target=segment ordinal={} (missing)", o).ok();
                    }
                }
                DataTarget::Communal { comdef_ord } => {
                    write!(&mut extra, "target=communal ordinal(extdef)={}", comdef_ord).ok();
                }
                DataTarget::Comdat { index } => {
                    write!(&mut extra, "target=COMDAT index={}", index).ok();
                }
                DataTarget::Unknown => {
                    write!(&mut extra, "target=unknown idx={}", seg_idx).ok();
                }
            }
            eprintln!(
                "LIDATA debug: {} data_offset={} expanded_len={}",
                extra, data_offset, expanded.len()
            );
        }

        // Normal segment target: store into segment's data buffer.
        match target {
            DataTarget::Segment(ord) => {
                if ord == 0 || (ord as usize) > self.segments.len() {
                    return Err(Error("LIDATA segment index out of range"));
                }
                let seg = &mut self.segments[ord as usize - 1];
                let required = data_offset + expanded.len();
                if required > 0x10000 {
                    return Err(Error("LIDATA data overflow"));
                }
                if seg.data.len() < required {
                    seg.data.resize(required, 0);
                }
                seg.data[data_offset..required].copy_from_slice(&expanded);
                return Ok((DataTarget::Segment(ord), data_offset as u32));
            }
            DataTarget::Communal { comdef_ord } => {
                let ordinal = comdef_ord;
                if ordinal == 0 || (ordinal as usize) > self.extdef_symbol_indices.len() {
                    return Err(Error("LIDATA segment index out of range"));
                }
                let sym_index = self.extdef_symbol_indices[ordinal as usize - 1];
                if let Some((comdat_pos, _)) = self
                    .comdat_groups
                    .iter()
                    .enumerate()
                    .find(|(_i, (sidx, _))| *sidx == sym_index)
                {
                    if comdat_pos < self.comdefs.len() {
                        let comdef = &mut self.comdefs[comdat_pos];
                        let req = data_offset + expanded.len();
                        if comdef.data.len() < req {
                            comdef.data.resize(req, 0);
                        }
                        comdef.data[data_offset..req].copy_from_slice(&expanded);
                        #[cfg(debug_assertions)]
                        eprintln!(
                            "LIDATA -> COMDEF: comdef_idx={} sym_index={} data_offset={} expanded_len={} required={}",
                            comdat_pos + 1,
                            sym_index.0,
                            data_offset,
                            expanded.len(),
                            req
                        );
                        return Ok((DataTarget::Communal { comdef_ord: ordinal }, data_offset as u32));
                    }
                }
                return Err(Error("LIDATA segment index out of range"));
            }
            DataTarget::Comdat { .. } => {
                return Err(Error("LIDATA cannot target COMDAT records"));
            }
            DataTarget::Unknown => return Err(Error("LIDATA segment index out of range")),
        }
    }

    fn parse_fixupp(
        &mut self,
        body: &[u8],
        last_data_target: Option<DataTarget>,
        ledata_offset: u32,
        thread_table: &mut ThreadTable,
        is_32bit: bool,
    ) -> Result<()> {
        let mut pos = 0;
        let mut subrecords = Vec::new();
        // Snapshot the thread table as it exists at the start of this
        // FIXUPP record. This preserves the provenance of THREAD subrecords
        // and allows dumps to show the threads that were active when the
        // record began (previous behavior saved the pre-record state).
        let start_thread_table = *thread_table;

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
                    omf::LOC_LOADER_OFFSET32 => omf::LOC_OFFSET32 as u8,
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
                    if is_32bit {
                        if sub_pos + 4 > body.len() {
                            return Err(Error("truncated FIXUPP32 displacement"));
                        }
                        target_displacement = Some(u32::from_le_bytes([
                            body[sub_pos],
                            body[sub_pos + 1],
                            body[sub_pos + 2],
                            body[sub_pos + 3],
                        ]));
                        sub_pos += 4;
                    } else {
                        if sub_pos + 2 > body.len() {
                            return Err(Error("truncated FIXUPP displacement"));
                        }
                        target_displacement = Some(u16::from_le_bytes([body[sub_pos], body[sub_pos + 1]]) as u32);
                        sub_pos += 2;
                    }
                }
                pos = sub_pos;

                let full_offset = ledata_offset + rec_offset as u32;

                subrecords.push(ParsedFixuppSubrecord::Fixup(ParsedFixupSubrecord {
                    record_offset: full_offset,
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

                {
                    let reloc_target = match target.method & 0x03 {
                        0 => RelocTarget::Segment(target.datum.unwrap_or(0)),
                        1 => RelocTarget::Group(target.datum.unwrap_or(0)),
                        2 => RelocTarget::External(target.datum.unwrap_or(0)),
                        3 => RelocTarget::AbsoluteFrame(target.datum.unwrap_or(0)),
                        _ => continue,
                    };
                    let data_target = last_data_target
                        .as_ref()
                        .ok_or(Error("FIXUPP with no preceding data record"))?;

                    match data_target {
                        DataTarget::Segment(seg_ordinal) => {
                            if *seg_ordinal == 0 || (*seg_ordinal as usize) > self.segments.len() {
                                return Err(Error("FIXUPP segment index out of range"));
                            }
                            let seg = &mut self.segments[*seg_ordinal as usize - 1];
                            seg.relocs.push(ParsedReloc {
                                offset: full_offset,
                                loc,
                                is_seg_rel,
                                target: reloc_target.clone(),
                                displacement: target_displacement.unwrap_or(0),
                            });
                        }
                        DataTarget::Communal { comdef_ord } => {
                            // communal target: map extdef ordinal -> symbol index -> comdat_groups pos -> comdefs index
                            let ordinal = *comdef_ord;
                            if ordinal == 0 || (ordinal as usize) > self.extdef_symbol_indices.len() {
                                return Err(Error("FIXUPP refers to unknown COMDEF ordinal"));
                            }
                            let sym_index = self.extdef_symbol_indices[ordinal as usize - 1];
                            if let Some((comdat_pos, _)) = self
                                .comdat_groups
                                .iter()
                                .enumerate()
                                .find(|(_i, (sidx, _))| *sidx == sym_index)
                            {
                                if comdat_pos < self.comdefs.len() {
                                    let comdef = &mut self.comdefs[comdat_pos];
                                    comdef.relocs.push(ParsedReloc {
                                        offset: full_offset,
                                        loc,
                                        is_seg_rel,
                                        target: reloc_target.clone(),
                                        displacement: target_displacement.unwrap_or(0),
                                    });
                                    #[cfg(debug_assertions)]
                                    eprintln!(
                                        "FIXUPP -> COMDEF: comdef_idx={} sym_index={} offset={} loc={} target={:?}",
                                        comdat_pos + 1,
                                        sym_index.0,
                                        full_offset,
                                        loc,
                                        reloc_target
                                    );
                                } else {
                                    return Err(Error("FIXUPP refers to unknown COMDEF ordinal"));
                                }
                            } else {
                                return Err(Error("FIXUPP refers to unknown COMDEF symbol"));
                            }
                        }
                        DataTarget::Comdat { index } => {
                            if *index >= self.comdat_records.len() {
                                return Err(Error("FIXUPP refers to unknown COMDAT record"));
                            }
                            let comdat = &mut self.comdat_records[*index];
                            comdat.relocs.push(ParsedReloc {
                                offset: full_offset,
                                loc,
                                is_seg_rel,
                                target: reloc_target.clone(),
                                displacement: target_displacement.unwrap_or(0),
                            });
                        }
                        &DataTarget::Unknown => return Err(Error("FIXUPP segment index out of range")),
                    }
                }
            }
        }

        let attached_seg_ordinal = last_data_target.as_ref().and_then(|t| match t {
            DataTarget::Segment(o) => Some(*o),
            DataTarget::Comdat { index } => {
                #[cfg(debug_assertions)]
                eprintln!("FIXUPP attached to COMDAT record {}", index);
                None
            }
            _ => None,
        });

        self.fixupp_records.push(ParsedFixuppRecord {
            attached_seg_ordinal,
            subrecords,
            thread_table: start_thread_table,
        });

        Ok(())
    }

    fn parse_modend(&mut self, body: &[u8], is_32bit: bool) -> Result<()> {
        if body.is_empty() {
            return Err(Error("truncated MODEND"));
        }
        let module_type = body[0];

        // No start address -> module has no entry point.
        if module_type & omf::MODEND_START == 0 {
            self.entry = EntryPoint::None;
            return Ok(());
        }

        // When Start is set the RELOC (X) bit must typically be present; our
        // parser treats the absence as unsupported.
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

        // Parse frame/target using helpers used by FIXUPP parsing. The
        // ThreadTable is empty here because MODEND start address uses the
        // fixed end_dat rather than referencing existing thread state.
        let empty_threads = ThreadTable::new();
        let _frame = resolve_frame_from_fixdat(body, &mut pos, end_dat, &empty_threads)?;
        let target = resolve_target_from_fixdat(body, &mut pos, end_dat, &empty_threads)?
            .ok_or(Error("MODEND target method unsupported"))?;

        let displacement = if (target.method & 0x04) == 0 {
            if is_32bit {
                if pos + 4 > body.len() {
                    return Err(Error("truncated MODEND32 target displacement"));
                }
                let d = u32::from_le_bytes([
                    body[pos],
                    body[pos + 1],
                    body[pos + 2],
                    body[pos + 3],
                ]);
                pos += 4;
                // clamp into u32; stored EntryPoint uses u32 for displacement
                d as u64
            } else {
                if pos + 2 > body.len() {
                    return Err(Error("truncated MODEND target displacement"));
                }
                let d = u16::from_le_bytes([body[pos], body[pos + 1]]) as u64;
                pos += 2;
                d
            }
        } else {
            0
        } as u64;

        // Map to existing EntryPoint enum which stores a 32-bit displacement
        // when appropriate. We preserve the datum values (EXTDEF/SEG/GROUP)
        // semantics used elsewhere in the parser.
        self.entry = match target.method {
            0 | 4 => EntryPoint::Segment(target.datum.unwrap_or(0), displacement as u32),
                1 | 5 => {
                let grp = self
                    .groups
                    .get(target.datum.unwrap_or(0) as usize - 1)
                    .ok_or(Error("MODEND group index out of range"))?;
                // Prefer the resolved_members view populated during finalize().
                // If the resolved view is absent or the first member is None,
                // conservatively treat the module as having no entry point
                // rather than inventing an address from an unresolved ordinal.
                if grp.resolved_members.is_empty() {
                    return Err(Error("MODEND group resolution not available"));
                }
                match grp.resolved_members.first().copied().flatten() {
                    Some(seg) => EntryPoint::Segment(seg, displacement as u32),
                    None => {
                        #[cfg(debug_assertions)]
                        eprintln!("MODEND: group {} first member unresolved; returning no entry", target.datum.unwrap_or(0));
                        EntryPoint::None
                    }
                }
            }
            2 | 6 => {
                EntryPoint::External(target.datum.unwrap_or(0), displacement as u32)
            }
            _ => return Err(Error("MODEND target method unsupported")),
        };

        if pos != body.len() {
            return Err(Error("unexpected trailing bytes in MODEND"));
        }

        Ok(())
    }

    fn parse_comdef(&mut self, body: &'data [u8]) -> Result<()> {
        let mut pos = 0;
        #[cfg(debug_assertions)]
        {
            // Targeted debug dump for COMDEF records. Prints the overall
            // record body length and a short hex preview to help diagnose
            // parser cursor drift when Borland variants or extensions are
            // present. Only enabled in debug builds to avoid noisy output in
            // normal use.
            use core::fmt::Write as _;
            let mut s = String::new();
            let preview_len = core::cmp::min(body.len(), 32);
            for b in &body[..preview_len] {
                write!(&mut s, "{:02X} ", b).ok();
            }
            if body.len() > preview_len {
                write!(&mut s, "... (len={})", body.len()).ok();
            } else {
                write!(&mut s, "(len={})", body.len()).ok();
            }
            eprintln!("COMDEF record: {}", s);
        }
        while pos < body.len() {
            let (name, c) = omf::read_name(body, pos).read_error("truncated COMDEF name")?;
            pos += c;
            let (type_idx, c) = omf::read_index(body, pos).read_error("truncated COMDEF type")?;
            pos += c;
            if pos >= body.len() {
                return Err(Error("truncated COMDEF DST"));
            }
            let dst = body[pos];
            pos += 1;

            // Pre-read any variable-length fields so we advance `pos` in the
            // same way the historical parser did and then construct the
            // ParsedCommunalKind from the captured values. This avoids
            // double-reading varlen fields.
            let mut near_size: Option<u32> = None;
            let mut far_count: Option<u32> = None;
            let mut far_elem_size: Option<u32> = None;

            match dst {
                omf::DST_NEAR => {
                    let (size, c) = omf::read_varlen(body, pos).read_error("truncated COMDEF size")?;
                    pos += c;
                    near_size = Some(size);
                }
                omf::DST_FAR => {
                    let (count, c) = omf::read_varlen(body, pos)
                        .read_error("truncated COMDEF num elements")?;
                    pos += c;
                    far_count = Some(count);
                    let (element_size, c) = omf::read_varlen(body, pos)
                        .read_error("truncated COMDEF element size")?;
                    pos += c;
                    far_elem_size = Some(element_size);
                }
                0x01..=0x5F => {
                    // Borland segment variant: historically some Borland toolchains
                    // emit an extra payload byte after the segment index. If we
                    // don't consume it the parser's cursor can drift one byte
                    // past the end of the COMDEF record, leaving an extra
                    // dangling byte. Consume one additional byte when present
                    // to remain compatible with these variants.
                    if pos < body.len() {
                        #[cfg(debug_assertions)]
                        {
                            // Debug: print the next few bytes to help diagnose
                            // exactly what the Borland payload looks like.
                            let remaining = body.len().saturating_sub(pos);
                            let mut preview = String::new();
                            let preview_len = core::cmp::min(remaining, 8);
                            for b in &body[pos..pos + preview_len] {
                                use core::fmt::Write as _;
                                write!(&mut preview, "{:02X} ", b).ok();
                            }
                            eprintln!(
                                "    Borland DST: consuming extra byte 0x{:02X}; remaining={} next={}",
                                body[pos],
                                remaining,
                                preview
                            );
                        }
                        // Consume the extra Borland payload byte to align the
                        // parser cursor with the recorded COMDEF boundary.
                        pos += 1;
                    }
                }
                _ => {
                    // Unknown DST — stop parsing this COMDEF record to avoid
                    // misinterpreting remaining bytes.
                    break;
                }
            }

            // Record the parsed COMDEF entry in the structured list.
            let communal = match dst {
                omf::DST_NEAR => crate::read::omf::ParsedCommunalKind::Near { size: near_size.unwrap_or(0) },
                omf::DST_FAR => crate::read::omf::ParsedCommunalKind::Far {
                    count: far_count.unwrap_or(0),
                    element_size: far_elem_size.unwrap_or(0),
                },
                0x01..=0x5F => crate::read::omf::ParsedCommunalKind::BorlandSegment { index: dst },
                _ => crate::read::omf::ParsedCommunalKind::Opaque(&body[pos..]),
            };

            self.comdefs.push(crate::read::omf::ParsedComdefEntry { name, type_index: type_idx, communal, data: Vec::new(), relocs: Vec::new() });

            // Preserve historical side effects: create a symbolic entry so
            // COMDEF variables are visible via symbols/comdat groups.
            let sym_index = SymbolIndex(self.symbols.len());
            self.symbols.push(ParsedSymbol {
                name,
                kind: ParsedSymbolKind::Communal,
                seg_ordinal: 0,
                offset: 0,
            });

            if self.extdef_symbol_indices.len() >= 1023 {
                return Err(Error("EXTDEF count exceeds LINK limit of 1023"));
            }
            // COMDEF symbols share the EXTDEF ordinal space.
            self.extdef_symbol_indices.push(sym_index);
            // Expose each COMDEF as a COMDAT group with zero sections.
            // This allows consumers to discover communal variables via the
            // ObjectComdat trait.
            self.comdat_groups.push((sym_index, crate::read::ComdatKind::Any));
            #[cfg(debug_assertions)]
            {
                // Log the cursor after each parsed entry so we can detect
                // whether parsing has drifted from the expected record
                // boundaries.
                eprintln!(
                    "  COMDEF entry parsed: name={:?} type_idx={} dst=0x{:02X} cursor={} remaining={} bytes",
                    name,
                    type_idx,
                    dst,
                    pos,
                    body.len().saturating_sub(pos)
                );
            }
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

    /// Classify a decoded LEDATA/LIDATA index into a DataTarget.
    fn classify_data_target(&self, seg_idx: u16) -> DataTarget {
        if seg_idx != 0 && (seg_idx as usize) <= self.segments.len() {
            return DataTarget::Segment(seg_idx);
        }
        // Try communal mapping via EXTDEF/COMDEF ordinal space.
        if seg_idx != 0 && (seg_idx as usize) <= self.extdef_symbol_indices.len() {
            let ordinal = seg_idx;
            if let Some(&sym_index) = self.extdef_symbol_indices.get(ordinal as usize - 1) {
                if let Some((comdat_pos, _)) = self
                    .comdat_groups
                    .iter()
                    .enumerate()
                    .find(|(_i, (sidx, _))| *sidx == sym_index)
                {
                    // If we have a matching comdat/comdef, classify as communal.
                    if comdat_pos < self.comdefs.len() {
                        return DataTarget::Communal { comdef_ord: ordinal };
                    }
                }
            }
        }
        DataTarget::Unknown
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

    /// Raw-format accessor: return the decoded FIXUPP records (OMF-native view).
    ///
    /// This follows the crate's `raw_*` naming convention used by other
    /// readers to expose format-native structures.
    pub fn raw_fixupp_records(&self) -> &[ParsedFixuppRecord] {
        &self.fixupp_records
    }

    /// Raw-format accessor: return the parsed TYPDEF records.
    pub fn raw_typdefs(&self) -> &[crate::read::omf::ParsedTypDefRecord<'data>] {
        &self.typdefs
    }

    /// Raw-format accessor: return the parsed COMDEF entries.
    pub fn raw_comdefs(&self) -> &[crate::read::omf::ParsedComdefEntry<'data>] {
        &self.comdefs
    }

    /// Returns the parsed COMDAT (0xC2/0xC3) records.
    pub fn comdat_records(&self) -> &[super::CombatRecord] {
        &self.comdat_records
    }

    /// Collect all THREAD subrecords from all FIXUPP records.
    pub fn thread_subrecords(&self) -> Vec<&ParsedThreadSubrecord> {
        let mut threads = Vec::new();
        for rec in &self.fixupp_records {
            for sub in &rec.subrecords {
                if let ParsedFixuppSubrecord::Thread(t) = sub {
                    threads.push(t);
                }
            }
        }
        threads
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
        // TARGET threads store only the base target kind (0, 1, 2) or no-displacement (4, 5, 6).
        matches!(method, 0 | 1 | 2 | 4 | 5 | 6)
    };
    if !valid {
        return Err(Error("invalid THREAD method"));
    }

    let has_datum = if is_frame {
        method <= 2
    } else {
        method <= 2 || matches!(method, 4 | 5 | 6)
    };

    let datum = if has_datum {
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
        let datum = if method <= 2 || method == 3 {
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
        let datum = te.datum.ok_or(Error("FIXUPP target thread missing datum"))?;
        Ok(Some(ResolvedTarget {
            method,
            datum: Some(datum),
            thread_num: Some(thread_num),
        }))
    }
}

fn expand_lidata(data: &[u8], pos: usize, depth: usize) -> Result<(Vec<u8>, usize)> {
    if depth > 8 {
        return Err(Error("LIDATA nesting too deep"));
    }
    if pos + 4 > data.len() {
        return Err(Error("truncated LIDATA block"));
    }
    let start_pos = pos;

    let repeat_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    let block_count = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
    let mut pos = pos + 4;

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

    Ok((result, pos - start_pos))
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
            index: 0,
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
            EntryPoint::None => 0,
            EntryPoint::Segment(seg_ord, offset) => self.flat_base(seg_ord) + offset as u64,
            EntryPoint::External(ordinal, _offset) => {
                // External entry: return 0 since we cannot resolve the address
                // from the object file alone. Consumers may look up the symbol
                // by ordinal via extdef_symbol_index().
                let _ = ordinal;
                0
            }
        }
    }

    fn flags(&self) -> FileFlags {
        FileFlags::None
    }
}

// ── Standalone COMDEF parser (spec-level) ──────────────────────────────────

fn comdef_read_u8(buf: &[u8], pos: &mut usize) -> core::result::Result<u8, super::ComdefError> {
    buf.get(*pos).copied().map(|b| {
        *pos += 1;
        b
    })
    .ok_or(super::ComdefError::UnexpectedEof(*pos))
}

fn comdef_parse_index(buf: &[u8], pos: &mut usize) -> core::result::Result<u16, super::ComdefError> {
    let b0 = comdef_read_u8(buf, pos)?;
    if b0 & 0x80 == 0 {
        Ok(b0 as u16)
    } else {
        let b1 = comdef_read_u8(buf, pos)?;
        Ok((((b0 & 0x7F) as u16) << 8) | b1 as u16)
    }
}

fn comdef_parse_communal_length(
    buf: &[u8],
    pos: &mut usize,
) -> core::result::Result<u32, super::ComdefError> {
    let lead = comdef_read_u8(buf, pos)?;
    match lead {
        0x00..=0x80 => Ok(lead as u32),
        0x81 => {
            let lo = comdef_read_u8(buf, pos)? as u32;
            let hi = comdef_read_u8(buf, pos)? as u32;
            Ok(lo | (hi << 8))
        }
        0x84 => {
            let b0 = comdef_read_u8(buf, pos)? as u32;
            let b1 = comdef_read_u8(buf, pos)? as u32;
            let b2 = comdef_read_u8(buf, pos)? as u32;
            Ok(b0 | (b1 << 8) | (b2 << 16))
        }
        0x88 => {
            let b0 = comdef_read_u8(buf, pos)? as u32;
            let b1 = comdef_read_u8(buf, pos)? as u32;
            let b2 = comdef_read_u8(buf, pos)? as u32;
            let b3 = comdef_read_u8(buf, pos)? as u32;
            Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
        }
        other => Err(super::ComdefError::InvalidLengthPrefix(other)),
    }
}

/// Parse a complete COMDEF record (0xB0) from a raw byte slice.
///
/// `input` must begin with the 0xB0 type byte and include all bytes
/// through (and including) the trailing checksum.
pub fn parse_comdef_record(input: &[u8]) -> core::result::Result<super::ComdefRecord, super::ComdefError> {
    let mut pos = 0usize;

    let record_type = comdef_read_u8(input, &mut pos)?;
    if record_type != 0xB0 {
        return Err(super::ComdefError::WrongRecordType { found: record_type });
    }

    let len_lo = comdef_read_u8(input, &mut pos)? as usize;
    let len_hi = comdef_read_u8(input, &mut pos)? as usize;
    let record_length = len_lo | (len_hi << 8);
    let body_end = pos + record_length;
    if body_end > input.len() {
        return Err(super::ComdefError::UnexpectedEof(input.len()));
    }

    // Verify checksum
    let stored = input.last().copied().unwrap_or(0);
    if stored != 0x00 {
        let sum: u8 = input.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if sum != 0 {
            let computed = 0u8.wrapping_sub(input[..input.len() - 1].iter().fold(0u8, |acc, &b| acc.wrapping_add(b)));
            return Err(super::ComdefError::ChecksumMismatch { computed, stored });
        }
    }

    let data_end = body_end - 1;
    let mut entries = Vec::new();

    while pos < data_end {
        let name_len = comdef_read_u8(input, &mut pos)? as usize;
        if pos + name_len > data_end {
            return Err(super::ComdefError::UnexpectedEof(pos));
        }
        let name = input[pos..pos + name_len].to_vec();
        pos += name_len;

        let type_index = comdef_parse_index(input, &mut pos)?;
        let data_type = comdef_read_u8(input, &mut pos)?;

        let communal = match data_type {
            0x01..=0x5F => super::ComdefKind::BorlandSegment { index: data_type },
            0x61 => {
                let count = comdef_parse_communal_length(input, &mut pos)?;
                let element_size = comdef_parse_communal_length(input, &mut pos)?;
                super::ComdefKind::Far { count, element_size }
            }
            0x62 => {
                let size = comdef_parse_communal_length(input, &mut pos)?;
                super::ComdefKind::Near { size }
            }
            other => return Err(super::ComdefError::UnknownDataType(other)),
        };

        entries.push(super::ComdefEntry {
            name,
            type_index,
            communal,
        });
    }

    Ok(super::ComdefRecord { entries })
}

// ── Standalone COMDAT parser (spec-level) ──────────────────────────────────

fn comdat_read_u8(buf: &[u8], pos: &mut usize) -> core::result::Result<u8, super::CombatError> {
    buf.get(*pos).copied()
        .map(|b| { *pos += 1; b })
        .ok_or(super::CombatError::UnexpectedEof(*pos))
}

fn comdat_read_u16_le(buf: &[u8], pos: &mut usize) -> core::result::Result<u16, super::CombatError> {
    let lo = comdat_read_u8(buf, pos)? as u16;
    let hi = comdat_read_u8(buf, pos)? as u16;
    Ok(lo | (hi << 8))
}

fn comdat_read_u32_le(buf: &[u8], pos: &mut usize) -> core::result::Result<u32, super::CombatError> {
    let b0 = comdat_read_u8(buf, pos)? as u32;
    let b1 = comdat_read_u8(buf, pos)? as u32;
    let b2 = comdat_read_u8(buf, pos)? as u32;
    let b3 = comdat_read_u8(buf, pos)? as u32;
    Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}

fn comdat_parse_index(buf: &[u8], pos: &mut usize) -> core::result::Result<u16, super::CombatError> {
    let b0 = comdat_read_u8(buf, pos)?;
    if b0 & 0x80 == 0 {
        Ok(b0 as u16)
    } else {
        let b1 = comdat_read_u8(buf, pos)?;
        Ok((((b0 & 0x7F) as u16) << 8) | b1 as u16)
    }
}

/// Parse a COMDAT or COMDAT32 record from a raw byte slice.
///
/// `input` must begin with the 0xC2 or 0xC3 type byte and include all
/// bytes through (and including) the trailing checksum byte.
pub fn parse_comdat(
    input: &[u8],
    name_encoding: super::PublicNameEncoding,
) -> core::result::Result<super::CombatRecord, super::CombatError> {
    let mut pos = 0usize;

    let kind = match comdat_read_u8(input, &mut pos)? {
        0xC2 => super::CombatKind::Comdat16,
        0xC3 => super::CombatKind::Comdat32,
        other => return Err(super::CombatError::WrongRecordType { found: other }),
    };

    let record_length = comdat_read_u16_le(input, &mut pos)? as usize;
    let record_end = pos + record_length;
    if record_end > input.len() {
        return Err(super::CombatError::UnexpectedEof(input.len()));
    }

    // Verify checksum
    let stored = input.last().copied().unwrap_or(0);
    if stored != 0x00 {
        let sum: u8 = input.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if sum != 0 {
            let computed = 0u8.wrapping_sub(input[..input.len() - 1].iter().fold(0u8, |acc, &b| acc.wrapping_add(b)));
            return Err(super::CombatError::ChecksumMismatch { computed, stored });
        }
    }

    let flags_byte = comdat_read_u8(input, &mut pos)?;
    let flags = super::CombatFlags::from_bits_truncate(flags_byte);

    let attr_byte = comdat_read_u8(input, &mut pos)?;
    let sel_nibble = (attr_byte >> 4) & 0x0F;
    let alloc_nibble = attr_byte & 0x0F;
    let selection = super::SelectionCriteria::from_nibble(sel_nibble)
        .ok_or(super::CombatError::ReservedSelectionCriteria(sel_nibble))?;
    let allocation = super::AllocationType::from_nibble(alloc_nibble)
        .ok_or(super::CombatError::ReservedAllocationType(alloc_nibble))?;
    let attributes = super::CombatAttributes { selection, allocation };

    let align_byte = comdat_read_u8(input, &mut pos)?;
    let align = super::CombatAlign::from_u8(align_byte);

    let data_offset = match kind {
        super::CombatKind::Comdat16 => comdat_read_u16_le(input, &mut pos)? as u32,
        super::CombatKind::Comdat32 => comdat_read_u32_le(input, &mut pos)?,
    };

    let type_index = comdat_parse_index(input, &mut pos)?;

    let public_base = if allocation.has_public_base() {
        let group_index = comdat_parse_index(input, &mut pos)?;
        let segment_index = comdat_parse_index(input, &mut pos)?;
        let segment = if segment_index == 0 {
            let frame = comdat_read_u16_le(input, &mut pos)?;
            super::SegmentBase::Absolute { frame }
        } else {
            super::SegmentBase::Segment(segment_index)
        };
        Some(super::PublicBase { group_index, segment })
    } else {
        None
    };

    let public_name = match name_encoding {
        super::PublicNameEncoding::MicrosoftIndex => {
            super::PublicName::Index(comdat_parse_index(input, &mut pos)?)
        }
        super::PublicNameEncoding::IbmString => {
            let len = comdat_read_u8(input, &mut pos)? as usize;
            if pos + len > record_end {
                return Err(super::CombatError::UnexpectedEof(pos));
            }
            let name = input[pos..pos + len].to_vec();
            pos += len;
            super::PublicName::Name(name)
        }
    };

    let data_end = record_end - 1;
    let data_len = data_end.saturating_sub(pos);
    if data_len > 1024 {
        return Err(super::CombatError::DataTooLong(data_len));
    }
    let data = input[pos..data_end].to_vec();

    Ok(super::CombatRecord {
        kind,
        flags,
        attributes,
        align,
        data_offset,
        type_index,
        public_base,
        public_name,
        data,
        relocs: Vec::new(),
    })
}

// ── Standalone PUBDEF parser (spec-level) ───────────────────────────────────

fn pubdef_read_u8(buf: &[u8], pos: &mut usize) -> core::result::Result<u8, super::PubdefError> {
    buf.get(*pos).copied()
        .map(|b| { *pos += 1; b })
        .ok_or(super::PubdefError::UnexpectedEof(*pos))
}

fn pubdef_read_u16_le(buf: &[u8], pos: &mut usize) -> core::result::Result<u16, super::PubdefError> {
    let lo = pubdef_read_u8(buf, pos)? as u16;
    let hi = pubdef_read_u8(buf, pos)? as u16;
    Ok(lo | (hi << 8))
}

fn pubdef_read_u32_le(buf: &[u8], pos: &mut usize) -> core::result::Result<u32, super::PubdefError> {
    let b0 = pubdef_read_u8(buf, pos)? as u32;
    let b1 = pubdef_read_u8(buf, pos)? as u32;
    let b2 = pubdef_read_u8(buf, pos)? as u32;
    let b3 = pubdef_read_u8(buf, pos)? as u32;
    Ok(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24))
}

fn pubdef_parse_index(buf: &[u8], pos: &mut usize) -> core::result::Result<u16, super::PubdefError> {
    let b0 = pubdef_read_u8(buf, pos)?;
    if b0 & 0x80 == 0 {
        Ok(b0 as u16)
    } else {
        let b1 = pubdef_read_u8(buf, pos)?;
        Ok((((b0 & 0x7F) as u16) << 8) | b1 as u16)
    }
}

fn pubdef_parse_base(buf: &[u8], pos: &mut usize) -> core::result::Result<super::PubdefBase, super::PubdefError> {
    let group_index   = pubdef_parse_index(buf, pos)?;
    let segment_index = pubdef_parse_index(buf, pos)?;

    if segment_index == 0 {
        let frame = pubdef_read_u16_le(buf, pos)?;
        Ok(super::PubdefBase::Frame { group_index, frame })
    } else {
        Ok(super::PubdefBase::Segment { group_index, segment_index })
    }
}

fn pubdef_parse_name(buf: &[u8], pos: &mut usize) -> core::result::Result<String, super::PubdefError> {
    let name_start = *pos;
    let len = pubdef_read_u8(buf, pos)? as usize;

    if len == 0 {
        return Err(super::PubdefError::EmptyName(name_start));
    }
    if len > 255 {
        return Err(super::PubdefError::NameTooLong(len));
    }
    if *pos + len > buf.len() {
        return Err(super::PubdefError::UnexpectedEof(*pos));
    }

    let name = String::from_utf8(buf[*pos..*pos + len].to_vec())
        .map_err(|_| super::PubdefError::InvalidName)?;
    *pos += len;
    Ok(name)
}

fn pubdef_parse_offset(
    buf: &[u8],
    pos: &mut usize,
    kind: super::PubdefKind,
) -> core::result::Result<u32, super::PubdefError> {
    match kind {
        super::PubdefKind::Pubdef16 => pubdef_read_u16_le(buf, pos).map(|v| v as u32),
        super::PubdefKind::Pubdef32 => pubdef_read_u32_le(buf, pos),
    }
}

fn pubdef_verify_checksum(record_bytes: &[u8]) -> core::result::Result<(), super::PubdefError> {
    let stored = match record_bytes.last() {
        Some(&b) => b,
        None => return Err(super::PubdefError::UnexpectedEof(0)),
    };
    if stored == 0x00 {
        return Ok(());
    }
    let sum: u8 = record_bytes
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum != 0 {
        let computed = 0u8.wrapping_sub(
            record_bytes[..record_bytes.len() - 1]
                .iter()
                .fold(0u8, |acc, &b| acc.wrapping_add(b)),
        );
        return Err(super::PubdefError::ChecksumMismatch { computed, stored });
    }
    Ok(())
}

/// Parse a PUBDEF or PUBDEF32 record from a raw byte slice.
///
/// `input` must begin with the 0x90 or 0x91 type byte and include all
/// bytes through (and including) the trailing checksum byte:
///
///   [type:1][length:2][base_group:1-2][base_seg:1-2][base_frame:0 or 2]
///   ([name_len:1][name:N][offset:2 or 4][type_idx:1-2])* [checksum:1]
pub fn parse_pubdef_record(input: &[u8]) -> core::result::Result<super::PubdefRecord, super::PubdefError> {
    let mut pos = 0usize;

    let kind = match pubdef_read_u8(input, &mut pos)? {
        0x90 => super::PubdefKind::Pubdef16,
        0x91 => super::PubdefKind::Pubdef32,
        other => return Err(super::PubdefError::WrongRecordType { found: other }),
    };

    let record_length = pubdef_read_u16_le(input, &mut pos)? as usize;
    let record_end = pos + record_length;
    if record_end > input.len() {
        return Err(super::PubdefError::UnexpectedEof(input.len()));
    }

    pubdef_verify_checksum(&input[..record_end])?;

    let base = pubdef_parse_base(input, &mut pos)?;

    let data_end = record_end - 1;
    let mut entries = Vec::new();

    while pos < data_end {
        let name = pubdef_parse_name(input, &mut pos)?;
        let offset = pubdef_parse_offset(input, &mut pos, kind)?;
        let type_index = pubdef_parse_index(input, &mut pos)?;
        entries.push(super::PubdefEntry { name, offset, type_index });
    }

    Ok(super::PubdefRecord { kind, base, entries })
}

// ── Standalone LPUBDEF parser (spec-level) ─────────────────────────────────

/// Parses an LPUBDEF record (0xB6 or 0xB7).
///
/// `record_type` is the byte that identified the record (0xB6 or 0xB7).
/// `body` is everything that followed the 2-byte Record Length field —
/// i.e. exactly `Record Length` bytes, still including the trailing
/// checksum byte.
pub fn parse_lpubdef(
    record_type: u8,
    body: &[u8],
) -> core::result::Result<super::LpubdefRecord, super::LpubdefParseError> {
    let offset_width = match record_type {
        0xB6 => super::OffsetWidth::Bit16,
        0xB7 => super::OffsetWidth::Bit32,
        other => return Err(super::LpubdefParseError::InvalidRecordType(other)),
    };

    if body.is_empty() {
        return Err(super::LpubdefParseError::UnexpectedEof { expected: 1, remaining: 0 });
    }
    let checksum = body[body.len() - 1];
    let mut cur = LpubdefCursor::new(&body[..body.len() - 1]);

    let base_group = cur.read_index()?;
    let base_segment = cur.read_index()?;

    let base_frame = if base_segment.0 == 0 {
        Some(cur.read_u16_le()?)
    } else {
        None
    };

    let mut names = Vec::new();
    while cur.remaining() > 0 {
        let name_len = cur.read_u8()? as usize;
        if name_len == 0 {
            return Err(super::LpubdefParseError::EmptyName);
        }
        let name = cur.read_bytes(name_len)?.to_vec();

        let offset = match offset_width {
            super::OffsetWidth::Bit16 => cur.read_u16_le()? as u32,
            super::OffsetWidth::Bit32 => cur.read_u32_le()?,
        };

        let type_index = cur.read_index()?;

        names.push(super::LocalPublicName { name, offset, type_index });
    }

    if cur.remaining() != 0 {
        return Err(super::LpubdefParseError::TrailingBytes { leftover: cur.remaining() });
    }

    Ok(super::LpubdefRecord { offset_width, base_group, base_segment, base_frame, names, checksum })
}

struct LpubdefCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> LpubdefCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> core::result::Result<u8, super::LpubdefParseError> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or(super::LpubdefParseError::UnexpectedEof { expected: 1, remaining: self.remaining() })?;
        self.pos += 1;
        Ok(byte)
    }

    fn read_u16_le(&mut self) -> core::result::Result<u16, super::LpubdefParseError> {
        self.expect(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32_le(&mut self) -> core::result::Result<u32, super::LpubdefParseError> {
        self.expect(4)?;
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_bytes(&mut self, n: usize) -> core::result::Result<&'a [u8], super::LpubdefParseError> {
        self.expect(n)?;
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn expect(&self, n: usize) -> core::result::Result<(), super::LpubdefParseError> {
        if self.remaining() < n {
            Err(super::LpubdefParseError::UnexpectedEof { expected: n, remaining: self.remaining() })
        } else {
            Ok(())
        }
    }

    fn read_index(&mut self) -> core::result::Result<super::OmfIndex, super::LpubdefParseError> {
        let first = self.read_u8()?;
        if first & 0x80 == 0 {
            Ok(super::OmfIndex(first as u16))
        } else {
            let second = self.read_u8()?;
            Ok(super::OmfIndex((((first & 0x7F) as u16) << 8) | second as u16))
        }
    }
}
