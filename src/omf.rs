//! Constants for the Intel/Microsoft OMF16 object file format.
//!
//! Reference: MS-DOS Encyclopedia, Article 19: Object Modules.
//!
//! Note: the flat address mapping in OmfFile is an object-crate abstraction.
//! The OMF format itself uses segmented 8086 addressing; the linearization
//! used here (segments laid out in ordinal order, each alignment-padded) is
//! not specified by the format and is documented as an implementation choice.

// ── Record type identifiers ───────────────────────────────────────────────

/// THEADR: Translator Header Record.
pub const RT_THEADR: u8 = 0x80;
/// COMENT: Comment Record.
pub const RT_COMENT: u8 = 0x88;
/// MODEND: Module End Record.
pub const RT_MODEND: u8 = 0x8A;
/// MODEND32: 32-bit Module End Record (target displacement is 32-bit).
pub const RT_MODEND32: u8 = 0x8B;
/// EXTDEF: External Names Definition Record.
pub const RT_EXTDEF: u8 = 0x8C;
/// LEXTDEF: Local External Names Definition Record.
pub const RT_LOCAL_EXTDEF: u8 = 0xB4;
/// TYPDEF: Type Definition Record.
pub const RT_TYPDEF: u8 = 0x8E;
/// PUBDEF: Public Names Definition Record.
pub const RT_PUBDEF: u8 = 0x90;
/// LPUBDEF: Local Public Names Definition Record.
pub const RT_LOCAL_PUBDEF: u8 = 0xB6;
/// LINNUM: Line Number Record.
pub const RT_LINNUM: u8 = 0x94;
/// LNAMES: List of Names Record.
pub const RT_LNAMES: u8 = 0x96;
/// SEGDEF: Segment Definition Record.
pub const RT_SEGDEF: u8 = 0x98;
/// SEGDEF32: 32-bit Segment Definition Record.
pub const RT_SEGDEF32: u8 = 0x99;
/// GRPDEF: Group Definition Record.
pub const RT_GRPDEF: u8 = 0x9A;
/// FIXUPP: Fixup Record.
pub const RT_FIXUPP: u8 = 0x9C;
/// FIXUPP32: 32-bit Fixup Record.
pub const RT_FIXUPP32: u8 = 0x9D;
/// LEDATA: Logical Enumerated Data Record.
pub const RT_LEDATA: u8 = 0xA0;
/// LEDATA32: 32-bit enumerated data offset.
pub const RT_LEDATA32: u8 = 0xA1;
/// LIDATA: Logical Iterated Data Record.
pub const RT_LIDATA: u8 = 0xA2;
/// COMDEF: Communal Names Definition Record.
pub const RT_COMDEF: u8 = 0xB0;

// ── SEGDEF ACBP byte ──────────────────────────────────────────────────────
//
// Bit layout:
//   [7:5] A  = Alignment
//   [4:2] C  = Combine type
//   [1]   B  = Big (exactly 64 KB; segment_length field will be 0)
//   [0]   P  = Page-resident (unused in MS-DOS, always 0)

/// ACBP A-field mask (alignment).
pub const ACBP_A_MASK: u8 = 0b1110_0000;
/// ACBP A-field shift.
pub const ACBP_A_SHIFT: u8 = 5;
/// ACBP C-field mask (combine type).
pub const ACBP_C_MASK: u8 = 0b0001_1100;
/// ACBP C-field shift.
pub const ACBP_C_SHIFT: u8 = 2;
/// ACBP B-bit mask (big/64KB).
pub const ACBP_B_MASK: u8 = 0b0000_0010;
// ACBP_P_MASK is unused in MS-DOS; not defined to avoid dead-code noise.

/// A-field values (alignment): absolute segment.
pub const ALIGN_ABSOLUTE: u8 = 0; // absolute segment; has frame+offset fields
/// A-field values (alignment): byte aligned.
pub const ALIGN_BYTE: u8 = 1; // relocatable, 1-byte boundary
/// A-field values (alignment): word aligned.
pub const ALIGN_WORD: u8 = 2; // relocatable, 2-byte boundary
/// A-field values (alignment): paragraph aligned (16 bytes).
pub const ALIGN_PARA: u8 = 3; // relocatable, 16-byte boundary
/// A-field values (alignment): page aligned (256 bytes).
pub const ALIGN_PAGE: u8 = 4; // relocatable, 256-byte boundary
/// A-field values (alignment): dword aligned (4 bytes).
pub const ALIGN_DWORD: u8 = 5; // relocatable, 4-byte boundary

/// C-field values (combine type): cannot be combined.
pub const COMBINE_PRIVATE: u8 = 0; // cannot be combined
/// C-field values (combine type): concatenate.
pub const COMBINE_PUBLIC: u8 = 2; // concatenate (also 4 and 7 per Microsoft)
/// C-field values (combine type): concatenate for stack.
pub const COMBINE_STACK: u8 = 5; // concatenate for stack segments
/// C-field values (combine type): overlap (common).
pub const COMBINE_COMMON: u8 = 6; // overlap (common)

// ── FIXUPP locat field ────────────────────────────────────────────────────
//
// The 2-byte locat field has non-standard byte order: the most significant
// bits are in the first (low-order) stored byte, contrary to normal Intel
// little-endian convention.  To reconstruct the logical 16-bit value:
//   logical = (stored_byte[0] as u16) << 8 | (stored_byte[1] as u16)
//
// Logical bit layout:
//   [15]    = 1 (fixup field marker; 0 = thread field)
//   [14]    M = 1 if segment-relative, 0 if self-relative
//   [13]    S = unused, should be 0
//   [12:10] loc = location type (0..5)
//   [9:0]   data record offset into the preceding LEDATA/LIDATA body

/// LOCAT fixup field marker.
pub const LOCAT_FIXUP_MARKER: u16 = 0x8000;
/// LOCAT M-bit (segment-relative).
pub const LOCAT_M_BIT: u16 = 0x4000;
/// LOCAT loc field mask.
pub const LOCAT_LOC_MASK: u16 = 0x3C00;
/// LOCAT loc field shift.
pub const LOCAT_LOC_SHIFT: u16 = 10;
/// LOCAT offset field mask.
pub const LOCAT_OFFSET_MASK: u16 = 0x03FF;

/// loc field values: single byte.
pub const LOC_BYTE: u16 = 0; // single byte
/// loc field values: 16-bit offset.
pub const LOC_OFFSET: u16 = 1; // 16-bit offset
/// loc field values: 16-bit segment value.
pub const LOC_SEGMENT: u16 = 2; // 16-bit segment value
/// loc field values: 32-bit far pointer (segment:offset).
pub const LOC_POINTER: u16 = 3; // 32-bit far pointer (segment:offset)
/// loc field values: high-order byte (not supported by LINK).
pub const LOC_HIGH_BYTE: u16 = 4; // high-order byte — NOT recognized by LINK
/// loc field values: loader-resolved offset.
pub const LOC_LOADER_OFFSET: u16 = 5; // loader-resolved offset; treat as LOC_OFFSET
/// loc field values: 32-bit offset.
pub const LOC_OFFSET32: u16 = 9;
/// loc field values: 48-bit pointer (segment:32-bit offset).
pub const LOC_POINTER48: u16 = 11;
/// loc field values: 32-bit loader-resolved offset.
pub const LOC_LOADER_OFFSET32: u16 = 13; // treat as LOC_OFFSET32

// ── FIXUPP fix_dat byte ───────────────────────────────────────────────────
//
// Bit layout:
//   [7]   F     = 1: FRAME from thread; 0: FRAME explicit in this fixup
//   [6:4] frame = FRAME method (0–5) or thread number (0–3) when F=1
//   [3]   T     = 1: TARGET from thread; 0: TARGET explicit
//   [2]   P     = high-order bit of TARGET method when T=0;
//                 combined with thread method low bits when T=1
//   [1:0] targt = TARGET method low bits (0–3) or thread number (0–3)

/// FIXDAT F-bit (FRAME from thread).
pub const FIXDAT_F_BIT: u8 = 0b1000_0000;
/// FIXDAT frame field mask.
pub const FIXDAT_FRAME_MASK: u8 = 0b0111_0000;
/// FIXDAT frame field shift.
pub const FIXDAT_FRAME_SHIFT: u8 = 4;
/// FIXDAT T-bit (TARGET from thread).
pub const FIXDAT_T_BIT: u8 = 0b0000_1000;
/// FIXDAT P-bit (TARGET method bit).
pub const FIXDAT_P_BIT: u8 = 0b0000_0100;
/// FIXDAT target field mask.
pub const FIXDAT_TARGT_MASK: u8 = 0b0000_0011;

// ── COMDEF / TYPDEF data segment type bytes ───────────────────────────────
//
// Note: read_varlen() uses a variable-length encoding specific to the
// leaf descriptor fields within TYPDEF and COMDEF records.  It is NOT
// a general-purpose OMF numeric encoding.

/// DST: FAR communal variable.
pub const DST_FAR: u8 = 0x61; // FAR communal variable (array of elements)
/// DST: NEAR communal variable.
pub const DST_NEAR: u8 = 0x62; // NEAR communal variable (flat size in bytes)

// ── MODEND module_type byte ───────────────────────────────────────────────

/// MODEND: module contains main().
pub const MODEND_MAIN: u8 = 0b1000_0000; // this module contains main()
/// MODEND: start address field present.
pub const MODEND_START: u8 = 0b0100_0000; // start address field is present
/// MODEND: start address is relocatable.
pub const MODEND_RELOC: u8 = 0b0000_0001; // start address is relocatable (must be 1 when START=1)

// ── COMENT comment class values ───────────────────────────────────────────

/// CC: Translator name.
pub const CC_TRANSLATOR: u8 = 0x00;
/// CC: Copyright.
pub const CC_COPYRIGHT: u8 = 0x01;
/// CC: Default library.
pub const CC_DEFAULT_LIB: u8 = 0x9F;
/// CC: MS Extensions.
pub const CC_MS_EXTENSIONS: u8 = 0xA1;

// ── Detection magic ───────────────────────────────────────────────────────
//
// The first byte of a valid OMF **object module** is always THEADR (0x80).
// This magic byte is specific to object modules; other OMF containers such
// as .LIB archive files do not start with THEADR.

/// MAGIC: first byte of an OMF object module (THEADR).
pub const MAGIC: u8 = RT_THEADR;

// ── Helper: decode OMF index field ───────────────────────────────────────
//
// Index fields are 1 or 2 bytes:
//   byte[0] bit 7 == 0 → index = byte[0] & 0x7F          (1-byte form)
//   byte[0] bit 7 == 1 → index = ((byte[0] & 0x7F) << 8) | byte[1]  (2-byte form)
//
// Returns (index_value, bytes_consumed) or None on truncation.

/// Decode an OMF index field (1 or 2 bytes).
pub fn read_index(data: &[u8], offset: usize) -> Option<(u16, usize)> {
    let b0 = *data.get(offset)?;
    if b0 & 0x80 == 0 {
        Some((b0 as u16, 1))
    } else {
        let b1 = *data.get(offset + 1)?;
        Some((((b0 & 0x7F) as u16) << 8 | b1 as u16, 2))
    }
}

// ── Helper: decode length-prefixed name ──────────────────────────────────

/// Decode a length-prefixed name.
pub fn read_name(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let len = *data.get(offset)? as usize;
    let end = offset + 1 + len;
    if end > data.len() {
        return None;
    }
    Some((&data[offset + 1..end], 1 + len))
}

// ── Helper: decode variable-length size field (TYPDEF/COMDEF only) ────────
//
// This encoding is used exclusively within the leaf descriptor fields of
// TYPDEF records and the communal_length field of COMDEF records.
// It is NOT a general OMF encoding and must not be used elsewhere.
//
// Encoding rules:
//   value < 128        → 1-byte field containing the value directly
//   0x81 prefix        → 2-byte value follows (little-endian)
//   0x84 prefix        → 3-byte value follows (little-endian)
//   0x88 prefix        → 4-byte value follows (little-endian)
//
// Returns (value, bytes_consumed) or None on truncation or unknown prefix.

/// Decode a variable-length size field (TYPDEF/COMDEF only).
pub fn read_varlen(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let b0 = *data.get(offset)?;
    match b0 {
        // Note: 0x80 is a valid single-byte value (128) per COMDEF/TYPDEF spec.
        0x00..=0x80 => Some((b0 as u32, 1)),
        0x81 => {
            let lo = *data.get(offset + 1)?;
            let hi = *data.get(offset + 2)?;
            Some(((hi as u32) << 8 | lo as u32, 3))
        }
        0x84 => {
            let b1 = *data.get(offset + 1)?;
            let b2 = *data.get(offset + 2)?;
            let b3 = *data.get(offset + 3)?;
            Some(((b3 as u32) << 16 | (b2 as u32) << 8 | b1 as u32, 4))
        }
        0x88 => {
            let b1 = *data.get(offset + 1)?;
            let b2 = *data.get(offset + 2)?;
            let b3 = *data.get(offset + 3)?;
            let b4 = *data.get(offset + 4)?;
            Some((
                (b4 as u32) << 24 | (b3 as u32) << 16 | (b2 as u32) << 8 | b1 as u32,
                5,
            ))
        }
        _ => None,
    }
}
