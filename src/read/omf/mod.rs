use alloc::vec::Vec;
use core::fmt::Debug;

mod file;
pub use file::*;

mod section;
pub use section::*;

mod symbol;
pub use symbol::*;

mod relocation;
pub use relocation::*;

mod comdat;
pub use comdat::*;

/// The kind of an OMF thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadKind {
    /// A target thread.
    Target,
    /// A frame thread.
    Frame,
}

/// One entry in the OMF thread table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadEntry {
    /// OMF thread method.
    /// FRAME threads permit methods 0, 1, 2, 4, 5.
    /// TARGET threads permit methods 0, 1, 2, 4, 5, 6.
    /// Method 3 (explicit frame number) is documented but not supported by Microsoft LINK.
    pub method: u8,
    /// The datum associated with the thread, if any.
    pub datum: Option<u16>,
}

/// The OMF thread table.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadTable {
    /// The target threads (0-3).
    pub target: [Option<ThreadEntry>; 4],
    /// The frame threads (0-3).
    pub frame: [Option<ThreadEntry>; 4],
}

impl ThreadTable {
    /// Create a new empty thread table.
    pub fn new() -> Self {
        Self::default()
    }
}

/// A decoded FIXUPP subrecord for dump purposes.
#[derive(Debug, Clone)]
pub enum ParsedFixuppSubrecord {
    /// A THREAD subrecord.
    Thread(ParsedThreadSubrecord),
    /// A fixup subrecord.
    Fixup(ParsedFixupSubrecord),
}

/// A decoded THREAD subrecord.
#[derive(Debug, Clone)]
pub struct ParsedThreadSubrecord {
    /// The kind of thread (FRAME or TARGET).
    pub kind: ThreadKind,
    /// The thread number (0-3).
    pub thread_number: u8,
    /// The method used by the thread (0-6).
    pub method: u8,
    /// The datum associated with the thread, if any.
    pub datum: Option<u16>,
}

/// A decoded fixup subrecord.
#[derive(Debug, Clone)]
pub struct ParsedFixupSubrecord {
    /// The offset within the logical data record (u32 to support 32-bit LEDATA).
    pub record_offset: u32,
    /// The raw location type from the file.
    pub loc_raw: u8,
    /// The normalized location type.
    pub loc: u8,
    /// True if the fixup is segment-relative.
    pub is_seg_rel: bool,
    /// The raw fix_dat byte.
    pub fixdat: u8,
    /// The thread number used for the FRAME, if any.
    pub frame_thread: Option<u8>,
    /// The effective method used for the FRAME.
    pub frame_method: u8,
    /// The datum used for the FRAME, if any.
    pub frame_datum: Option<u16>,
    /// The thread number used for the TARGET, if any.
    pub target_thread: Option<u8>,
    /// The effective method used for the TARGET.
    pub target_method: u8,
    /// The datum used for the TARGET.
    pub target_datum: u16,
    /// The displacement associated with the TARGET, if any.
    pub target_displacement: Option<u32>,
    }

/// A decoded FIXUPP record containing multiple subrecords.
#[derive(Debug, Clone)]
pub struct ParsedFixuppRecord {
    /// The ordinal of the segment this record is attached to, if known.
    pub attached_seg_ordinal: Option<u16>,
    /// The list of subrecords in encounter order.
    pub subrecords: Vec<ParsedFixuppSubrecord>,
    /// Snapshot of the thread table at the start of this FIXUPP record.
    pub thread_table: ThreadTable,
}

/// One segment, parsed from a SEGDEF record and populated by LEDATA/LIDATA.
#[derive(Debug, Clone)]
pub struct ParsedSegment<'data> {
    /// 0-based index into OmfFile::lnames. u16::MAX = no name.
    pub name_idx: u16,
    /// 0-based index into OmfFile::lnames. u16::MAX = no class.
    pub class_idx: u16,
    /// Declared length in bytes from SEGDEF. 0 means max-size when big==true
    /// (64 KB for 0x98, 4 GB for 0x99).
    pub length: u32,
    /// True when the ACBP B-bit is set (segment is exactly 64 KB).
    pub big: bool,
    /// Alignment in bytes derived from the ACBP A-field.
    pub alignment: u32,
    /// Raw C-field value from the ACBP byte.
    #[allow(dead_code)]
    pub combine: u8,
    /// Frame number; only meaningful when alignment == ALIGN_ABSOLUTE.
    #[allow(dead_code)]
    pub frame: u16,
    /// Accumulated data bytes from all LEDATA/LIDATA records.
    pub data: Vec<u8>,
    /// Relocations collected from FIXUPP records following LEDATA/LIDATA.
    pub relocs: Vec<ParsedReloc>,
    /// 1-based ordinal as this segment appeared in the file (first SEGDEF = 1).
    #[allow(dead_code)]
    pub ordinal: u16,
    /// True if this segment is absolute (ACBP A field == 0).
    pub is_absolute: bool,
    /// Base address in the flat layout (computed after scan, not from the file).
    pub flat_base: u64,
    /// Phantom data for lifetime.
    pub(super) _marker: core::marker::PhantomData<&'data ()>,
}

/// Symbol from PUBDEF (defined), EXTDEF (imported), or COMDEF (communal).
#[derive(Debug, Clone)]
pub struct ParsedSymbol<'data> {
    /// The name of the symbol.
    pub name: &'data [u8],
    /// The kind of the symbol.
    pub kind: ParsedSymbolKind,
    /// 1-based SEGDEF ordinal. 0 = absolute or undefined or communal.
    pub seg_ordinal: u16,
    /// Byte offset within the segment.
    pub offset: u16,
}

/// A parsed TYPDEF record (obsolete compatibility record).
#[derive(Debug, Clone)]
pub struct ParsedTypDefRecord<'data> {
    /// The optional name (count-prefixed string from the record).
    pub name: &'data [u8],
    /// EN field from the record (not always present; 0 when absent).
    pub en: u8,
    /// The decoded descriptor.
    pub descriptor: ParsedTypDefDescriptor<'data>,
}

/// A single parsed COMDEF (communal variable) entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedComdefEntry<'data> {
    /// Communal name (borrowed slice from the OMF data).
    pub name: &'data [u8],
    /// Raw type index (1- or 2-byte OMF index).
    pub type_index: u16,
    /// Placement and size encoding.
    pub communal: ParsedCommunalKind<'data>,
    /// Accumulated data bytes for this communal entry (filled from LEDATA/LIDATA
    /// records that target the COMDEF/COMDAT ordinal space).
    pub data: Vec<u8>,
    /// Relocations attached to this communal entry (parsed from FIXUPP
    /// records that immediately follow LEDATA/LIDATA targeting the COMDEF
    /// ordinal space).
    pub relocs: Vec<ParsedReloc>,
}

/// Communal kind describing NEAR/FAR/Borland segment encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedCommunalKind<'data> {
    /// NEAR data — flat allocation of `size` bytes.
    Near {
        /// Total allocation size in bytes.
        size: u32,
    },
    /// FAR data — `count` elements each of `element_size` bytes.
    Far {
        /// Number of elements in the FAR array.
        count: u32,
        /// Size of each element in bytes.
        element_size: u32,
    },
    /// Borland segment index (Data Type 0x01–0x5F).
    BorlandSegment {
        /// Segment index byte value.
        index: u8,
    },
    /// Unknown/opaque remainder of the COMDEF entry.
    Opaque(&'data [u8]),
}

// Variable kinds supported by NEAR descriptors are encoded as a single byte in
// the record. We store the raw byte here to preserve on-disk fidelity; this
// keeps the parser tolerant of tool-specific values while still exposing the
// common cases for callers.

/// TYPDEF descriptor decoded from the leaf-stream. Unknown leaf tags are
/// captured as opaques to preserve compatibility with tool-specific
/// extensions.
#[derive(Debug, Clone)]
pub enum ParsedTypDefDescriptor<'data> {
    /// NEAR variable: (variable_type_byte, length_bits)
    /// NEAR variable: (variable_type_byte, length_bits)
    Near {
        /// The raw variable type byte (e.g. 0x77 for array).
        variable_type: u8,
        /// The bit length of the variable.
        length_bits: u32,
    },
    /// FAR variable: (element_count, element_type_index)
    Far {
        /// Number of elements in the FAR array.
        element_count: u32,
        /// Index into the TYPDEF list for the element type (1-based).
        element_type_index: u16,
    },
    /// Unknown/opaque leafs — the raw remaining bytes of the descriptor.
    Opaque(&'data [u8]),
}

/// The kind of a parsed OMF symbol.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParsedSymbolKind {
    /// PUBDEF: defined and exported from this module.
    Public,
    /// LPUBDEF: defined but not exported from this module.
    LocalPublic,
    /// EXTDEF: referenced but defined in another module.
    External,
    /// LEXTDEF: referenced but defined in another module, not visible outside.
    LocalExternal,
    /// COMDEF: communal (common) storage; may be merged across modules.
    Communal,
}

/// One relocation entry, attached to a segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedReloc {
    /// Byte offset within the segment's data buffer (u32 for LEDATA32 support).
    pub offset: u32,
    /// Effective loc value after normalization.
    pub loc: u8,
    /// True if segment-relative; false if self-relative.
    pub is_seg_rel: bool,
    /// What the fixup targets.
    pub target: RelocTarget,
    /// Target displacement.
    pub displacement: u32,
}

/// The target of an OMF relocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocTarget {
    /// A segment.
    Segment(u16),
    /// A group.
    ///
    /// NOTE: the object crate has no group concept. When building a
    /// RelocationTarget, this will be resolved to the first segment in the group.
    /// This is a heuristic approximation.
    Group(u16),
    /// An external symbol.
    External(u16),
    /// An absolute frame number.
    ///
    /// The effective absolute address is `(frame_number << 4) + displacement`.
    /// Used by FIXUPP target methods 3 and 7 (explicit frame number).
    AbsoluteFrame(u16),
}

/// One group, parsed from a GRPDEF record.
#[derive(Debug, Clone)]
pub struct ParsedGroup {
    /// 0-based index into OmfFile::lnames.
    #[allow(dead_code)]
    pub name_idx: u16,
    /// 1-based SEGDEF ordinals of all member segments, in encounter order.
    pub members: Vec<u16>,
    /// Ordinals referenced by the group that were not materialized at parse time.
    /// These are kept so consumers can inspect unresolved references rather than
    /// failing the entire parse when toolchains emit groups ahead of segment
    /// declarations or use alternative segment encoding schemes.
    pub unresolved: Vec<u16>,
    /// Resolved view of members after finalize(): for each entry in `members`,
    /// Some(ordinal) when that ordinal was materialized and None when it was
    /// unresolved at parse time. Populated by OmfFile::finalize().
    pub resolved_members: Vec<Option<u16>>,
    /// Full list of decoded components in the GRPDEF record. This preserves
    /// non-segment components (Intel-specific forms) so the parser remains
    /// stream-aligned and lossless.
    pub components: Vec<ParsedGroupComponent>,
}

/// One GRPDEF component decoded from the file.
#[derive(Debug, Clone)]
pub enum ParsedGroupComponent {
    /// A plain segment reference component (0xFF).
    Segment {
        /// 1-based SEGDEF ordinal.
        seg_index: u16,
    },
    /// External (EXTDEF) component (0xFE).
    External {
        /// 1-based EXTDEF ordinal.
        ext_index: u16,
    },
    /// Name triple component (0xFD): seg-name, class-name, overlay-name.
    NameTriple {
        /// 1-based LNAMES index for the segment name.
        seg_name_index: u16,
        /// 1-based LNAMES index for the class name.
        class_name_index: u16,
        /// 1-based LNAMES index for the overlay name.
        overlay_name_index: u16,
    },
    /// LTL component (0xFB) carrying LTL data and group length fields.
    Ltl {
        /// Raw LTL data byte.
        ltl_data: u8,
        /// Maximum group length value.
        max_group_length: u16,
        /// Actual group length value.
        group_length: u16,
    },
    /// Absolute frame component (0xFA) with frame number and offset.
    AbsoluteFrame {
        /// Frame number.
        frame_number: u16,
        /// Offset within the frame.
        offset: u16,
    },
}

/// The entry point kind for a parsed OMF file.
///
/// Note: the offset/displacement is stored as a 32-bit value to support
/// MODEND32 (0x8B) records which encode a 32-bit start displacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPoint {
    /// No entry point (module is not main).
    None,
    /// Entry point is a segment ordinal + offset.
    Segment(u16, u32),
    /// Entry point is an external symbol ordinal + offset.
    External(u16, u32),
}
