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
    /// The offset within the logical data record.
    pub record_offset: u16,
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
    pub target_displacement: Option<u16>,
}

/// A decoded FIXUPP record containing multiple subrecords.
#[derive(Debug, Clone)]
pub struct ParsedFixuppRecord {
    /// The ordinal of the segment this record is attached to, if known.
    pub attached_seg_ordinal: Option<u16>,
    /// The list of subrecords in encounter order.
    pub subrecords: Vec<ParsedFixuppSubrecord>,
}

/// One segment, parsed from a SEGDEF record and populated by LEDATA/LIDATA.
#[derive(Debug, Clone)]
pub struct ParsedSegment<'data> {
    /// 0-based index into OmfFile::lnames. u16::MAX = no name.
    pub name_idx: u16,
    /// 0-based index into OmfFile::lnames. u16::MAX = no class.
    pub class_idx: u16,
    /// Declared length in bytes from SEGDEF. 0 means 64 KB when big==true.
    pub length: u16,
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

/// The kind of a parsed OMF symbol.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParsedSymbolKind {
    /// PUBDEF: defined and exported from this module.
    Public,
    /// EXTDEF: referenced but defined in another module.
    External,
    /// COMDEF: communal (common) storage; may be merged across modules.
    Communal,
}

/// One relocation entry, attached to a segment.
#[derive(Debug, Clone)]
pub struct ParsedReloc {
    /// Byte offset within the segment's data buffer.
    pub offset: u16,
    /// Effective loc value after normalization.
    pub loc: u8,
    /// True if segment-relative; false if self-relative.
    pub is_seg_rel: bool,
    /// What the fixup targets.
    pub target: RelocTarget,
    /// Target displacement.
    pub displacement: u16,
}

/// The target of an OMF relocation.
#[derive(Debug, Clone)]
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
}

/// One group, parsed from a GRPDEF record.
#[derive(Debug, Clone)]
pub struct ParsedGroup {
    /// 0-based index into OmfFile::lnames.
    #[allow(dead_code)]
    pub name_idx: u16,
    /// 1-based SEGDEF ordinals of all member segments, in encounter order.
    pub members: Vec<u16>,
}
