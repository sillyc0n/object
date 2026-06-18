use alloc::string::String;
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
    /// Byte offset within the segment (32-bit to support PUBDEF32).
    pub offset: u32,
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

// ── COMDEF spec-level types ────────────────────────────────────────────────
//
// These types mirror the spec at COMDEF_B0H_Parser_Spec.md and are exposed
// as a standalone parser alongside the integrated ParsedComdefEntry type.

/// Error type for the standalone COMDEF parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComdefError {
    /// Unexpected end of input at the given offset.
    UnexpectedEof(usize),
    /// Record type byte is not 0xB0.
    WrongRecordType {
        /// The actual record type byte found.
        found: u8,
    },
    /// Communal length prefix byte is reserved/invalid.
    InvalidLengthPrefix(u8),
    /// Unknown data type byte.
    UnknownDataType(u8),
    /// Checksum mismatch.
    ChecksumMismatch {
        /// The computed checksum value.
        computed: u8,
        /// The stored checksum value from the record.
        stored: u8,
    },
}

/// A single communal variable entry from a COMDEF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComdefEntry {
    /// Variable name (empty string is valid).
    pub name: Vec<u8>,
    /// Raw type index (not inspected by linkers).
    pub type_index: u16,
    /// Placement and size encoding.
    pub communal: ComdefKind,
}

/// Size/placement description from the COMDEF Data Type + Length fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComdefKind {
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
}

/// A fully-parsed COMDEF record.
#[derive(Debug, Clone)]
pub struct ComdefRecord {
    /// Entries parsed from the record.
    pub entries: Vec<ComdefEntry>,
}

// ── PUBDEF spec-level types ────────────────────────────────────────────────
//
// These types mirror the spec at PUBDEF_90H_91H_Parser_Spec.md and are exposed
// as a standalone parser alongside the integrated parser in OmfFile.

/// Which PUBDEF variant this record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubdefKind {
    /// 0x90 — 16-bit Public Offset.
    Pubdef16,
    /// 0x91 — 32-bit Public Offset.
    Pubdef32,
}

/// The base addressing context, shared by all entries in the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubdefBase {
    /// Base Segment Index nonzero: segment-relative (most common).
    /// group_index may be 0 (no group) or nonzero.
    Segment {
        /// Index into the GRPDEF table; 0 = no group.
        group_index:   u16,
        /// Index into the SEGDEF table (nonzero).
        segment_index: u16,
    },
    /// Base Segment Index = 0: Base Frame field is present.
    /// When group_index is also 0, frame defines an absolute symbol.
    /// When group_index is nonzero, frame is present but ignored.
    Frame {
        /// Index into the GRPDEF table; 0 = no group.
        group_index: u16,
        /// Frame paragraph number (present only when segment_index == 0).
        frame:       u16,
    },
}

/// A single public name entry within a PUBDEF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubdefEntry {
    /// Public symbol name (1–255 bytes, non-empty).
    pub name:       String,
    /// Offset of the symbol within its base context.
    pub offset:     u32,
    /// Type index (0 = no type data).
    pub type_index: u16,
}

/// A fully-parsed PUBDEF or PUBDEF32 record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubdefRecord {
    /// Which variant (16-bit or 32-bit offset).
    pub kind:    PubdefKind,
    /// Base addressing context for all entries.
    pub base:    PubdefBase,
    /// The public name entries in this record.
    pub entries: Vec<PubdefEntry>,
}

/// Error type for the standalone PUBDEF parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubdefError {
    /// Unexpected end of input at the given offset.
    #[allow(dead_code)]
    UnexpectedEof(usize),
    /// Record type byte is not 0x90 or 0x91.
    WrongRecordType {
        /// The actual record type byte found.
        found: u8,
    },
    /// Public name has zero length.
    EmptyName(usize),
    /// Public name length exceeds maximum of 255.
    NameTooLong(usize),
    /// Invalid UTF-8 in public name.
    InvalidName,
    /// Checksum mismatch.
    ChecksumMismatch {
        /// The computed checksum value.
        computed: u8,
        /// The stored checksum value from the record.
        stored: u8,
    },
}

// ── LPUBDEF spec-level types ───────────────────────────────────────────────
//
// These types mirror the spec at LPUBDEF_B6H_B7H_spec.md and are exposed
// as a standalone parser.

/// Errors that can occur while parsing a B6H/B7H LPUBDEF record body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LpubdefParseError {
    /// `record_type` was neither 0xB6 nor 0xB7.
    InvalidRecordType(u8),
    /// Ran out of bytes while trying to read `expected` more, with only
    /// `remaining` left in the buffer.
    UnexpectedEof {
        /// Number of additional bytes needed.
        expected: usize,
        /// Number of bytes still available.
        remaining: usize,
    },
    /// The field area was fully consumed but `leftover` bytes remained —
    /// not enough to form another complete name entry.
    TrailingBytes {
        /// Number of leftover bytes.
        leftover: usize,
    },
    /// String Length was 0; LPUBDEF names must be non-empty.
    EmptyName,
}

/// Whether this record carries 16-bit or 32-bit Local Offset values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetWidth {
    /// Record type 0xB6.
    Bit16,
    /// Record type 0xB7.
    Bit32,
}

/// A decoded OMF variable-length index field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OmfIndex(pub u16);

impl OmfIndex {
    /// Returns true when the index is nonzero (i.e., present/valid).
    pub fn is_present(self) -> bool {
        self.0 != 0
    }
}

/// One symbol defined inside an LPUBDEF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPublicName {
    /// Raw name bytes (OMF doesn't guarantee an encoding).
    pub name: Vec<u8>,
    /// Always widened to u32 regardless of source width.
    pub offset: u32,
    /// Type index (variable-width OMF index).
    pub type_index: OmfIndex,
}

/// A fully decoded B6H/B7H LPUBDEF record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpubdefRecord {
    /// Whether offsets are 16-bit or 32-bit.
    pub offset_width: OffsetWidth,
    /// Base Group Index (0 = absent).
    pub base_group: OmfIndex,
    /// Base Segment Index (0 → absolute / Base Frame follows).
    pub base_segment: OmfIndex,
    /// `Some` only when `base_segment` decoded to 0.
    pub base_frame: Option<u16>,
    /// The local public name entries.
    pub names: Vec<LocalPublicName>,
    /// The raw checksum byte from the record.
    pub checksum: u8,
}

// ── COMDAT types ───────────────────────────────────────────────────────────

/// Which COMDAT variant (0xC2 vs 0xC3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CombatKind {
    /// 0xC2 — 16-bit Enumerated Data Offset.
    Comdat16,
    /// 0xC3 — 32-bit Enumerated Data Offset.
    Comdat32,
}

impl core::ops::BitOr for CombatFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for CombatFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

/// Flags byte for a COMDAT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CombatFlags(pub u8);

impl CombatFlags {
    /// Continuation — data continues a previous COMDAT for this symbol.
    pub const CONTINUATION: u8 = 0x01;
    /// Iterated Data — data field uses LIDATA nested-block format.
    pub const ITERATED_DATA: u8 = 0x02;
    /// Local — effectively an LCOMDAT (local communal).
    pub const LOCAL: u8 = 0x04;
    /// Data in Code — forces COMDAT into root text when overlaid.
    pub const DATA_IN_CODE: u8 = 0x08;

    /// Create from a raw byte, truncating reserved bits.
    pub fn from_bits_truncate(bits: u8) -> Self {
        Self(bits & 0x0F)
    }

    /// Returns true if the Continuation flag is set.
    pub fn is_continuation(self) -> bool {
        self.0 & Self::CONTINUATION != 0
    }

    /// Returns true if the Iterated Data flag is set.
    pub fn is_iterated(self) -> bool {
        self.0 & Self::ITERATED_DATA != 0
    }

    /// Returns true if the Local flag is set.
    pub fn is_local(self) -> bool {
        self.0 & Self::LOCAL != 0
    }

    /// Returns true if the Data in Code flag is set.
    pub fn is_data_in_code(self) -> bool {
        self.0 & Self::DATA_IN_CODE != 0
    }
}

/// Selection criteria for COMDAT (high nibble of Attributes byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SelectionCriteria {
    /// Only one instance allowed.
    NoMatch    = 0x0,
    /// Any instance may be selected.
    PickAny    = 0x1,
    /// All instances must have the same length.
    SameSize   = 0x2,
    /// All instances must have identical checksums.
    ExactMatch = 0x3,
}

impl SelectionCriteria {
    /// Parse from a nibble value (0x0–0xF). Returns None for reserved values.
    pub fn from_nibble(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x0 => Some(Self::NoMatch),
            0x1 => Some(Self::PickAny),
            0x2 => Some(Self::SameSize),
            0x3 => Some(Self::ExactMatch),
            _   => None,
        }
    }
}

/// Allocation type for COMDAT (low nibble of Attributes byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AllocationType {
    /// Explicit — allocate in the segment specified by Public Base.
    Explicit = 0x0,
    /// Far Code — allocate as CODE16, linker creates segments automatically.
    FarCode  = 0x1,
    /// Far Data — allocate as DATA16, linker creates segments automatically.
    FarData  = 0x2,
    /// Code32 — allocate as CODE32.
    Code32   = 0x3,
    /// Data32 — allocate as DATA32.
    Data32   = 0x4,
}

impl AllocationType {
    /// Parse from a nibble value (0x0–0xF). Returns None for reserved values.
    pub fn from_nibble(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x0 => Some(Self::Explicit),
            0x1 => Some(Self::FarCode),
            0x2 => Some(Self::FarData),
            0x3 => Some(Self::Code32),
            0x4 => Some(Self::Data32),
            _   => None,
        }
    }

    /// Whether the Public Base field is present for this allocation type.
    pub fn has_public_base(self) -> bool {
        matches!(self, Self::Explicit)
    }
}

/// COMDAT alignment code (from the Align byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CombatAlign {
    /// Use value from the associated SEGDEF.
    UseSegdef  = 0,
    /// Byte aligned.
    Byte       = 1,
    /// Word (2-byte) aligned.
    Word       = 2,
    /// Paragraph (16-byte) aligned.
    Paragraph  = 3,
    /// Page aligned (Intel: 256 B; IBM OMF: 4096 B).
    Page       = 4,
    /// Double word (4-byte) aligned.
    DoubleWord = 5,
}

impl CombatAlign {
    /// Parse from a u8 value, masking to the low 3 bits.
    pub fn from_u8(v: u8) -> Self {
        match v & 0x07 {
            0 => Self::UseSegdef,
            1 => Self::Byte,
            2 => Self::Word,
            3 => Self::Paragraph,
            4 => Self::Page,
            5 => Self::DoubleWord,
            _ => Self::UseSegdef,
        }
    }
}

/// Decoded Attributes byte for a COMDAT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CombatAttributes {
    /// Selection criteria (high nibble).
    pub selection: SelectionCriteria,
    /// Allocation type (low nibble).
    pub allocation: AllocationType,
}

/// Segment base for the Public Base field of a COMDAT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentBase {
    /// Nonzero index into the SEGDEF table (1-based).
    Segment(u16),
    /// Absolute segment: frame number when segment index = 0.
    Absolute {
        /// Frame number (paragraph-aligned base address).
        frame: u16,
    },
}

/// Public Base field for a COMDAT record (present only when Allocation = Explicit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBase {
    /// Index into GRPDEF table; 0 = no group.
    pub group_index: u16,
    /// The segment base (segment ordinal or absolute frame).
    pub segment: SegmentBase,
}

/// Public Name encoding for a COMDAT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicName {
    /// Microsoft LINK: OMF index into LNAMES/LLNAMES.
    Index(u16),
    /// IBM LINK386: length-prefixed name string.
    Name(Vec<u8>),
}

/// Which Public Name encoding to use when parsing COMDAT records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicNameEncoding {
    /// Microsoft LINK: OMF index (1 or 2 bytes).
    MicrosoftIndex,
    /// IBM LINK386: length-prefixed string.
    IbmString,
}

/// A fully-parsed COMDAT or COMDAT32 record.
#[derive(Debug, Clone)]
pub struct CombatRecord {
    /// Which variant (16-bit or 32-bit offset).
    pub kind: CombatKind,
    /// Flags byte.
    pub flags: CombatFlags,
    /// Attributes (selection + allocation).
    pub attributes: CombatAttributes,
    /// Alignment.
    pub align: CombatAlign,
    /// Byte offset from start of COMDAT symbol to first data byte.
    pub data_offset: u32,
    /// Type index (0 = none).
    pub type_index: u16,
    /// Public Base, present only when Allocation is Explicit.
    pub public_base: Option<PublicBase>,
    /// Public Name identifying the communal symbol.
    pub public_name: PublicName,
    /// Raw data bytes (0–1024). Enumerated or iterated per flags.
    pub data: Vec<u8>,
    /// Relocations attached to this COMDAT's data (from subsequent FIXUPP).
    pub relocs: Vec<ParsedReloc>,
}

/// Error type for the standalone COMDAT parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CombatError {
    /// Unexpected end of input at the given offset.
    UnexpectedEof(usize),
    /// Record type byte is not 0xC2 or 0xC3.
    WrongRecordType {
        /// The actual record type byte found.
        found: u8,
    },
    /// Reserved Selection Criteria value.
    ReservedSelectionCriteria(u8),
    /// Reserved Allocation Type value.
    ReservedAllocationType(u8),
    /// Data payload length exceeds maximum of 1024 bytes.
    DataTooLong(usize),
    /// Checksum mismatch.
    ChecksumMismatch {
        /// The computed checksum value.
        computed: u8,
        /// The stored checksum value from the record.
        stored: u8,
    },
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
