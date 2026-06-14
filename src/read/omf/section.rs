use alloc::slice;
use core::str;
use core::marker::PhantomData;

use crate::read::{
    self, Error, ObjectSection, ObjectSegment, Result, SectionFlags, SectionIndex,
    SectionKind, SegmentFlags, Permissions, CompressedData, CompressedFileRange, RelocationMap,
};
use crate::ReadRef;

use super::*;

fn omf_class_to_section_kind(class: &[u8]) -> SectionKind {
    match class {
        b"CODE" | b"FAR_CODE" => SectionKind::Text,
        b"DATA" | b"FAR_DATA" => SectionKind::Data,
        b"BSS" => SectionKind::UninitializedData,
        b"STACK" => SectionKind::Data,
        _ => SectionKind::Unknown,
    }
}

/// A section of an OMF file.
#[derive(Debug, Clone, Copy)]
pub struct OmfSection<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) seg: &'file ParsedSegment<'data>,
    pub(super) index: SectionIndex,
}

impl<'data, 'file, R: ReadRef<'data>> OmfSection<'data, 'file, R> {
    fn bytes(&self) -> &'data [u8] {
        // Safety: the ParsedSegment is owned by OmfFile, which must outlive this OmfSection.
        // The Object trait expects data to have the 'data lifetime.
        unsafe { core::mem::transmute(self.seg.data.as_slice()) }
    }
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSection<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSection<'data> for OmfSection<'data, 'file, R> {
    type RelocationIterator = OmfRelocationIterator<'data, 'file, R>;

    fn index(&self) -> SectionIndex {
        self.index
    }

    fn address(&self) -> u64 {
        self.seg.flat_base
    }

    fn size(&self) -> u64 {
        if self.seg.big {
            0x10000
        } else {
            self.seg.length as u64
        }
    }

    fn align(&self) -> u64 {
        self.seg.alignment as u64
    }

    fn file_range(&self) -> Option<(u64, u64)> {
        None
    }

    fn data(&self) -> Result<&'data [u8]> {
        Ok(self.bytes())
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        let base = ObjectSection::address(self);
        if address < base {
            return Ok(None);
        }
        let start = (address - base) as usize;
        let data = self.bytes();
        let end = start.checked_add(size as usize).filter(|&e| e <= data.len());
        Ok(end.map(|e| &data[start..e]))
    }

    fn compressed_file_range(&self) -> Result<CompressedFileRange> {
        Ok(CompressedFileRange::none(None))
    }

    fn compressed_data(&self) -> Result<CompressedData<'data>> {
        Ok(CompressedData::none(self.bytes()))
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        if self.seg.name_idx == u16::MAX {
            return Ok(b"");
        }
        Ok(self.file.lnames.get(self.seg.name_idx as usize).copied().unwrap_or(b""))
    }

    fn name(&self) -> Result<&'data str> {
        let bytes = self.name_bytes()?;
        str::from_utf8(bytes).map_err(|_| Error("non-UTF8 section name"))
    }

    fn segment_name_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(None)
    }

    fn segment_name(&self) -> Result<Option<&str>> {
        Ok(None)
    }

    fn kind(&self) -> SectionKind {
        let class = if self.seg.class_idx == u16::MAX {
            b"".as_slice()
        } else {
            self.file.lnames.get(self.seg.class_idx as usize).copied().unwrap_or(b"")
        };
        omf_class_to_section_kind(class)
    }

    fn relocations(&self) -> Self::RelocationIterator {
        OmfRelocationIterator {
            file: self.file,
            relocs: self.seg.relocs.iter(),
            marker: PhantomData,
        }
    }

    fn relocation_map(&self) -> Result<RelocationMap> {
        RelocationMap::new(self.file, self)
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags::None
    }
}

/// An iterator over the sections of an OMF file.
#[derive(Debug)]
pub struct OmfSectionIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) iter: core::iter::Enumerate<slice::Iter<'file, ParsedSegment<'data>>>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSectionIterator<'data, 'file, R> {
    type Item = OmfSection<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(i, seg)| OmfSection {
            file: self.file,
            seg,
            index: SectionIndex(i),
        })
    }
}

/// A segment of an OMF file.
#[derive(Debug, Clone, Copy)]
pub struct OmfSegment<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) seg: &'file ParsedSegment<'data>,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSegment<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSegment<'data> for OmfSegment<'data, 'file, R> {
    fn address(&self) -> u64 {
        self.seg.flat_base
    }

    fn size(&self) -> u64 {
        if self.seg.big {
            0x10000
        } else {
            self.seg.length as u64
        }
    }

    fn align(&self) -> u64 {
        self.seg.alignment as u64
    }

    fn file_range(&self) -> (u64, u64) {
        (0, 0)
    }

    fn data(&self) -> Result<&'data [u8]> {
        // Safety: same as OmfSection::bytes()
        Ok(unsafe { core::mem::transmute(self.seg.data.as_slice()) })
    }

    fn data_range(&self, address: u64, size: u64) -> Result<Option<&'data [u8]>> {
        let base = ObjectSegment::address(self);
        if address < base {
            return Ok(None);
        }
        let start = (address - base) as usize;
        let data = self.data()?;
        let end = start.checked_add(size as usize).filter(|&e| e <= data.len());
        Ok(end.map(|e| &data[start..e]))
    }

    fn name_bytes(&self) -> Result<Option<&[u8]>> {
        if self.seg.name_idx == u16::MAX {
            return Ok(None);
        }
        Ok(self.file.lnames.get(self.seg.name_idx as usize).copied())
    }

    fn name(&self) -> Result<Option<&str>> {
        if let Some(bytes) = self.name_bytes()? {
            Ok(Some(str::from_utf8(bytes).map_err(|_| Error("non-UTF8 segment name"))?))
        } else {
            Ok(None)
        }
    }

    fn flags(&self) -> SegmentFlags {
        SegmentFlags::None
    }

    fn permissions(&self) -> Permissions {
        let class = if self.seg.class_idx == u16::MAX {
            b"".as_slice()
        } else {
            self.file.lnames.get(self.seg.class_idx as usize).copied().unwrap_or(b"")
        };
        match omf_class_to_section_kind(class) {
            SectionKind::Text => Permissions::new(true, false, true),  // R-X
            _ => Permissions::new(true, true, false),                   // RW-
        }
    }
}

/// An iterator over the segments of an OMF file.
#[derive(Debug)]
pub struct OmfSegmentIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) iter: core::iter::Enumerate<slice::Iter<'file, ParsedSegment<'data>>>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSegmentIterator<'data, 'file, R> {
    type Item = OmfSegment<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(_, seg)| OmfSegment {
            file: self.file,
            seg,
        })
    }
}
