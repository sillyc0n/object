use crate::read::{ObjectComdat, Result, SectionIndex};
use crate::ReadRef;

use super::*;

/// A COMDAT section group of an OMF file.
#[derive(Debug, Clone, Copy)]
pub struct OmfComdat<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    #[allow(unused)]
    pub(super) file: &'file OmfFile<'data, R>,
}

impl<'data, 'file, R: ReadRef<'data>> crate::read::private::Sealed for OmfComdat<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectComdat<'data> for OmfComdat<'data, 'file, R> {
    type SectionIterator = OmfComdatSectionIterator<'data, 'file, R>;

    fn kind(&self) -> crate::read::ComdatKind {
        crate::read::ComdatKind::Unknown
    }

    fn symbol(&self) -> crate::read::SymbolIndex {
        crate::read::SymbolIndex(0)
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        Ok(b"")
    }

    fn name(&self) -> Result<&'data str> {
        Ok("")
    }

    fn sections(&self) -> Self::SectionIterator {
        OmfComdatSectionIterator {
            #[allow(unused)]
            file: self.file,
        }
    }
}

/// An iterator over the sections in a COMDAT section group of an OMF file.
#[derive(Debug)]
pub struct OmfComdatSectionIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    #[allow(unused)]
    pub(super) file: &'file OmfFile<'data, R>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatSectionIterator<'data, 'file, R> {
    type Item = SectionIndex;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// An iterator over the COMDAT section groups of an OMF file.
#[derive(Debug)]
pub struct OmfComdatIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    #[allow(unused)]
    pub(super) file: &'file OmfFile<'data, R>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatIterator<'data, 'file, R> {
    type Item = OmfComdat<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}
