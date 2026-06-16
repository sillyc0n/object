use crate::read::{ComdatKind, Error, ObjectComdat, Result, SectionIndex, SymbolIndex};
use crate::ReadRef;

use super::*;

/// A COMDAT section group of an OMF file.
///
/// OMF does not have native COMDAT section groups. Instead, each COMDEF
/// (communal variable) entry is exposed as a synthetic COMDAT group with
/// zero associated sections. The COMDAT symbol is the communal variable
/// itself.
#[derive(Debug, Clone, Copy)]
pub struct OmfComdat<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) symbol: SymbolIndex,
    pub(super) kind: ComdatKind,
}

impl<'data, 'file, R: ReadRef<'data>> crate::read::private::Sealed for OmfComdat<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectComdat<'data> for OmfComdat<'data, 'file, R> {
    type SectionIterator = OmfComdatSectionIterator<'data, 'file, R>;

    fn kind(&self) -> ComdatKind {
        self.kind
    }

    fn symbol(&self) -> SymbolIndex {
        self.symbol
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        let sym = self
            .file
            .symbols
            .get(self.symbol.0)
            .ok_or(Error("Invalid COMDAT symbol index"))?;
        Ok(sym.name)
    }

    fn name(&self) -> Result<&'data str> {
        let bytes = self.name_bytes()?;
        core::str::from_utf8(bytes).map_err(|_| Error("non-UTF8 COMDAT symbol name"))
    }

    fn sections(&self) -> Self::SectionIterator {
        OmfComdatSectionIterator {
            file: self.file,
        }
    }
}

/// An iterator over the sections in a COMDAT section group of an OMF file.
///
/// COMDEF-based COMDAT groups have no associated sections (communal variables
/// live in common storage, not in a segment). This iterator is always empty.
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
pub struct OmfComdatIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) index: usize,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfComdatIterator<'data, 'file, R> {
    type Item = OmfComdat<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        let (sym, kind) = self.file.comdat_groups.get(self.index)?;
        self.index += 1;
        Some(OmfComdat {
            file: self.file,
            symbol: *sym,
            kind: *kind,
        })
    }
}
