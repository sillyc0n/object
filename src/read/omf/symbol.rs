use alloc::slice;
use core::str;

use crate::read::{
    self, Error, ObjectSymbol, ObjectSymbolTable, Result, SectionIndex, SymbolFlags, SymbolIndex,
    SymbolKind, SymbolScope, SymbolSection,
};
use crate::ReadRef;

use super::*;

/// A symbol of an OMF file.
#[derive(Debug, Clone, Copy)]
pub struct OmfSymbol<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) sym: &'file ParsedSymbol<'data>,
    pub(super) index: SymbolIndex,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSymbol<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSymbol<'data> for OmfSymbol<'data, 'file, R> {
    fn index(&self) -> SymbolIndex {
        self.index
    }

    fn name_bytes(&self) -> Result<&'data [u8]> {
        Ok(self.sym.name)
    }

    fn name(&self) -> Result<&'data str> {
        let bytes = self.name_bytes()?;
        str::from_utf8(bytes).map_err(|_| Error("non-UTF8 symbol name"))
    }

    fn address(&self) -> u64 {
        match self.sym.kind {
            ParsedSymbolKind::Public => {
                if self.sym.seg_ordinal == 0 {
                    return 0;
                }
                self.file.flat_base(self.sym.seg_ordinal) + self.sym.offset as u64
            }
            _ => 0,
        }
    }

    fn size(&self) -> u64 {
        0
    }

    fn kind(&self) -> SymbolKind {
        match self.sym.kind {
            ParsedSymbolKind::Public => SymbolKind::Label,
            ParsedSymbolKind::External => SymbolKind::Unknown,
            ParsedSymbolKind::Communal => SymbolKind::Data,
        }
    }

    fn section(&self) -> SymbolSection {
        match self.sym.kind {
            ParsedSymbolKind::Public => {
                if self.sym.seg_ordinal == 0 {
                    SymbolSection::Absolute
                } else {
                    SymbolSection::Section(SectionIndex(self.sym.seg_ordinal as usize - 1))
                }
            }
            ParsedSymbolKind::External => SymbolSection::Undefined,
            ParsedSymbolKind::Communal => SymbolSection::Common,
        }
    }

    fn is_undefined(&self) -> bool {
        self.sym.kind == ParsedSymbolKind::External
    }

    fn is_definition(&self) -> bool {
        self.sym.kind == ParsedSymbolKind::Public
    }

    fn is_common(&self) -> bool {
        self.sym.kind == ParsedSymbolKind::Communal
    }

    fn is_weak(&self) -> bool {
        false
    }

    fn is_global(&self) -> bool {
        true
    }

    fn is_local(&self) -> bool {
        false
    }

    fn scope(&self) -> SymbolScope {
        SymbolScope::Linkage
    }

    fn flags(&self) -> SymbolFlags<SectionIndex, SymbolIndex> {
        SymbolFlags::None
    }
}

/// An iterator over the symbols of an OMF file.
#[derive(Debug)]
pub struct OmfSymbolIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) iter: core::iter::Enumerate<slice::Iter<'file, ParsedSymbol<'data>>>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfSymbolIterator<'data, 'file, R> {
    type Item = OmfSymbol<'data, 'file, R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(i, sym)| OmfSymbol {
            file: self.file,
            sym,
            index: SymbolIndex(i),
        })
    }
}

/// A symbol table of an OMF file.
#[derive(Debug, Clone, Copy)]
pub struct OmfSymbolTable<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
}

impl<'data, 'file, R: ReadRef<'data>> read::private::Sealed for OmfSymbolTable<'data, 'file, R> {}

impl<'data, 'file, R: ReadRef<'data>> ObjectSymbolTable<'data> for OmfSymbolTable<'data, 'file, R> {
    type Symbol = OmfSymbol<'data, 'file, R>;
    type SymbolIterator = OmfSymbolIterator<'data, 'file, R>;

    fn symbols(&self) -> Self::SymbolIterator {
        OmfSymbolIterator {
            file: self.file,
            iter: self.file.symbols.iter().enumerate(),
        }
    }

    fn symbol_by_index(&self, index: SymbolIndex) -> Result<Self::Symbol> {
        self.file
            .symbols
            .get(index.0)
            .map(|sym| OmfSymbol {
                file: self.file,
                sym,
                index,
            })
            .ok_or(Error("Invalid OMF symbol index"))
    }
}
