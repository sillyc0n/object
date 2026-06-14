use core::marker::PhantomData;

use crate::omf;
use crate::read::{
    Relocation, RelocationEncoding, RelocationKind, RelocationTarget, SectionIndex, RelocationFlags,
};
use crate::ReadRef;

use super::*;

/// An iterator over the relocations of an OMF section.
#[derive(Debug)]
pub struct OmfRelocationIterator<'data, 'file, R: ReadRef<'data> = &'data [u8]> {
    pub(super) file: &'file OmfFile<'data, R>,
    pub(super) relocs: core::slice::Iter<'file, ParsedReloc>,
    pub(super) marker: PhantomData<&'data ()>,
}

impl<'data, 'file, R: ReadRef<'data>> Iterator for OmfRelocationIterator<'data, 'file, R> {
    type Item = (u64, Relocation);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let r = self.relocs.next()?;

            let size = match r.loc as u16 {
                omf::LOC_BYTE => 8,
                omf::LOC_OFFSET => 16,
                omf::LOC_SEGMENT => 16,
                omf::LOC_POINTER => 32,
                omf::LOC_HIGH_BYTE => 8,
                omf::LOC_LOADER_OFFSET => 16,
                _ => 16,
            };

            let (kind, encoding) = if r.is_seg_rel {
                (RelocationKind::Absolute, RelocationEncoding::Generic)
            } else {
                (RelocationKind::Relative, RelocationEncoding::Generic)
            };

            let target = match r.target {
                RelocTarget::Segment(ord) => {
                    RelocationTarget::Section(SectionIndex(ord as usize - 1))
                }
                RelocTarget::Group(ord) => {
                    let seg_ord = self
                        .file
                        .groups
                        .get(ord as usize - 1)
                        .and_then(|g| g.members.first())
                        .copied();
                    match seg_ord {
                        Some(s) => RelocationTarget::Section(SectionIndex(s as usize - 1)),
                        None => continue,
                    }
                }
                RelocTarget::External(ord) => {
                    match self.file.extdef_symbol_index(ord) {
                        Ok(sym) => RelocationTarget::Symbol(sym),
                        Err(_) => continue,
                    }
                }
            };

            return Some((
                r.offset as u64,
                Relocation {
                    kind,
                    encoding,
                    size,
                    target,
                    subtractor: None,
                    addend: r.displacement as i64,
                    implicit_addend: true,
                    flags: RelocationFlags::Generic {
                        kind,
                        encoding,
                        size,
                    },
                },
            ));
        }
    }
}
