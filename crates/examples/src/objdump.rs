use object::read::archive::ArchiveFile;
use object::read::coff;
use object::read::macho::{DyldCache, FatArch, MachOFatFile32, MachOFatFile64};
use object::{Endianness, FileKind, Object, ObjectComdat, ObjectSection, ObjectSymbol};
use std::io::{Result, Write};

pub fn print<W: Write, E: Write>(
    w: &mut W,
    e: &mut E,
    file: &[u8],
    extra_files: &[&[u8]],
    member_names: Vec<String>,
) -> Result<()> {
    let mut member_names: Vec<_> = member_names.into_iter().map(|name| (name, false)).collect();

    if let Ok(archive) = ArchiveFile::parse(file) {
        writeln!(w, "Format: Archive (kind: {:?})", archive.kind())?;
        for member in archive.members() {
            match member {
                Ok(member) => {
                    if find_member(&mut member_names, member.name()) {
                        writeln!(w)?;
                        writeln!(w, "{}:", String::from_utf8_lossy(member.name()))?;
                        if let Ok(data) = member.data(file) {
                            if FileKind::parse(data) == Ok(FileKind::CoffImport) {
                                dump_import(w, e, data)?;
                            } else {
                                dump_object(w, e, data)?;
                            }
                        }
                    }
                }
                Err(err) => writeln!(e, "Failed to parse archive member: {}", err)?,
            }
        }
    } else if let Ok(fat) = MachOFatFile32::parse(file) {
        writeln!(w, "Format: Mach-O Fat 32")?;
        for arch in fat.arches() {
            writeln!(w)?;
            writeln!(w, "Fat Arch: {:?}", arch.architecture())?;
            match arch.data(file) {
                Ok(data) => dump_object(w, e, data)?,
                Err(err) => writeln!(e, "Failed to parse Fat 32 data: {}", err)?,
            }
        }
    } else if let Ok(fat) = MachOFatFile64::parse(file) {
        writeln!(w, "Format: Mach-O Fat 64")?;
        for arch in fat.arches() {
            writeln!(w)?;
            writeln!(w, "Fat Arch: {:?}", arch.architecture())?;
            match arch.data(file) {
                Ok(data) => dump_object(w, e, data)?,
                Err(err) => writeln!(e, "Failed to parse Fat 64 data: {}", err)?,
            }
        }
    } else if let Ok(cache) = DyldCache::<Endianness>::parse(file, extra_files) {
        writeln!(w, "Format: dyld cache {:?}-endian", cache.endianness())?;
        writeln!(w, "Architecture: {:?}", cache.architecture())?;
        for image in cache.images() {
            let path = match image.path() {
                Ok(path) => path,
                Err(err) => {
                    writeln!(e, "Failed to parse dyld image name: {}", err)?;
                    continue;
                }
            };
            if !find_member(&mut member_names, path.as_bytes()) {
                continue;
            }
            writeln!(w)?;
            writeln!(w, "{}:", path)?;
            let file = match image.parse_object() {
                Ok(file) => file,
                Err(err) => {
                    writeln!(e, "Failed to parse file: {}", err)?;
                    continue;
                }
            };
            dump_parsed_object(w, e, &file)?;
        }
    } else {
        dump_object(w, e, file)?;
    }

    for (name, found) in member_names {
        if !found {
            writeln!(e, "Failed to find member '{}", name)?;
        }
    }
    Ok(())
}

fn find_member(member_names: &mut [(String, bool)], name: &[u8]) -> bool {
    if member_names.is_empty() {
        return true;
    }
    match member_names.iter().position(|x| x.0.as_bytes() == name) {
        Some(i) => {
            member_names[i].1 = true;
            true
        }
        None => false,
    }
}

fn dump_object<W: Write, E: Write>(w: &mut W, e: &mut E, data: &[u8]) -> Result<()> {
    match object::File::parse(data) {
        Ok(file) => {
            dump_parsed_object(w, e, &file)?;
        }
        Err(err) => {
            writeln!(e, "Failed to parse file: {}", err)?;
        }
    }
    Ok(())
}

fn dump_parsed_object<W: Write, E: Write>(w: &mut W, e: &mut E, file: &object::File) -> Result<()> {
    let bit_width = file
        .architecture()
        .address_size()
        .map(|s| (s.bytes() * 8).to_string())
        .unwrap_or_else(|| if file.is_64() { "64".into() } else { "32".into() });
    writeln!(
        w,
        "Format: {:?} {:?}-endian {}-bit",
        file.format(),
        file.endianness(),
        bit_width,
    )?;
    writeln!(w, "Kind: {:?}", file.kind())?;
    writeln!(w, "Architecture: {:?}", file.architecture())?;
    if let Some(sub_architecture) = file.sub_architecture() {
        writeln!(w, "Sub-Architecture: {:?}", sub_architecture)?;
    }
    writeln!(w, "Flags: {:x?}", file.flags())?;
    writeln!(
        w,
        "Relative Address Base: {:x?}",
        file.relative_address_base()
    )?;
    writeln!(w, "Entry Address: {:x?}", file.entry())?;

    if let object::File::Omf(omf) = file {
        dump_omf_details(w, e, omf)?;
    }

    match file.mach_uuid() {
        Ok(Some(uuid)) => writeln!(w, "Mach UUID: {:x?}", uuid)?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse Mach UUID: {}", err)?,
    }
    match file.build_id() {
        Ok(Some(build_id)) => writeln!(w, "Build ID: {:x?}", build_id)?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse build ID: {}", err)?,
    }
    match file.gnu_debuglink() {
        Ok(Some((filename, crc))) => writeln!(
            w,
            "GNU debug link: {} CRC: {:08x}",
            String::from_utf8_lossy(filename),
            crc,
        )?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse GNU debug link: {}", err)?,
    }
    match file.gnu_debugaltlink() {
        Ok(Some((filename, build_id))) => writeln!(
            w,
            "GNU debug alt link: {}, build ID: {:x?}",
            String::from_utf8_lossy(filename),
            build_id,
        )?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse GNU debug alt link: {}", err)?,
    }
    match file.pdb_info() {
        Ok(Some(info)) => writeln!(
            w,
            "PDB file: {}, GUID: {:x?}, Age: {}",
            String::from_utf8_lossy(info.path()),
            info.guid(),
            info.age()
        )?,
        Ok(None) => {}
        Err(err) => writeln!(e, "Failed to parse PE CodeView info: {}", err)?,
    }

    for segment in file.segments() {
        writeln!(w, "{:x?}", segment)?;
    }

    for section in file.sections() {
        writeln!(w, "{}: {:x?}", section.index(), section)?;
    }

    for comdat in file.comdats() {
        write!(w, "{:?} Sections:", comdat)?;
        for section in comdat.sections() {
            write!(w, " {}", section)?;
        }
        writeln!(w)?;
    }

    writeln!(w)?;
    writeln!(w, "Symbols")?;
    for symbol in file.symbols() {
        writeln!(w, "{}: {:x?}", symbol.index(), symbol)?;
    }

    for section in file.sections() {
        if section.relocations().next().is_some() {
            writeln!(
                w,
                "\n{} relocations",
                section.name().unwrap_or("<invalid name>")
            )?;
            for relocation in section.relocations() {
                writeln!(w, "{:x?}", relocation)?;
            }
        }
    }

    writeln!(w)?;
    writeln!(w, "Dynamic symbols")?;
    for symbol in file.dynamic_symbols() {
        writeln!(w, "{}: {:x?}", symbol.index(), symbol)?;
    }

    if let Some(relocations) = file.dynamic_relocations() {
        writeln!(w)?;
        writeln!(w, "Dynamic relocations")?;
        for relocation in relocations {
            writeln!(w, "{:x?}", relocation)?;
        }
    }

    match file.imports() {
        Ok(imports) => {
            if !imports.is_empty() {
                writeln!(w)?;
                for import in imports {
                    writeln!(w, "{:x?}", import)?;
                }
            }
        }
        Err(err) => writeln!(e, "Failed to parse imports: {}", err)?,
    }

    match file.exports() {
        Ok(exports) => {
            if !exports.is_empty() {
                writeln!(w)?;
                for export in exports {
                    writeln!(w, "{:x?}", export)?;
                }
            }
        }
        Err(err) => writeln!(e, "Failed to parse exports: {}", err)?,
    }

    writeln!(w)?;
    writeln!(w, "Symbol map")?;
    for symbol in file.symbol_map().symbols() {
        writeln!(
            w,
            "0x{:x}-0x{:x} \"{}\"",
            symbol.address(),
            symbol.address() + symbol.size(),
            symbol.name()
        )?;
    }

    Ok(())
}

fn dump_omf_details<W: Write, E: Write>(
    w: &mut W,
    _e: &mut E,
    file: &object::read::omf::OmfFile,
) -> Result<()> {
    writeln!(w, "\nOMF details:")?;
    for record in file.fixupp_records() {
        let seg_name = record.attached_seg_ordinal.and_then(|ord| {
            file.segments
                .get(ord as usize - 1)
                .and_then(|seg| file.lname(seg.name_idx))
        });
        writeln!(
            w,
            "FIXUPP record (attached to segment: {:?})",
            seg_name.map(String::from_utf8_lossy).unwrap_or_else(|| "none".into())
        )?;
        for sub in &record.subrecords {
            match sub {
                object::read::omf::ParsedFixuppSubrecord::Thread(t) => {
                    let kind_str = match t.kind {
                        object::read::omf::ThreadKind::Frame => "FRAME",
                        object::read::omf::ThreadKind::Target => "TARGET",
                    };
                    let method_name = match t.kind {
                        object::read::omf::ThreadKind::Frame => match t.method {
                            0 => "segment index",
                            1 => "group index",
                            2 => "external index",
                            4 => "segment containing LOCATION",
                            5 => "TARGET's segment/group/external index",
                            _ => "unknown",
                        },
                        object::read::omf::ThreadKind::Target => match t.method {
                            0 => "segment index",
                            1 => "group index",
                            2 => "external index",
                            _ => "unknown",
                        },
                    };
                    write!(
                        w,
                        "  THREAD {}[{}]: method={} ({})",
                        kind_str, t.thread_number, t.method, method_name
                    )?;
                    if let Some(datum) = t.datum {
                        let datum_name = match t.kind {
                            object::read::omf::ThreadKind::Frame => match t.method {
                                0 => file.segments.get(datum as usize - 1).and_then(|seg| file.lname(seg.name_idx)),
                                1 => file.groups.get(datum as usize - 1).and_then(|grp| file.lname(grp.name_idx)),
                                2 => file.extdef_symbol_index(datum).ok().and_then(|idx| file.symbols.get(idx.0)).map(|sym| sym.name),
                                _ => None,
                            },
                            object::read::omf::ThreadKind::Target => match t.method {
                                0 => file.segments.get(datum as usize - 1).and_then(|seg| file.lname(seg.name_idx)),
                                1 => file.groups.get(datum as usize - 1).and_then(|grp| file.lname(grp.name_idx)),
                                2 => file.extdef_symbol_index(datum).ok().and_then(|idx| file.symbols.get(idx.0)).map(|sym| sym.name),
                                _ => None,
                            },
                        };
                        write!(w, ", datum={}", datum)?;
                        if let Some(name) = datum_name {
                            write!(w, " -> {}", String::from_utf8_lossy(name))?;
                        }
                    } else {
                        write!(w, ", no datum")?;
                    }
                    writeln!(w)?;
                }
                object::read::omf::ParsedFixuppSubrecord::Fixup(f) => {
                    writeln!(
                        w,
                        "  FIXUP @{:04X}: M={} {} loc={}({}) fixdat={:02X}",
                        f.record_offset,
                        if f.is_seg_rel { 1 } else { 0 },
                        if f.is_seg_rel { "segment-relative" } else { "self-relative" },
                        f.loc_raw,
                        match f.loc_raw as u16 {
                            object::omf::LOC_BYTE => "byte",
                            object::omf::LOC_OFFSET => "offset",
                            object::omf::LOC_SEGMENT => "segment",
                            object::omf::LOC_POINTER => "pointer",
                            object::omf::LOC_HIGH_BYTE => "high-order byte",
                            object::omf::LOC_LOADER_OFFSET => "loader-resolved offset",
                            _ => "unknown",
                        },
                        f.fixdat
                    )?;

                    let frame_method_name = match f.frame_method {
                        0 => "segment index",
                        1 => "group index",
                        2 => "external index",
                        3 => "frame number",
                        4 => "segment containing LOCATION",
                        5 => "TARGET's segment/group/external index",
                        _ => "unknown",
                    };
                    if let Some(thread_num) = f.frame_thread {
                        write!(w, "    FRAME: thread FRAME[{}] -> ", thread_num)?;
                    } else {
                        write!(w, "    FRAME: explicit ")?;
                    }
                    write!(w, "method={} ({})", f.frame_method, frame_method_name)?;
                    if let Some(datum) = f.frame_datum {
                        let datum_name = match f.frame_method {
                            0 => file.segments.get(datum as usize - 1).and_then(|seg| file.lname(seg.name_idx)),
                            1 => file.groups.get(datum as usize - 1).and_then(|grp| file.lname(grp.name_idx)),
                            2 => file.extdef_symbol_index(datum).ok().and_then(|idx| file.symbols.get(idx.0)).map(|sym| sym.name),
                            _ => None,
                        };
                        write!(w, ", datum={}", datum)?;
                        if let Some(name) = datum_name {
                            write!(w, " -> {}", String::from_utf8_lossy(name))?;
                        }
                    } else if f.frame_method <= 2 {
                        write!(w, ", MISSING datum")?;
                    }
                    writeln!(w)?;

                    let target_method_name = match f.target_method {
                        0 => "segment index",
                        1 => "group index",
                        2 => "external index",
                        3 => "frame number",
                        4 => "segment index, no displacement",
                        5 => "group index, no displacement",
                        6 => "external index, no displacement",
                        _ => "unknown",
                    };
                    if let Some(thread_num) = f.target_thread {
                        write!(w, "    TARGET: thread TARGET[{}] -> effective ", thread_num)?;
                    } else {
                        write!(w, "    TARGET: explicit ")?;
                    }
                    write!(w, "method={} ({})", f.target_method, target_method_name)?;
                    let datum = f.target_datum;
                    let datum_name = match f.target_method & 0x03 {
                        0 => file.segments.get(datum as usize - 1).and_then(|seg| file.lname(seg.name_idx)),
                        1 => file.groups.get(datum as usize - 1).and_then(|grp| file.lname(grp.name_idx)),
                        2 => file.extdef_symbol_index(datum).ok().and_then(|idx| file.symbols.get(idx.0)).map(|sym| sym.name),
                        _ => None,
                    };
                    write!(w, ", datum={}", datum)?;
                    if let Some(name) = datum_name {
                        write!(w, " -> {}", String::from_utf8_lossy(name))?;
                    }
                    if let Some(disp) = f.target_displacement {
                        write!(w, ", displacement={:04X}", disp)?;
                    }
                    writeln!(w)?;
                }
            }
        }
    }
    Ok(())
}

fn dump_import<W: Write, E: Write>(w: &mut W, e: &mut E, data: &[u8]) -> Result<()> {
    let file = match coff::ImportFile::parse(data) {
        Ok(import) => import,
        Err(err) => {
            writeln!(e, "Failed to parse short import: {}", err)?;
            return Ok(());
        }
    };

    writeln!(w, "Format: Short Import File")?;
    writeln!(w, "Architecture: {:?}", file.architecture())?;
    if let Some(sub_architecture) = file.sub_architecture() {
        writeln!(w, "Sub-Architecture: {:?}", sub_architecture)?;
    }
    writeln!(w, "DLL: {:?}", String::from_utf8_lossy(file.dll()))?;
    writeln!(w, "Symbol: {:?}", String::from_utf8_lossy(file.symbol()))?;
    write!(w, "Import: ")?;
    match file.import() {
        coff::ImportName::Ordinal(n) => writeln!(w, "Ordinal({})", n)?,
        coff::ImportName::Name(name) => writeln!(w, "Name({:?})", String::from_utf8_lossy(name))?,
    }
    writeln!(w, "Type: {:?}", file.import_type())?;
    Ok(())
}
