use anyhow::{bail, Result};
use goblin::Object;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub data: Vec<u8>,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
}

#[derive(Debug)]
pub struct LoadedBinary {
    pub arch: Arch,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub imports: Vec<Symbol>,
}

impl LoadedBinary {
    pub fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        for sec in &self.sections {
            let start = sec.virtual_address;
            let end = start + sec.data.len() as u64;
            if addr >= start && addr + len as u64 <= end {
                let off = (addr - start) as usize;
                return Some(&sec.data[off..off + len]);
            }
        }
        None
    }

    pub fn bytes_from(&self, addr: u64) -> Option<&[u8]> {
        for sec in &self.sections {
            let start = sec.virtual_address;
            let end = start + sec.data.len() as u64;
            if addr >= start && addr < end {
                let off = (addr - start) as usize;
                return Some(&sec.data[off..]);
            }
        }
        None
    }

    pub fn exec_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.executable)
    }

    pub fn symbol_map(&self) -> HashMap<u64, &Symbol> {
        self.symbols.iter().map(|s| (s.address, s)).collect()
    }
}

pub fn load(data: &[u8]) -> Result<LoadedBinary> {
    match Object::parse(data)? {
        Object::Elf(elf) => load_elf(elf, data),
        Object::PE(pe) => load_pe(pe, data),
        _ => bail!("Unsupported binary format (only ELF and PE supported)"),
    }
}

fn load_elf(elf: goblin::elf::Elf, data: &[u8]) -> Result<LoadedBinary> {
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_386 => Arch::X86,
        goblin::elf::header::EM_X86_64 => Arch::X86_64,
        m => bail!("Unsupported ELF machine type: {}", m),
    };

    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        if sh.sh_type == goblin::elf::section_header::SHT_PROGBITS && sh.sh_size > 0 {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_string();
            let off = sh.sh_offset as usize;
            let sz = sh.sh_size as usize;
            if off + sz <= data.len() {
                let executable =
                    sh.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0;
                sections.push(Section {
                    name,
                    virtual_address: sh.sh_addr,
                    data: data[off..off + sz].to_vec(),
                    executable,
                });
            }
        }
    }

    let mut symbols: Vec<Symbol> = Vec::new();
    for sym in &elf.syms {
        if sym.st_value != 0 {
            let name = elf
                .strtab
                .get_at(sym.st_name)
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                symbols.push(Symbol {
                    name,
                    address: sym.st_value,
                    size: sym.st_size,
                });
            }
        }
    }

    let mut imports: Vec<Symbol> = Vec::new();
    for sym in &elf.dynsyms {
        let name = elf
            .dynstrtab
            .get_at(sym.st_name)
            .unwrap_or("")
            .to_string();
        if !name.is_empty() {
            imports.push(Symbol {
                name,
                address: sym.st_value,
                size: sym.st_size,
            });
        }
    }

    Ok(LoadedBinary {
        arch,
        entry_point: elf.header.e_entry,
        sections,
        symbols,
        imports,
    })
}

fn load_pe(pe: goblin::pe::PE, data: &[u8]) -> Result<LoadedBinary> {
    let arch = if pe.is_64 { Arch::X86_64 } else { Arch::X86 };
    let image_base = pe.image_base as u64;

    let mut sections = Vec::new();
    for sec in &pe.sections {
        let name = std::str::from_utf8(&sec.name)
            .unwrap_or("")
            .trim_matches('\0')
            .to_string();
        let va = sec.virtual_address as u64 + image_base;
        let off = sec.pointer_to_raw_data as usize;
        let sz = sec.size_of_raw_data as usize;
        if sz > 0 && off + sz <= data.len() {
            use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;
            let executable = sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
            sections.push(Section {
                name,
                virtual_address: va,
                data: data[off..off + sz].to_vec(),
                executable,
            });
        }
    }

    let mut symbols: Vec<Symbol> = Vec::new();
    for (_, exp) in pe.exports.iter().enumerate() {
        if let Some(name) = exp.name {
            let rva = exp.rva;
            symbols.push(Symbol {
                name: name.to_string(),
                address: image_base + rva as u64,
                size: 0,
            });
        }
    }

    let imports: Vec<Symbol> = pe
        .imports
        .iter()
        .map(|imp| Symbol {
            name: imp.name.to_string(),
            address: image_base + imp.rva as u64,
            size: 0,
        })
        .collect();

    let entry = image_base + pe.entry as u64;
    Ok(LoadedBinary {
        arch,
        entry_point: entry,
        sections,
        symbols,
        imports,
    })
}
