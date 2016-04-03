#![feature(custom_derive, question_mark)]
#![no_std]

#![crate_name = "elfloader"]
#![crate_type = "lib"]

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod elf;
use core::fmt;
use core::mem::size_of;

pub type PAddr = u64;
pub type VAddr = usize;

#[derive(Debug)]
pub struct Error;

macro_rules! error {
    () => ({
        Err(Error)
    })
}

pub trait DataHeader {
    fn data<'s, 'i>(&'s self, image: &'i Image<'s>) -> &'s [u8];
}

impl DataHeader for elf::SectionHeader {
    fn data<'s, 'i>(&'s self, image: &'i Image<'s>) -> &'s [u8] {
        &image.region[(self.offset as usize)..(self.offset as usize + self.size as usize)]
    }
}

impl DataHeader for elf::ProgramHeader {
    fn data<'s, 'i>(&'s self, image: &'i Image<'s>) -> &'s [u8] {
        &image.region[(self.offset as usize)..(self.offset as usize + self.filesz as usize)]
    }
}

pub struct Image<'s> {
    pub header: Option<&'s elf::FileHeader>,
    pub segments: &'s [elf::ProgramHeader],
    pub sections: &'s [elf::SectionHeader],
    pub region: &'s [u8],
    pub shstrtab: &'s elf::SectionHeader,
}

impl<'s> fmt::Debug for Image<'s> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "header: {:?}", self.header)
    }
}

// T must be a POD for this to be safe
unsafe fn slice_pod<T>(region: &[u8], offset: usize, count: usize) -> Result<&[T], Error> {
    if region.len() - offset < count * size_of::<T>() {
        return error!();
    }
    Ok(core::slice::from_raw_parts(region[offset..].as_ptr() as *const T, count))
}

pub fn get_headers<'s, T>(region: &'s [u8], offset: u64, num: u16, entry_size: u16, zero: bool) -> Result<&'s [T], Error> {
    if offset == 0 && zero {
        return Ok(&[]);
    }
    if entry_size as usize != size_of::<T>() {
        return error!();
    }
    unsafe {
        slice_pod(region, offset as usize, num as usize)
    }
}

impl<'s> Image<'s> {
    /// Create a new Image.
    pub fn new(region: &'s [u8]) -> Result<Image<'s>, Error> {
        let header: &elf::FileHeader = unsafe { &slice_pod(region, 0, 1)?[0] };
        if header.ident.magic != elf::ELF_MAGIC {
            return error!();
        }
        let sections = get_headers(region, header.shoff, header.shnum, header.shentsize, true)?;
        let segments = get_headers(region, header.phoff, header.phnum, header.phentsize, true)?;

        Ok(Image {
            region: region,
            header: Some(header),
            segments: segments,
            sections: sections,
            shstrtab: &sections[header.shstrndx as usize],
        })
    }

    pub fn new_sections(region: &'s [u8], offset: u64, num: u16, entry_size: u16, strtab: u16) -> Result<Image<'s>, Error> {
        let sections = get_headers(region, offset, num, entry_size, false)?;

        Ok(Image {
            region: region,
            header: None,
            segments: &[],
            sections: sections,
            shstrtab: &sections[strtab as usize],
        })
    }

    // Get the string at offset str_offset in the string table strtab
    fn strtab_str(&self, strtab: &'s elf::SectionHeader, str_offset: elf::StrOffset) -> Result<&'s str, Error> {
        if strtab.shtype != elf::SHT_STRTAB {
            return error!();
        }
        let data = strtab.data(self);
        let offset = str_offset.0 as usize;
        let mut end = offset;
        while data[end] != 0 {
            end += 1;
        }
        Ok(core::str::from_utf8(&data[offset..end]).unwrap())
    }

    // Get the name of the section
    pub fn symbol_name(&self, symbol: &'s elf::Symbol, owner: &'s elf::SectionHeader) -> Result<&'s str, Error> {
        let strtab = &self.sections[owner.link as usize];
        self.strtab_str(strtab, symbol.name)
    }

    // Get the name of the section
    pub fn section_name(&self, section: &'s elf::SectionHeader) -> Result<&'s str, Error> {
        self.strtab_str(self.shstrtab, section.name)
    }

    // Get the symbols of the section
    fn section_symbols(&self, section: &'s elf::SectionHeader) -> Result<&'s [elf::Symbol], Error> {
        assert!(section.shtype == elf::SHT_SYMTAB);
        unsafe {
            slice_pod(section.data(self), 0, section.size as usize / size_of::<elf::Symbol>())
        }
    }

    pub fn find_symbol<F: FnMut(&'s elf::Symbol, &'s elf::SectionHeader) -> bool> (&self, mut func: F) -> Option<(&'s elf::Symbol, &'s elf::SectionHeader)> {
        for section in self.sections {
            if section.shtype != elf::SHT_SYMTAB {
                continue;
            }
            for symbol in self.section_symbols(section).unwrap() {
                if func(symbol, section) {
                    return Some((symbol, section));
                }
            }
        }
        None
    }

    // Enumerate all the symbols in the file
    pub fn for_each_symbol<F: FnMut(&'s elf::Symbol, &'s elf::SectionHeader)> (&self, mut func: F) {
        self.find_symbol(|s, h| { func(s, h); false });
    }

    /// Can we load the binary on our platform?
    fn can_load(&self) -> Result<bool, Error> {
        let header = self.header.ok_or(Error)?;
        let correct_class = header.ident.class == elf::ELFCLASS64;
        let correct_elfversion = header.ident.version == elf::EV_CURRENT;
        let correct_data = header.ident.data == elf::ELFDATA2LSB;
        let correct_osabi = header.ident.osabi == elf::ELFOSABI_SYSV || header.ident.osabi == elf::ELFOSABI_LINUX;
        let correct_type = header.elftype == elf::ET_EXEC || header.elftype == elf::ET_DYN;
        let correct_machine = header.machine == elf::EM_X86_64;

        Ok(correct_class &&
           correct_data &&
           correct_elfversion &&
           correct_machine &&
           correct_osabi &&
           correct_type)
    }

    pub fn load<L>(&self, loader: L) -> Result<(), ()>
            where L: Fn(&'s elf::ProgramHeader, &'s [u8]) -> Result<(), ()> {
        for p in self.segments {
            let x = match p.progtype {
                elf::PT_LOAD => try!(loader(p, p.data(self))),
                _ => ()
            };
        }

        Ok(())
    }
}
