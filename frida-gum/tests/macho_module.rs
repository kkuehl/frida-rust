//! Tests for [`MachoModule`] against a 64-bit Mach-O dylib assembled here byte by byte, so every
//! platform parses the same known input.
//!
//! The image has the same layout on disk as in memory (each segment's file offset is its VM
//! address, and `__TEXT` starts at zero), so the one buffer serves as a file and as a mapped image.

use frida_gum::{Gum, MachoModule};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
}

const LC_SYMTAB: u32 = 0x2;
const LC_ID_DYLIB: u32 = 0xd;
const LC_SEGMENT_64: u32 = 0x19;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;

const IMAGE_SIZE: usize = 0x3000;
const BINDS_OFFSET: u32 = 0x2000;
const EXPORTS_OFFSET: u32 = 0x2040;
const SYMBOLS_OFFSET: u32 = 0x2080;
const STRINGS_OFFSET: u32 = 0x20c0;

/// Binds `_imported` from the first dependency at `__DATA` + 8, with addend -2.
const BINDS: &[u8] = b"\x11\x40_imported\0\x51\x60\x7e\x71\x08\x90\x00";

/// An export trie with `_exported` at offset 0x400 and `_reexported` from the first dependency.
const EXPORTS: &[u8] =
    b"\x00\x02_exported\0\x1a_reexported\0\x1f\x03\x00\x80\x08\x00\x03\x08\x01\x00\x00";

const STRINGS: &[u8] = b"\0_exported\0_local\0";

/// A Mach-O image under construction: load commands are appended, everything else is put at a
/// file offset.
struct Image {
    bytes: Vec<u8>,
    commands_end: usize,
    command_count: u32,
}

impl Image {
    const HEADER_SIZE: usize = 32;

    fn new() -> Self {
        Self {
            bytes: vec![0; IMAGE_SIZE],
            commands_end: Self::HEADER_SIZE,
            command_count: 0,
        }
    }

    fn put(&mut self, offset: usize, bytes: &[u8]) {
        self.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn command(&mut self, command: u32, body: &[u8]) {
        let size = 8 + body.len();
        assert_eq!(
            size % 8,
            0,
            "a 64-bit load command is a multiple of 8 bytes"
        );
        self.put(self.commands_end, &command.to_le_bytes());
        self.put(self.commands_end + 4, &(size as u32).to_le_bytes());
        self.put(self.commands_end + 8, body);
        self.commands_end += size;
        self.command_count += 1;
    }

    /// A segment at `address` on disk and in memory, with at most one section.
    fn segment(&mut self, name: &str, address: u64, protection: u32, section: Option<Section>) {
        let mut body = Vec::new();
        body.extend(name16(name));
        for value in [address, 0x1000, address, 0x1000] {
            body.extend(value.to_le_bytes());
        }
        for value in [protection, protection, section.is_some() as u32, 0] {
            body.extend(value.to_le_bytes());
        }
        if let Some(section) = section {
            body.extend(name16(section.name));
            body.extend(name16(name));
            body.extend(section.address.to_le_bytes());
            body.extend(section.size.to_le_bytes());
            for value in [section.address as u32, 0, 0, 0, section.flags, 0, 0, 0] {
                body.extend(value.to_le_bytes());
            }
        }
        self.command(LC_SEGMENT_64, &body);
    }

    fn finish(mut self) -> Vec<u8> {
        const MH_MAGIC_64: u32 = 0xfeed_facf;
        const CPU_TYPE_X86_64: u32 = 0x0100_0007;
        const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
        const MH_DYLIB: u32 = 6;

        let commands_size = (self.commands_end - Self::HEADER_SIZE) as u32;
        for (i, value) in [
            MH_MAGIC_64,
            CPU_TYPE_X86_64,
            CPU_SUBTYPE_X86_64_ALL,
            MH_DYLIB,
            self.command_count,
            commands_size,
        ]
        .into_iter()
        .enumerate()
        {
            self.put(i * 4, &value.to_le_bytes());
        }
        self.bytes
    }
}

struct Section {
    name: &'static str,
    address: u64,
    size: u64,
    flags: u32,
}

fn name16(name: &str) -> [u8; 16] {
    let mut field = [0; 16];
    field[..name.len()].copy_from_slice(name.as_bytes());
    field
}

fn u32s(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn image() -> Vec<u8> {
    const VM_PROT_READ: u32 = 1;
    const VM_PROT_WRITE: u32 = 2;
    const VM_PROT_EXECUTE: u32 = 4;
    const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;

    let mut image = Image::new();

    image.segment(
        "__TEXT",
        0,
        VM_PROT_READ | VM_PROT_EXECUTE,
        Some(Section {
            name: "__text",
            address: 0x400,
            size: 0x10,
            flags: S_ATTR_PURE_INSTRUCTIONS,
        }),
    );
    image.segment(
        "__DATA",
        0x1000,
        VM_PROT_READ | VM_PROT_WRITE,
        Some(Section {
            name: "__data",
            address: 0x1000,
            size: 0x20,
            flags: 0,
        }),
    );
    image.segment("__LINKEDIT", 0x2000, VM_PROT_READ, None);

    let mut id = u32s(&[24, 0, 0x1_0000, 0x1_0000]);
    id.extend(b"libsynthetic.dylib\0\0\0\0\0\0");
    image.command(LC_ID_DYLIB, &id);

    image.command(
        LC_DYLD_INFO_ONLY,
        &u32s(&[
            0,
            0,
            BINDS_OFFSET,
            BINDS.len() as u32,
            0,
            0,
            0,
            0,
            EXPORTS_OFFSET,
            EXPORTS.len() as u32,
        ]),
    );
    image.put(BINDS_OFFSET as usize, BINDS);
    image.put(EXPORTS_OFFSET as usize, EXPORTS);

    image.command(
        LC_SYMTAB,
        &u32s(&[SYMBOLS_OFFSET, 2, STRINGS_OFFSET, STRINGS.len() as u32]),
    );
    // Each symbol: offset of its name, type, section number, description, value.
    for (i, (name, kind, section, value)) in [(1u32, 0x0fu8, 1u8, 0x400u64), (11, 0x0e, 2, 0x1010)]
        .into_iter()
        .enumerate()
    {
        let symbol = SYMBOLS_OFFSET as usize + i * 16;
        image.put(symbol, &name.to_le_bytes());
        image.put(symbol + 4, &[kind, section]);
        image.put(symbol + 8, &value.to_le_bytes());
    }
    image.put(STRINGS_OFFSET as usize, STRINGS);

    image.finish()
}

/// What the tests read from a module: segments, sections, symbols, exports and binds, as tuples.
type Segments = Vec<(String, u64, u64, u64, u64, u32)>;
type Sections = Vec<(String, String, u64, u64)>;
type Symbols = Vec<(String, u64)>;
type Exports = Vec<(String, u64, u64)>;
type Binds = Vec<(u16, u64, u8, i16, String, i8, i64)>;

fn segments(module: &MachoModule) -> Segments {
    module
        .segments()
        .into_iter()
        .map(|segment| {
            (
                segment.name,
                segment.vm_address,
                segment.vm_size,
                segment.file_offset,
                segment.file_size,
                segment.protection,
            )
        })
        .collect()
}

fn sections(module: &MachoModule) -> Sections {
    module
        .sections()
        .into_iter()
        .map(|section| {
            (
                section.segment_name,
                section.section_name,
                section.vm_address,
                section.size,
            )
        })
        .collect()
}

fn symbols(module: &MachoModule) -> Symbols {
    module
        .symbols()
        .into_iter()
        .map(|symbol| (symbol.name, symbol.address))
        .collect()
}

fn exports(module: &MachoModule) -> Exports {
    module
        .exports()
        .into_iter()
        .map(|export| (export.name, export.flags, export.offset))
        .collect()
}

fn binds(module: &MachoModule) -> Binds {
    module
        .binds()
        .into_iter()
        .map(|bind| {
            (
                bind.segment_index,
                bind.offset,
                bind.type_,
                bind.library_ordinal,
                bind.symbol_name,
                bind.symbol_flags,
                bind.addend,
            )
        })
        .collect()
}

fn expected_segments() -> Segments {
    vec![
        ("__TEXT".to_owned(), 0, 0x1000, 0, 0x1000, 5),
        ("__DATA".to_owned(), 0x1000, 0x1000, 0x1000, 0x1000, 3),
        ("__LINKEDIT".to_owned(), 0x2000, 0x1000, 0x2000, 0x1000, 1),
    ]
}

/// The sections of the image loaded at `base`.
fn expected_sections(base: u64) -> Sections {
    vec![
        ("__TEXT".to_owned(), "__text".to_owned(), base + 0x400, 0x10),
        (
            "__DATA".to_owned(),
            "__data".to_owned(),
            base + 0x1000,
            0x20,
        ),
    ]
}

/// The symbols of the image loaded at `base`.
fn expected_symbols(base: u64) -> Symbols {
    vec![
        ("_exported".to_owned(), base + 0x400),
        ("_local".to_owned(), base + 0x1010),
    ]
}

fn expected_exports() -> Exports {
    vec![
        ("_exported".to_owned(), 0, 0x400),
        ("_reexported".to_owned(), 8, 0),
    ]
}

fn expected_binds() -> Binds {
    vec![(1, 8, 1, 1, "_imported".to_owned(), 0, -2)]
}

fn module_from_bytes() -> MachoModule {
    let _gum = &*GUM;
    MachoModule::from_bytes(&image()).expect("the assembled image should parse")
}

#[test]
fn enumerates_segments() {
    assert_eq!(segments(&module_from_bytes()), expected_segments());
}

#[test]
fn enumerates_sections() {
    assert_eq!(sections(&module_from_bytes()), expected_sections(0));
}

#[test]
fn enumerates_symbols() {
    assert_eq!(symbols(&module_from_bytes()), expected_symbols(0));
}

#[test]
fn enumerates_exports() {
    assert_eq!(exports(&module_from_bytes()), expected_exports());
}

#[test]
fn enumerates_binds() {
    assert_eq!(binds(&module_from_bytes()), expected_binds());
}

#[test]
fn stops_enumerating_when_the_callback_says_so() {
    let module = module_from_bytes();

    let mut sections = Vec::new();
    module.enumerate_sections(|section| {
        sections.push(section.section_name);
        false
    });
    let mut symbols = Vec::new();
    module.enumerate_symbols(|symbol| {
        symbols.push(symbol.name);
        false
    });
    let mut exports = Vec::new();
    module.enumerate_exports(|export| {
        exports.push(export.name);
        false
    });

    assert_eq!(sections, ["__text"]);
    assert_eq!(symbols, ["_exported"]);
    assert_eq!(exports, ["_exported"]);
}

#[test]
fn parses_a_file_like_the_bytes_in_it() {
    let _gum = &*GUM;
    let path = std::env::temp_dir().join(format!(
        "frida-gum-macho-module-test-{}.dylib",
        std::process::id()
    ));
    std::fs::write(&path, image()).unwrap();

    let module = MachoModule::from_file(path.to_str().unwrap());
    std::fs::remove_file(&path).unwrap();
    let module = module.expect("the assembled file should parse");

    assert_eq!(segments(&module), expected_segments());
    assert_eq!(sections(&module), expected_sections(0));
    assert_eq!(symbols(&module), expected_symbols(0));
    assert_eq!(exports(&module), expected_exports());
    assert_eq!(binds(&module), expected_binds());
}

#[test]
fn parses_an_image_in_memory() {
    let _gum = &*GUM;
    let image = image();
    let base = image.as_ptr() as u64;

    let module = MachoModule::from_memory("synthetic", base).expect("a module for a mapped image");

    assert_eq!(segments(&module), expected_segments());
    assert_eq!(sections(&module), expected_sections(base));
    assert_eq!(symbols(&module), expected_symbols(base));
    assert_eq!(exports(&module), expected_exports());
    assert_eq!(binds(&module), expected_binds());
}

#[test]
fn rejects_what_is_not_a_mach_o_image() {
    let _gum = &*GUM;

    assert!(MachoModule::from_bytes(&[]).is_none());
    assert!(MachoModule::from_bytes(b"not a Mach-O image").is_none());

    let mut unsupported_cpu = image();
    unsupported_cpu[4..8].copy_from_slice(&0x0100_0012u32.to_le_bytes());
    assert!(MachoModule::from_bytes(&unsupported_cpu).is_none());

    let mut no_segments = Image::new();
    no_segments.command(LC_SYMTAB, &u32s(&[0, 0, 0, 0]));
    assert!(MachoModule::from_bytes(&no_segments.finish()).is_none());
}

#[test]
fn rejects_a_file_it_cannot_read() {
    let _gum = &*GUM;
    let missing = std::env::temp_dir().join("frida-gum-macho-module-no-such-file.dylib");

    assert!(MachoModule::from_file(missing.to_str().unwrap()).is_none());
    assert!(MachoModule::from_file("interior\0nul.dylib").is_none());
}

#[test]
fn rejects_a_null_base_or_a_name_with_a_nul_in_it() {
    let _gum = &*GUM;
    let image = image();

    assert!(MachoModule::from_memory("synthetic", 0).is_none());
    assert!(MachoModule::from_memory("interior\0nul", image.as_ptr() as u64).is_none());
}

#[test]
#[allow(deprecated)]
fn the_darwin_names_still_resolve() {
    let _gum = &*GUM;

    let module: frida_gum::DarwinModule =
        frida_gum::DarwinModule::from_bytes(&image()).expect("the assembled image should parse");
    let segments: Vec<frida_gum::DarwinSegment> = module.segments();

    assert_eq!(segments.len(), 3);
}
