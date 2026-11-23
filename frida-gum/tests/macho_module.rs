//! Tests for [`MachoModule`] against a 64-bit Mach-O dylib assembled here byte by byte, so every
//! platform parses the same known input.
//!
//! The image has the same layout on disk as in memory (each segment's file offset is its VM
//! address, and `__TEXT` starts at zero), so the one buffer serves as a file and as a mapped image.

use frida_gum::{
    DependencyType, Gum, ImportType, MachoLinkeditData, MachoModule, MachoPointerTable,
    MachoRebaseDetails, MachoThreadedItem, MachoTlvDescriptorDetails, MachoTlvParameters,
};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
}

const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_ID_DYLIB: u32 = 0xd;
const LC_SEGMENT_64: u32 = 0x19;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;

const IMAGE_SIZE: usize = 0x3000;
const BINDS_OFFSET: u32 = 0x2000;
const REBASES_OFFSET: u32 = 0x2020;
const LAZY_BINDS_OFFSET: u32 = 0x2030;
const EXPORTS_OFFSET: u32 = 0x2040;
const SYMBOLS_OFFSET: u32 = 0x2080;
const STRINGS_OFFSET: u32 = 0x20c0;

/// Binds `_imported` from the first dependency at `__DATA` + 8, with addend -2.
const BINDS: &[u8] = b"\x11\x40_imported\0\x51\x60\x7e\x71\x08\x90\x00";

/// Two pointers to rebase, at `__DATA` + 0x10 and + 0x18.
const REBASES: &[u8] = b"\x11\x21\x10\x52\x00";

/// Binds `_lazy` from the second dependency at `__DATA` + 0x18.
const LAZY_BINDS: &[u8] = b"\x71\x18\x12\x40_lazy\0\x90\x00";

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

    /// A segment at `address` on disk and in memory.
    fn segment(&mut self, name: &str, address: u64, protection: u32, sections: &[Section]) {
        let mut body = Vec::new();
        body.extend(name16(name));
        for value in [address, 0x1000, address, 0x1000] {
            body.extend(value.to_le_bytes());
        }
        for value in [protection, protection, sections.len() as u32, 0] {
            body.extend(value.to_le_bytes());
        }
        for section in sections {
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

    /// A command that names a library: this one, or one it depends on.
    fn dylib(&mut self, command: u32, name: &str) {
        let mut body = u32s(&[24, 0, 0x1_0000, 0x1_0000]);
        body.extend(name.as_bytes());
        body.resize((body.len() + 1).next_multiple_of(8), 0);
        self.command(command, &body);
    }

    fn finish(mut self) -> Vec<u8> {
        const MH_MAGIC_64: u32 = 0xfeed_facf;
        const CPU_TYPE_X86_64: u32 = 0x0100_0007;
        const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
        const MH_DYLIB: u32 = 6;
        const MH_HAS_TLV_DESCRIPTORS: u32 = 0x80_0000;

        let commands_size = (self.commands_end - Self::HEADER_SIZE) as u32;
        for (i, value) in [
            MH_MAGIC_64,
            CPU_TYPE_X86_64,
            CPU_SUBTYPE_X86_64_ALL,
            MH_DYLIB,
            self.command_count,
            commands_size,
            MH_HAS_TLV_DESCRIPTORS,
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
    image_with(|_| ())
}

/// The image, with whatever load commands `more` appends after the segments.
fn image_with(more: impl FnOnce(&mut Image)) -> Vec<u8> {
    const VM_PROT_READ: u32 = 1;
    const VM_PROT_WRITE: u32 = 2;
    const VM_PROT_EXECUTE: u32 = 4;
    const S_MOD_INIT_FUNC_POINTERS: u32 = 0x09;
    const S_MOD_TERM_FUNC_POINTERS: u32 = 0x0a;
    const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
    const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
    const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
    const S_INIT_FUNC_OFFSETS: u32 = 0x16;
    const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;

    let mut image = Image::new();

    image.segment(
        "__TEXT",
        0,
        VM_PROT_READ | VM_PROT_EXECUTE,
        &[Section {
            name: "__text",
            address: 0x400,
            size: 0x10,
            flags: S_ATTR_PURE_INSTRUCTIONS,
        }],
    );
    image.segment(
        "__DATA",
        0x1000,
        VM_PROT_READ | VM_PROT_WRITE,
        &[
            ("__data", 0x1000, 0x20, 0),
            ("__mod_init_func", 0x1020, 0x10, S_MOD_INIT_FUNC_POINTERS),
            ("__mod_term_func", 0x1030, 0x8, S_MOD_TERM_FUNC_POINTERS),
            ("__init_offsets", 0x1038, 0x8, S_INIT_FUNC_OFFSETS),
            ("__thread_vars", 0x1040, 0x30, S_THREAD_LOCAL_VARIABLES),
            ("__thread_data", 0x1070, 0x10, S_THREAD_LOCAL_REGULAR),
            ("__thread_bss", 0x1080, 0x20, S_THREAD_LOCAL_ZEROFILL),
        ]
        .map(|(name, address, size, flags)| Section {
            name,
            address,
            size,
            flags,
        }),
    );
    image.segment("__LINKEDIT", 0x2000, VM_PROT_READ, &[]);
    more(&mut image);

    // Two thread-local variables: each a thunk, a key, and an offset into the thread's data.
    for (i, value) in [0x400u64, 0, 0, 0x400, 0, 8].into_iter().enumerate() {
        image.put(0x1040 + i * 8, &value.to_le_bytes());
    }

    image.dylib(LC_ID_DYLIB, "libsynthetic.dylib");
    image.dylib(LC_LOAD_DYLIB, "libdep.dylib");
    image.dylib(LC_LOAD_WEAK_DYLIB, "libweak.dylib");

    image.command(
        LC_DYLD_INFO_ONLY,
        &u32s(&[
            REBASES_OFFSET,
            REBASES.len() as u32,
            BINDS_OFFSET,
            BINDS.len() as u32,
            0,
            0,
            LAZY_BINDS_OFFSET,
            LAZY_BINDS.len() as u32,
            EXPORTS_OFFSET,
            EXPORTS.len() as u32,
        ]),
    );
    image.put(REBASES_OFFSET as usize, REBASES);
    image.put(BINDS_OFFSET as usize, BINDS);
    image.put(LAZY_BINDS_OFFSET as usize, LAZY_BINDS);
    image.put(EXPORTS_OFFSET as usize, EXPORTS);

    image.command(LC_FUNCTION_STARTS, &u32s(&[0x2100, 8]));

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
    [
        ("__TEXT", "__text", 0x400, 0x10),
        ("__DATA", "__data", 0x1000, 0x20),
        ("__DATA", "__mod_init_func", 0x1020, 0x10),
        ("__DATA", "__mod_term_func", 0x1030, 0x8),
        ("__DATA", "__init_offsets", 0x1038, 0x8),
        ("__DATA", "__thread_vars", 0x1040, 0x30),
        ("__DATA", "__thread_data", 0x1070, 0x10),
        ("__DATA", "__thread_bss", 0x1080, 0x20),
    ]
    .map(|(segment, section, address, size)| {
        (segment.to_owned(), section.to_owned(), base + address, size)
    })
    .into()
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

/// Imports as tuples: type, name, module, address, slot.
type Imports = Vec<(ImportType, String, Option<String>, usize, usize)>;

fn imports(module: &MachoModule) -> Imports {
    module
        .imports()
        .into_iter()
        .map(|import| {
            (
                import.typ,
                import.name,
                import.module,
                import.address,
                import.slot,
            )
        })
        .collect()
}

/// The imports of the image loaded at `base`.
fn expected_imports(base: usize) -> Imports {
    vec![
        (
            ImportType::Unknown,
            "_imported".to_owned(),
            Some("libdep.dylib".to_owned()),
            0,
            base + 0x1008,
        ),
        (
            ImportType::Unknown,
            "_lazy".to_owned(),
            Some("libweak.dylib".to_owned()),
            0,
            base + 0x1018,
        ),
    ]
}

#[test]
fn enumerates_lazy_binds() {
    let lazy_binds: Binds = module_from_bytes()
        .lazy_binds()
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
        .collect();

    assert_eq!(lazy_binds, [(1, 0x18, 1, 2, "_lazy".to_owned(), 0, 0)]);
}

#[test]
fn enumerates_rebases() {
    let rebase = |offset| MachoRebaseDetails {
        segment_index: 1,
        offset,
        type_: 1,
        slide: 0,
    };

    assert_eq!(module_from_bytes().rebases(), [rebase(0x10), rebase(0x18)]);
}

#[test]
fn enumerates_imports() {
    let module = module_from_bytes();

    let mut asked_to_resolve = Vec::new();
    let mut found = Vec::new();
    module.enumerate_imports(
        |module, symbol| {
            asked_to_resolve.push((module.map(str::to_owned), symbol.to_owned()));
            0
        },
        |import| {
            found.push(import.name);
            true
        },
    );

    assert_eq!(found, ["_imported", "_lazy"]);
    assert_eq!(
        asked_to_resolve,
        [],
        "only an import bound through chained fixups is resolved"
    );
    assert_eq!(imports(&module), expected_imports(0));
}

#[test]
fn stops_enumerating_imports_when_the_callback_says_so() {
    let mut found = Vec::new();
    module_from_bytes().enumerate_imports(
        |_, _| 0,
        |import| {
            found.push(import.name);
            false
        },
    );

    assert_eq!(found, ["_imported"]);
}

#[test]
fn enumerates_dependencies() {
    let module = module_from_bytes();

    let dependencies: Vec<_> = module
        .dependencies()
        .into_iter()
        .map(|dependency| (dependency.name, dependency.typ))
        .collect();

    assert_eq!(
        dependencies,
        [
            ("libdep.dylib".to_owned(), DependencyType::Regular),
            ("libweak.dylib".to_owned(), DependencyType::Weak),
        ]
    );
    assert_eq!(
        module.dependency_by_ordinal(0).as_deref(),
        Some("libsynthetic.dylib")
    );
    assert_eq!(
        module.dependency_by_ordinal(1).as_deref(),
        Some("libdep.dylib")
    );
    assert_eq!(
        module.dependency_by_ordinal(2).as_deref(),
        Some("libweak.dylib")
    );
    assert_eq!(module.dependency_by_ordinal(3), None);
    assert_eq!(module.dependency_by_ordinal(-2), None);
}

#[test]
fn resolves_exports_and_symbols() {
    let module = module_from_bytes();
    let export = |name| {
        module
            .resolve_export(name)
            .map(|export| (export.name, export.flags, export.offset))
    };

    assert_eq!(
        export("_exported"),
        Some(("_exported".to_owned(), 0, 0x400))
    );
    assert_eq!(
        export("_reexported"),
        Some(("_reexported".to_owned(), 8, 0))
    );
    assert_eq!(export("_export"), None);
    assert_eq!(export("_exported\0"), None);
    assert_eq!(module.resolve_symbol_address("_local"), Some(0x1010));
    assert_eq!(module.resolve_symbol_address("_missing"), None);
}

#[test]
fn enumerates_exports_with_a_prefix() {
    let module = module_from_bytes();
    let names = |prefix| {
        let mut names = Vec::new();
        module.enumerate_exports_with_prefix(prefix, |export| {
            names.push(export.name);
            true
        });
        names
    };

    assert_eq!(names("_re"), ["_reexported"]);
    assert_eq!(names(""), ["_exported", "_reexported"]);
    assert_eq!(names("_x"), [] as [&str; 0]);
    assert_eq!(names("_re\0"), [] as [&str; 0]);
}

#[test]
fn reads_thread_local_variables() {
    let module = module_from_bytes();
    let descriptor = |file_offset, offset| MachoTlvDescriptorDetails {
        file_offset,
        thunk: 0x400,
        key: 0,
        offset,
    };

    assert_eq!(
        module.tlv_parameters(),
        MachoTlvParameters {
            num_descriptors: 2,
            descriptors_offset: 0x1040,
            data_offset: 0x1070,
            data_size: 0x10,
            bss_size: 0x20,
        }
    );
    assert_eq!(
        module.tlv_descriptors(),
        [descriptor(0x1040, 0), descriptor(0x1058, 8)]
    );
}

#[test]
fn enumerates_initializers_and_terminators() {
    let module = module_from_bytes();
    let table = |address, count| MachoPointerTable { address, count };

    assert_eq!(module.init_pointers(), [table(0x1020, 2)]);
    assert_eq!(module.term_pointers(), [table(0x1030, 1)]);
    assert_eq!(module.init_offsets(), [table(0x1038, 2)]);
}

#[test]
fn enumerates_function_starts_and_chained_fixups() {
    let _gum = &*GUM;
    let with_fixups = image_with(|image| {
        image.command(LC_DYLD_CHAINED_FIXUPS, &u32s(&[0x2200, 0x20]));
    });
    let with_fixups = MachoModule::from_bytes(&with_fixups).unwrap();
    let data = |offset, size| MachoLinkeditData {
        vm_address: offset,
        file_offset: offset,
        size,
    };

    assert_eq!(module_from_bytes().function_starts(), [data(0x2100, 8)]);
    assert_eq!(module_from_bytes().chained_fixups(), []);
    assert_eq!(with_fixups.chained_fixups(), [data(0x2200, 0x20)]);
}

#[test]
fn describes_where_a_file_would_load() {
    let module = module_from_bytes();

    assert!(module.ensure_image_loaded());
    assert_eq!(module.slide(), 0);
    assert!(module.is_address_in_text_section(0x400));
    assert!(module.is_address_in_text_section(0x40f));
    assert!(!module.is_address_in_text_section(0x410));
    assert!(!module.is_address_in_text_section(0x1000));
    assert!(module.lacks_exports_for_reexports());
}

#[test]
fn describes_an_image_in_memory_by_where_it_is() {
    let _gum = &*GUM;
    let image = image();
    let base = image.as_ptr() as u64;
    let module = MachoModule::from_memory("synthetic", base).unwrap();
    let table = |address, count| MachoPointerTable { address, count };

    assert!(module.ensure_image_loaded());
    assert_eq!(module.slide(), base);
    assert!(module.is_address_in_text_section(base + 0x400));
    assert!(!module.is_address_in_text_section(0x400));
    assert_eq!(module.resolve_symbol_address("_local"), Some(base + 0x1010));
    assert_eq!(module.init_pointers(), [table(base + 0x1020, 2)]);
    assert_eq!(
        module.rebases(),
        [0x10, 0x18].map(|offset| MachoRebaseDetails {
            segment_index: 1,
            offset,
            type_: 1,
            slide: base,
        })
    );
    assert_eq!(
        module.function_starts(),
        [MachoLinkeditData {
            vm_address: base + 0x2100,
            file_offset: 0x2100,
            size: 8,
        }]
    );
    assert_eq!(imports(&module), expected_imports(base as usize));
    assert_eq!(
        module.dependency_by_ordinal(0).as_deref(),
        Some("synthetic")
    );
}

#[test]
fn decodes_threaded_items() {
    let bind = (1 << 62) | (2 << 51) | 5;
    let authenticated_rebase = (1 << 63) | (3 << 49) | (1 << 48) | (0x1234 << 32) | 0x8000_1000;
    let rebase = (1 << 51) | 0x7ff_ffff_f000;

    assert_eq!(
        MachoThreadedItem::parse(bind),
        MachoThreadedItem {
            is_authenticated: false,
            type_: MachoThreadedItem::BIND,
            delta: 2,
            key: 0,
            has_address_diversity: false,
            diversity: 0,
            bind_ordinal: 5,
            rebase_address: 0,
        }
    );
    assert_eq!(
        MachoThreadedItem::parse(authenticated_rebase),
        MachoThreadedItem {
            is_authenticated: true,
            type_: MachoThreadedItem::REBASE,
            delta: 0,
            key: 3,
            has_address_diversity: true,
            diversity: 0x1234,
            bind_ordinal: 0,
            rebase_address: 0x8000_1000,
        }
    );
    assert_eq!(
        MachoThreadedItem::parse(rebase).rebase_address,
        0x00ff_ffff_ffff_f000,
        "bit 42 is the sign of an address that is not authenticated"
    );
}
