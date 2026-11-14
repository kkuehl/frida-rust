//! Tests for [`PeModule`] against a PE32+ image assembled here byte by byte, so every platform
//! parses the same known input, and on Windows against images the system provides.

use frida_gum::{
    DependencyType, Gum, PageProtection, PeDataDirectory, PeDirectoryIndex, PeExportDetails,
    PeExportTarget, PeImportDetails, PeImportLoadMode, PeImportSymbol, PeMachine, PeModule,
    PeRelocationDetails, PeRelocationType, PeSourceMode, PeTlsDetails,
};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = Gum::obtain();
}

const IMAGE_BASE: u64 = 0x1_8000_0000;
const SIZE_OF_HEADERS: u32 = 0x200;
const SIZE_OF_IMAGE: u32 = 0x3000;
const ENTRYPOINT_RVA: u32 = 0x1000;

const TEXT_RVA: u32 = 0x1000;
const TEXT_FILE_OFFSET: u32 = 0x200;
const TEXT_SIZE: u32 = 0x200;
const RDATA_RVA: u32 = 0x2000;
const RDATA_FILE_OFFSET: u32 = 0x400;
const RDATA_SIZE: u32 = 0x800;

/// File offset of the optional header: DOS header, signature, COFF header.
const OPTIONAL_HEADER: usize = 0x40 + 4 + 20;
/// File offset of the data directory table in a PE32+ optional header.
const DATA_DIRECTORIES: usize = OPTIONAL_HEADER + 112;

const EXPORT_DIRECTORY: PeDataDirectory = PeDataDirectory {
    rva: 0x2000,
    size: 0x100,
};
const IMPORT_DIRECTORY_RVA: u32 = 0x2100;
const DELAY_IMPORT_DIRECTORY_RVA: u32 = 0x2200;
const RELOCATION_DIRECTORY_RVA: u32 = 0x2300;
const TLS_DIRECTORY_RVA: u32 = 0x2380;
const EXCEPTION_DIRECTORY_RVA: u32 = 0x2400;
const LOAD_CONFIG_DIRECTORY_RVA: u32 = 0x2500;
const RESOURCE_DIRECTORY_RVA: u32 = 0x2680;

/// A PE image under construction, written at file offsets or at RVAs inside `.rdata`.
struct Image(Vec<u8>);

impl Image {
    fn put(&mut self, offset: usize, bytes: &[u8]) {
        self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn put_u16(&mut self, offset: usize, value: u16) {
        self.put(offset, &value.to_le_bytes());
    }

    fn put_u32(&mut self, offset: usize, value: u32) {
        self.put(offset, &value.to_le_bytes());
    }

    fn put_u64(&mut self, offset: usize, value: u64) {
        self.put(offset, &value.to_le_bytes());
    }

    fn rdata(rva: u32) -> usize {
        (rva - RDATA_RVA + RDATA_FILE_OFFSET) as usize
    }

    fn put_u16s_at_rva(&mut self, rva: u32, values: &[u16]) {
        for (i, value) in values.iter().enumerate() {
            self.put_u16(Self::rdata(rva) + i * 2, *value);
        }
    }

    fn put_u32s_at_rva(&mut self, rva: u32, values: &[u32]) {
        for (i, value) in values.iter().enumerate() {
            self.put_u32(Self::rdata(rva) + i * 4, *value);
        }
    }

    fn put_u64s_at_rva(&mut self, rva: u32, values: &[u64]) {
        for (i, value) in values.iter().enumerate() {
            self.put_u64(Self::rdata(rva) + i * 8, *value);
        }
    }

    fn put_str_at_rva(&mut self, rva: u32, text: &str) {
        self.put(Self::rdata(rva), text.as_bytes());
        self.put(Self::rdata(rva) + text.len(), &[0]);
    }

    fn set_directory(&mut self, index: usize, rva: u32, size: u32) {
        self.put_u32(DATA_DIRECTORIES + index * 8, rva);
        self.put_u32(DATA_DIRECTORIES + index * 8 + 4, size);
    }
}

/// An AMD64 image with a `.text` and a `.rdata` section and no data directories.
fn bare_image() -> Image {
    let mut image = Image(vec![0; (RDATA_FILE_OFFSET + RDATA_SIZE) as usize]);

    image.put(0, b"MZ");
    image.put_u32(0x3c, 0x40);
    image.put(0x40, b"PE\0\0");

    let coff_header = 0x44;
    image.put_u16(coff_header, 0x8664);
    image.put_u16(coff_header + 2, 2);
    image.put_u16(coff_header + 16, 240);

    image.put_u16(OPTIONAL_HEADER, 0x20b);
    image.put_u32(OPTIONAL_HEADER + 16, ENTRYPOINT_RVA);
    image.put_u64(OPTIONAL_HEADER + 24, IMAGE_BASE);
    image.put_u32(OPTIONAL_HEADER + 56, SIZE_OF_IMAGE);
    image.put_u32(OPTIONAL_HEADER + 60, SIZE_OF_HEADERS);
    image.put_u32(OPTIONAL_HEADER + 108, 16);

    let sections = OPTIONAL_HEADER + 240;
    for (i, (name, virtual_size, rva, raw_size, file_offset, characteristics)) in [
        (
            b".text\0\0\0",
            0x50,
            TEXT_RVA,
            TEXT_SIZE,
            TEXT_FILE_OFFSET,
            0x6000_0020u32,
        ),
        (
            b".rdata\0\0",
            0x740,
            RDATA_RVA,
            RDATA_SIZE,
            RDATA_FILE_OFFSET,
            0x4000_0040,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let header = sections + i * 40;
        image.put(header, name);
        image.put_u32(header + 8, virtual_size);
        image.put_u32(header + 12, rva);
        image.put_u32(header + 16, raw_size);
        image.put_u32(header + 20, file_offset);
        image.put_u32(header + 36, characteristics);
    }

    image
}

/// [`bare_image`] with every data directory [`PeModule`] reads filled in.
fn full_image() -> Vec<u8> {
    let mut image = bare_image();

    // Exports, ordinal base 5: "alpha", an unused slot, one by ordinal only, and "beta" forwarded.
    image.set_directory(0, EXPORT_DIRECTORY.rva, EXPORT_DIRECTORY.size);
    image.put_u32s_at_rva(
        EXPORT_DIRECTORY.rva + 12,
        &[0x2080, 5, 4, 2, 0x2028, 0x2038, 0x2040],
    );
    image.put_u32s_at_rva(0x2028, &[0x1010, 0, 0x1020, 0x2090]);
    image.put_u32s_at_rva(0x2038, &[0x2050, 0x2058]);
    image.put_u16s_at_rva(0x2040, &[0, 3]);
    image.put_str_at_rva(0x2050, "alpha");
    image.put_str_at_rva(0x2058, "beta");
    image.put_str_at_rva(0x2080, "synthetic.dll");
    image.put_str_at_rva(0x2090, "OTHER.Beta");

    // Imports from dep.dll: one by name, one by ordinal 42.
    image.set_directory(1, IMPORT_DIRECTORY_RVA, 40);
    image.put_u32s_at_rva(IMPORT_DIRECTORY_RVA, &[0x2140, 0, 0, 0x2180, 0x2160]);
    for table in [0x2140, 0x2160] {
        image.put_u64s_at_rva(table, &[0x2190, 0x8000_0000_0000_0000 | 42, 0]);
    }
    image.put_str_at_rva(0x2180, "dep.dll");
    image.put_str_at_rva(0x2190 + 2, "ImportedByName");

    // A delay-loaded import from lazy.dll.
    image.set_directory(13, DELAY_IMPORT_DIRECTORY_RVA, 64);
    image.put_u32s_at_rva(DELAY_IMPORT_DIRECTORY_RVA, &[1, 0x2260, 0, 0x2240, 0x2250]);
    image.put_u64s_at_rva(0x2250, &[0x2270, 0]);
    image.put_str_at_rva(0x2260, "lazy.dll");
    image.put_str_at_rva(0x2270 + 2, "LazyFn");

    // One relocation block for the page at 0x1000: a DIR64 at +8, then padding.
    image.set_directory(5, RELOCATION_DIRECTORY_RVA, 12);
    image.put_u32s_at_rva(RELOCATION_DIRECTORY_RVA, &[0x1000, 12]);
    image.put_u16s_at_rva(RELOCATION_DIRECTORY_RVA + 8, &[(10 << 12) | 8, 0]);

    // TLS: a 16-byte template, 32 bytes of zero fill, one callback.
    image.set_directory(9, TLS_DIRECTORY_RVA, 40);
    image.put_u64s_at_rva(
        TLS_DIRECTORY_RVA,
        &[
            IMAGE_BASE + 0x23d0,
            IMAGE_BASE + 0x23e0,
            IMAGE_BASE + 0x23e8,
            IMAGE_BASE + 0x23c0,
        ],
    );
    image.put_u32s_at_rva(TLS_DIRECTORY_RVA + 32, &[0x20]);
    image.put_u64s_at_rva(0x23c0, &[IMAGE_BASE + 0x1030, 0]);

    // Exception directory: two functions, and a third entry whose unwind data marks it as part
    // of another function.
    image.set_directory(3, EXCEPTION_DIRECTORY_RVA, 36);
    image.put_u32s_at_rva(
        EXCEPTION_DIRECTORY_RVA,
        &[
            0x1000, 0x1010, 0x2440, 0x1010, 0x1020, 0x2440, 0x1020, 0x1030, 0x2441,
        ],
    );
    image.put(Image::rdata(0x2440), &[1]);

    // Load configuration with a stack cookie and no hybrid metadata.
    image.set_directory(10, LOAD_CONFIG_DIRECTORY_RVA, 0x140);
    image.put_u32s_at_rva(LOAD_CONFIG_DIRECTORY_RVA, &[0x140]);
    image.put_u64s_at_rva(LOAD_CONFIG_DIRECTORY_RVA + 0x58, &[IMAGE_BASE + 0x1040]);

    // Resources: type 16 (version) -> name 1 -> language 0x409 -> a VS_VERSIONINFO for 1.2.3.4.
    const SUBDIRECTORY: u32 = 0x8000_0000;
    let resources = RESOURCE_DIRECTORY_RVA;
    image.set_directory(2, resources, 0xc0);
    for (directory, id, child) in [
        (0x00, 16, SUBDIRECTORY | 0x18),
        (0x18, 1, SUBDIRECTORY | 0x30),
        (0x30, 0x409, 0x48),
    ] {
        image.put_u16s_at_rva(resources + directory + 14, &[1]);
        image.put_u32s_at_rva(resources + directory + 16, &[id, child]);
    }
    let version_info = resources + 0x60;
    image.put_u32s_at_rva(resources + 0x48, &[version_info, 92]);
    image.put_u16s_at_rva(version_info, &[92, 52, 0]);
    let key: Vec<u16> = "VS_VERSION_INFO".encode_utf16().collect();
    image.put_u16s_at_rva(version_info + 6, &key);
    image.put_u32s_at_rva(
        version_info + 40,
        &[0xfeef_04bd, 0x1_0000, (1 << 16) | 2, (3 << 16) | 4],
    );

    image.0
}

fn full_module() -> PeModule {
    PeModule::from_bytes(&GUM, &full_image()).expect("the assembled image should parse")
}

fn alpha() -> PeExportDetails {
    PeExportDetails {
        ordinal: 5,
        name: Some("alpha".to_owned()),
        target: PeExportTarget::Rva(0x1010),
    }
}

fn beta() -> PeExportDetails {
    PeExportDetails {
        ordinal: 8,
        name: Some("beta".to_owned()),
        target: PeExportTarget::Forwarder("OTHER.Beta".to_owned()),
    }
}

#[test]
fn reads_the_headers() {
    let image = full_image();
    let module = PeModule::from_bytes(&GUM, &image).unwrap();

    assert_eq!(module.pointer_size(), 8);
    assert_eq!(module.machine(), PeMachine::Amd64);
    assert_eq!(module.image_base(), IMAGE_BASE);
    assert_eq!(module.size_of_image(), SIZE_OF_IMAGE as usize);
    assert_eq!(module.size_of_headers(), SIZE_OF_HEADERS as usize);
    assert_eq!(module.entrypoint(), ENTRYPOINT_RVA);
    assert_eq!(module.source_mode(), PeSourceMode::Offline);
    assert_eq!(module.source_bytes(), Some(image));
}

#[test]
fn reports_a_machine_it_has_no_name_for() {
    let mut image = bare_image();
    image.put_u16(0x44, 0x5064);

    let module = PeModule::from_bytes(&GUM, &image.0).unwrap();

    assert_eq!(module.machine(), PeMachine::Other(0x5064));
}

#[test]
fn rejects_what_is_not_a_pe_image() {
    assert!(PeModule::from_bytes(&GUM, &[]).is_none());
    assert!(PeModule::from_bytes(&GUM, b"MZ, but nothing more").is_none());

    let mut wrong_signature = bare_image();
    wrong_signature.put(0x40, b"NE\0\0");
    assert!(PeModule::from_bytes(&GUM, &wrong_signature.0).is_none());

    let mut truncated = full_image();
    truncated.truncate(SIZE_OF_HEADERS as usize - 1);
    assert!(PeModule::from_bytes(&GUM, &truncated).is_none());
}

#[test]
fn rejects_a_file_it_cannot_read() {
    let missing = std::env::temp_dir().join("frida-gum-pe-module-no-such-file.dll");

    assert!(PeModule::from_file(&GUM, missing.to_str().unwrap()).is_none());
    assert!(PeModule::from_file(&GUM, "interior\0nul.dll").is_none());
}

#[test]
fn parses_a_file_like_the_bytes_in_it() {
    let path = std::env::temp_dir().join(format!(
        "frida-gum-pe-module-test-{}.dll",
        std::process::id()
    ));
    let image = full_image();
    std::fs::write(&path, &image).unwrap();

    let module = PeModule::from_file(&GUM, path.to_str().unwrap());
    let parsed = module.as_ref().map(|module| {
        (
            module.source_mode(),
            module.source_bytes(),
            module.exports(),
            module.version(),
        )
    });
    // Unmap the file before removing it.
    drop(module);
    std::fs::remove_file(&path).unwrap();

    assert_eq!(
        parsed,
        Some((
            PeSourceMode::Offline,
            Some(image),
            full_module().exports(),
            Some("1.2.3.4".to_owned())
        ))
    );
}

#[test]
fn enumerates_sections() {
    let sections = full_module().sections();

    let summary: Vec<_> = sections
        .iter()
        .map(|section| {
            (
                section.name.as_str(),
                section.virtual_address,
                section.virtual_size,
                section.raw_data_offset,
                section.raw_data_size,
                section.characteristics,
                section.protection.clone(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (
                ".text",
                TEXT_RVA,
                0x50,
                TEXT_FILE_OFFSET,
                TEXT_SIZE,
                0x6000_0020,
                PageProtection::ReadExecute
            ),
            (
                ".rdata",
                RDATA_RVA,
                0x740,
                RDATA_FILE_OFFSET,
                RDATA_SIZE,
                0x4000_0040,
                PageProtection::Read
            ),
        ]
    );
}

#[test]
fn stops_enumerating_when_the_callback_says_so() {
    let module = full_module();

    let mut sections = Vec::new();
    module.enumerate_sections(|section| {
        sections.push(section.name);
        false
    });
    let mut exports = Vec::new();
    module.enumerate_exports(|export| {
        exports.push(export.ordinal);
        false
    });
    let mut function_starts = Vec::new();
    module.enumerate_function_starts(|rva| {
        function_starts.push(rva);
        false
    });

    assert_eq!(sections, [".text"]);
    assert_eq!(exports, [5]);
    assert_eq!(function_starts, [0x1000]);
}

#[test]
fn reads_data_directories() {
    let module = full_module();

    assert_eq!(module.directory(PeDirectoryIndex::Export), EXPORT_DIRECTORY);
    for (index, rva, size) in [
        (PeDirectoryIndex::Import, IMPORT_DIRECTORY_RVA, 40),
        (PeDirectoryIndex::Resource, RESOURCE_DIRECTORY_RVA, 0xc0),
        (PeDirectoryIndex::Exception, EXCEPTION_DIRECTORY_RVA, 36),
        (PeDirectoryIndex::BaseReloc, RELOCATION_DIRECTORY_RVA, 12),
        (PeDirectoryIndex::Tls, TLS_DIRECTORY_RVA, 40),
        (
            PeDirectoryIndex::LoadConfig,
            LOAD_CONFIG_DIRECTORY_RVA,
            0x140,
        ),
        (
            PeDirectoryIndex::DelayImport,
            DELAY_IMPORT_DIRECTORY_RVA,
            64,
        ),
    ] {
        assert_eq!(
            module.directory(index),
            PeDataDirectory { rva, size },
            "{index:?}"
        );
    }
}

#[test]
fn finds_data_by_rva() {
    let module = full_module();

    let alpha = module
        .data_at_rva(0x2050)
        .expect("an RVA inside .rdata has data");
    // SAFETY: the image holds "alpha\0" at this RVA, and `module` is alive.
    let alpha = unsafe { std::slice::from_raw_parts(alpha.cast::<u8>(), 6) };

    assert_eq!(alpha, b"alpha\0");
    assert!(module.data_at_rva(SIZE_OF_IMAGE + 0x1000).is_none());
}

#[test]
fn enumerates_exports() {
    let exports = full_module().exports();

    assert_eq!(
        exports,
        [
            alpha(),
            PeExportDetails {
                ordinal: 7,
                name: None,
                target: PeExportTarget::Rva(0x1020),
            },
            beta(),
        ]
    );
}

#[test]
fn finds_an_export_by_name() {
    let module = full_module();

    assert_eq!(module.find_export_by_name("alpha"), Some(alpha()));
    assert_eq!(module.find_export_by_name("beta"), Some(beta()));
    assert_eq!(module.find_export_by_name("Alpha"), None);
    assert_eq!(module.find_export_by_name("gamma"), None);
    assert_eq!(module.find_export_by_name("al\0pha"), None);
}

#[test]
fn enumerates_imports() {
    let imports = full_module().imports();

    assert_eq!(
        imports,
        [
            PeImportDetails {
                module_name: "dep.dll".to_owned(),
                symbol: PeImportSymbol::Name("ImportedByName".to_owned()),
                load_mode: PeImportLoadMode::Regular,
                slot_rva: 0x2160,
            },
            PeImportDetails {
                module_name: "dep.dll".to_owned(),
                symbol: PeImportSymbol::Ordinal(42),
                load_mode: PeImportLoadMode::Regular,
                slot_rva: 0x2168,
            },
            PeImportDetails {
                module_name: "lazy.dll".to_owned(),
                symbol: PeImportSymbol::Name("LazyFn".to_owned()),
                load_mode: PeImportLoadMode::Delayed,
                slot_rva: 0x2240,
            },
        ]
    );
}

#[test]
fn enumerates_dependencies() {
    let dependencies: Vec<_> = full_module()
        .dependencies()
        .into_iter()
        .map(|dependency| (dependency.name, dependency.typ))
        .collect();

    assert_eq!(
        dependencies,
        [
            ("dep.dll".to_owned(), DependencyType::Regular),
            ("lazy.dll".to_owned(), DependencyType::Weak),
        ]
    );
}

#[test]
fn enumerates_relocations() {
    let relocations = full_module().relocations();

    assert_eq!(
        relocations,
        [
            PeRelocationDetails {
                rva: 0x1008,
                typ: PeRelocationType::Dir64,
            },
            PeRelocationDetails {
                rva: 0x1000,
                typ: PeRelocationType::Absolute,
            },
        ]
    );
}

#[test]
fn reads_thread_local_storage() {
    let module = full_module();

    assert_eq!(
        module.tls_details(),
        Some(PeTlsDetails {
            template_rva: 0x23d0,
            template_size: 0x10,
            zero_fill_size: 0x20,
            index_rva: 0x23e8,
        })
    );
    assert_eq!(module.tls_callbacks(), [0x1030]);
}

#[test]
fn enumerates_function_starts_without_fragments() {
    let module = full_module();

    assert_eq!(module.function_count(), 3);
    assert_eq!(module.function_starts(), [0x1000, 0x1010]);
}

#[test]
fn reads_the_load_configuration() {
    let module = full_module();

    assert_eq!(module.security_cookie_rva(), 0x1040);
    assert_eq!(module.chpe_metadata_rva(), 0);
}

#[test]
fn reads_the_file_version() {
    assert_eq!(full_module().version(), Some("1.2.3.4".to_owned()));
}

#[test]
fn an_image_without_directories_has_nothing_in_them() {
    let module = PeModule::from_bytes(&GUM, &bare_image().0).unwrap();

    assert_eq!(
        module.directory(PeDirectoryIndex::Export),
        PeDataDirectory::default()
    );
    assert_eq!(module.sections().len(), 2);
    assert!(module.exports().is_empty());
    assert!(module.imports().is_empty());
    assert!(module.dependencies().is_empty());
    assert!(module.relocations().is_empty());
    assert_eq!(module.tls_details(), None);
    assert!(module.tls_callbacks().is_empty());
    assert_eq!(module.function_count(), 0);
    assert!(module.function_starts().is_empty());
    assert_eq!(module.security_cookie_rva(), 0);
    assert_eq!(module.chpe_metadata_rva(), 0);
    assert_eq!(module.version(), None);
}

#[cfg(windows)]
mod on_windows {
    use super::*;
    use frida_gum::Process;

    fn kernel32() -> PeModule {
        let path = format!(
            r"{}\System32\kernel32.dll",
            std::env::var("SystemRoot").unwrap()
        );
        PeModule::from_file(&GUM, &path).expect("kernel32.dll should parse")
    }

    #[test]
    fn reads_the_version_of_a_system_library() {
        let version = kernel32().version().expect("kernel32.dll has a version");

        let fields: Vec<_> = version.split('.').collect();
        assert_eq!(fields.len(), 4, "{version}");
        assert!(
            fields.iter().all(|field| field.parse::<u16>().is_ok()),
            "{version}"
        );
    }

    #[test]
    fn reads_the_exports_of_a_system_library() {
        let module = kernel32();
        let exports = module.exports();

        let found = module.find_export_by_name("GetCurrentProcessId");
        assert!(
            matches!(
                found,
                Some(PeExportDetails {
                    target: PeExportTarget::Rva(rva),
                    ..
                }) if rva != 0
            ),
            "{found:?}"
        );
        assert!(found.is_some_and(|found| exports.contains(&found)));
        assert!(
            exports.iter().any(|export| matches!(
                &export.target,
                PeExportTarget::Forwarder(forwarder) if forwarder.contains('.')
            )),
            "kernel32.dll forwards some of its exports"
        );
    }

    #[test]
    fn parses_the_image_this_test_runs_from() {
        let base = Process::obtain(&GUM).main_module().range().base_address();
        // SAFETY: the main module is mapped at its base for the life of the process.
        let module = unsafe { PeModule::from_memory(&GUM, base.0 as u64) }
            .expect("the main module is a PE image");

        assert_eq!(module.source_mode(), PeSourceMode::Online);
        assert_eq!(module.source_bytes(), None);
        assert_eq!(module.pointer_size() as usize, std::mem::size_of::<usize>());
        assert_eq!(
            module.machine(),
            if cfg!(target_arch = "x86_64") {
                PeMachine::Amd64
            } else if cfg!(target_arch = "aarch64") {
                PeMachine::Arm64
            } else {
                PeMachine::I386
            }
        );
        assert!(
            module
                .sections()
                .iter()
                .any(|section| section.name == ".text")
        );
        assert!(
            module
                .dependencies()
                .iter()
                .any(|dependency| dependency.name.eq_ignore_ascii_case("kernel32.dll"))
        );
        assert!(
            module
                .imports()
                .iter()
                .any(|import| import.module_name.eq_ignore_ascii_case("kernel32.dll"))
        );
    }

    #[test]
    fn rejects_memory_that_is_not_an_image() {
        let not_an_image = [0u8; 4096];

        // SAFETY: the buffer is readable, and the parser stops at its first two bytes.
        let module = unsafe { PeModule::from_memory(&GUM, not_an_image.as_ptr() as u64) };

        assert!(module.is_none());
    }
}
