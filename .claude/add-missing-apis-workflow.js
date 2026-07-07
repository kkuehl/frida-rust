export const meta = {
  name: 'add-missing-gum-apis',
  description: 'Add all missing GUM API wrappers to frida-rust',
  phases: [
    { title: 'Add ThumbWriter' },
    { title: 'Add MipsWriter' },
    { title: 'Add DarwinModule' },
    { title: 'Add KernelAPI' },
    { title: 'Add MetalCollections' },
    { title: 'Add Spinlock' },
    { title: 'Add InspectorServer' },
    { title: 'Add MemoryMap' },
    { title: 'Verify' },
  ],
}

const APIS = [
  {
    name: 'ThumbWriter',
    phase: 'Add ThumbWriter',
    file: 'frida-gum/src/instruction_writer/arm/thumb_writer.rs',
    description: 'ARM Thumb/Thumb-2 instruction writer for 32-bit ARM code generation',
    platform: 'arm',
    priority: 'critical',
  },
  {
    name: 'MipsWriter',
    phase: 'Add MipsWriter',
    file: 'frida-gum/src/instruction_writer/mips/writer.rs',
    description: 'MIPS instruction writer for MIPS architecture support',
    platform: 'mips',
    priority: 'medium',
  },
  {
    name: 'DarwinModule',
    phase: 'Add DarwinModule',
    file: 'frida-gum/src/darwin_module.rs',
    description: 'Mach-O binary parsing and inspection for macOS/iOS',
    platform: 'darwin',
    priority: 'critical',
  },
  {
    name: 'KernelAPI',
    phase: 'Add KernelAPI',
    file: 'frida-gum/src/kernel.rs',
    description: 'Kernel memory operations and module enumeration',
    platform: 'all',
    priority: 'high',
  },
  {
    name: 'MetalArray',
    phase: 'Add MetalCollections',
    file: 'frida-gum/src/metal_array.rs',
    description: 'Lock-free array for signal-safe callbacks',
    platform: 'all',
    priority: 'medium',
  },
  {
    name: 'MetalHashTable',
    phase: 'Add MetalCollections',
    file: 'frida-gum/src/metal_hash_table.rs',
    description: 'Lock-free hash table for signal-safe callbacks',
    platform: 'all',
    priority: 'medium',
  },
  {
    name: 'Spinlock',
    phase: 'Add Spinlock',
    file: 'frida-gum/src/spinlock.rs',
    description: 'Platform-agnostic spinlock primitive',
    platform: 'all',
    priority: 'low',
  },
  {
    name: 'InspectorServer',
    phase: 'Add InspectorServer',
    file: 'frida-gum/src/inspector_server.rs',
    description: 'Chrome DevTools protocol debugging server',
    platform: 'all',
    priority: 'low',
  },
  {
    name: 'MemoryMap',
    phase: 'Add MemoryMap',
    file: 'frida-gum/src/memory_map.rs',
    description: 'Cached memory range enumeration',
    platform: 'all',
    priority: 'low',
  },
]

phase('Add ThumbWriter')
const thumbResult = await agent(
  `Create ARM Thumb instruction writer wrapper.

**Task**: Implement ThumbWriter in frida-gum/src/instruction_writer/arm/thumb_writer.rs

**Requirements**:
1. Read target/debug/build/frida-gum-sys-*/out/bindings.rs to find all gum_thumb_writer_* functions
2. Create a complete Rust wrapper following the pattern in x86_64/writer.rs and aarch64/writer.rs
3. Implement InstructionWriter trait
4. Add platform cfg gates: #[cfg(target_arch = "arm")]
5. Include proper documentation
6. Add copyright header: "Copyright © 2026 Kirby Kuehl"
7. Create frida-gum/src/instruction_writer/arm/mod.rs if needed
8. Update frida-gum/src/instruction_writer.rs to export arm module
9. Run cargo fmt and cargo clippy
10. Do NOT commit

Report: file path and line count.`,
  { phase: 'Add ThumbWriter', schema: { type: 'object', properties: { file: { type: 'string' }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['file', 'lines', 'status'] } }
)

phase('Add MipsWriter')
const mipsResult = await agent(
  `Create MIPS instruction writer wrapper.

**Task**: Implement MipsWriter in frida-gum/src/instruction_writer/mips/writer.rs

**Requirements**:
1. Read bindings.rs to find all gum_mips_writer_* functions
2. Create complete Rust wrapper
3. Implement InstructionWriter trait
4. Add platform cfg gates: #[cfg(target_arch = "mips")] or #[cfg(target_arch = "mips64")]
5. Include proper documentation
6. Add copyright header: "Copyright © 2026 Kirby Kuehl"
7. Create frida-gum/src/instruction_writer/mips/mod.rs
8. Update frida-gum/src/instruction_writer.rs to export mips module
9. Run cargo fmt and cargo clippy
10. Do NOT commit

Report: file path and line count.`,
  { phase: 'Add MipsWriter', schema: { type: 'object', properties: { file: { type: 'string' }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['file', 'lines', 'status'] } }
)

phase('Add DarwinModule')
const darwinResult = await agent(
  `Create Darwin (macOS/iOS) module wrapper for Mach-O binary inspection.

**Task**: Implement DarwinModule in frida-gum/src/darwin_module.rs

**Requirements**:
1. Read bindings.rs to find all gum_darwin_module_* and gum_darwin_grafter_* functions
2. Create DarwinModule struct with all methods
3. Create DarwinGrafter struct
4. Add enums/structs for imports, exports, symbols, sections, fixups, rebases, binds, TLV descriptors
5. Add platform cfg gates: #[cfg(target_vendor = "apple")]
6. Include comprehensive documentation
7. Add copyright header: "Copyright © 2026 Kirby Kuehl"
8. Update frida-gum/src/lib.rs to add: pub mod darwin_module;
9. Run cargo fmt and cargo clippy
10. Do NOT commit

Report: file path and line count.`,
  { phase: 'Add DarwinModule', schema: { type: 'object', properties: { file: { type: 'string' }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['file', 'lines', 'status'] } }
)

phase('Add KernelAPI')
const kernelResult = await agent(
  `Create kernel memory operations API wrapper.

**Task**: Implement Kernel API in frida-gum/src/kernel.rs

**Requirements**:
1. Read bindings.rs to find all gum_kernel_* functions
2. Create Kernel struct with methods for: scan, read, write, enumerate_ranges, enumerate_modules, alloc, free
3. Add KernelModule, KernelScanMatch structs
4. Include proper error handling
5. Add comprehensive documentation
6. Add copyright header: "Copyright © 2026 Kirby Kuehl"
7. Update frida-gum/src/lib.rs to add: pub mod kernel;
8. Run cargo fmt and cargo clippy
9. Do NOT commit

Report: file path and line count.`,
  { phase: 'Add KernelAPI', schema: { type: 'object', properties: { file: { type: 'string' }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['file', 'lines', 'status'] } }
)

phase('Add MetalCollections')
const metalResult = await agent(
  `Create lock-free collection wrappers for signal-safe callbacks.

**Task**: Implement MetalArray and MetalHashTable

**Requirements**:
1. Read bindings.rs to find gum_metal_array_* and gum_metal_hash_table_* functions
2. Create frida-gum/src/metal_array.rs with MetalArray<T> wrapper
3. Create frida-gum/src/metal_hash_table.rs with MetalHashTable<K, V> wrapper
4. Implement safe Rust APIs wrapping the C functions
5. Add comprehensive documentation explaining signal-safety
6. Add copyright header: "Copyright © 2026 Kirby Kuehl"
7. Update frida-gum/src/lib.rs to add both modules
8. Run cargo fmt and cargo clippy
9. Do NOT commit

Report: files created and total line count.`,
  { phase: 'Add MetalCollections', schema: { type: 'object', properties: { files: { type: 'array', items: { type: 'string' } }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['files', 'lines', 'status'] } }
)

phase('Add Spinlock')
const spinlockResult = await agent(
  `Create spinlock primitive wrapper.

**Task**: Implement Spinlock in frida-gum/src/spinlock.rs

**Requirements**:
1. Read bindings.rs to find gum_spinlock_* functions (init, acquire, release, free)
2. Create Spinlock struct with RAII guard pattern
3. Implement safe Rust API with lock() returning a guard
4. Add documentation
5. Add copyright header: "Copyright © 2026 Kirby Kuehl"
6. Update frida-gum/src/lib.rs
7. Run cargo fmt and cargo clippy
8. Do NOT commit

Report: file path and line count.`,
  { phase: 'Add Spinlock', schema: { type: 'object', properties: { file: { type: 'string' }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['file', 'lines', 'status'] } }
)

phase('Add InspectorServer')
const inspectorResult = await agent(
  `Create Chrome DevTools protocol debugging server wrapper.

**Task**: Implement InspectorServer in frida-gum/src/inspector_server.rs

**Requirements**:
1. Read bindings.rs to find gum_inspector_server_* functions
2. Create InspectorServer struct
3. Add methods for start, stop, get_address
4. Add documentation explaining Chrome DevTools protocol integration
5. Add copyright header: "Copyright © 2026 Kirby Kuehl"
6. Update frida-gum/src/lib.rs
7. Run cargo fmt and cargo clippy
8. Do NOT commit

Report: file path and line count.`,
  { phase: 'Add InspectorServer', schema: { type: 'object', properties: { file: { type: 'string' }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['file', 'lines', 'status'] } }
)

phase('Add MemoryMap')
const memMapResult = await agent(
  `Create cached memory range enumeration wrapper.

**Task**: Implement MemoryMap (different from ModuleMap) in frida-gum/src/memory_map.rs (NOT module_map.rs)

**Requirements**:
1. Read bindings.rs to find GumMemoryMap functions
2. Create MemoryMap struct for cached memory range enumeration
3. Add methods following the C API
4. Add documentation explaining it's an optimization over direct enumeration
5. Add copyright header: "Copyright © 2026 Kirby Kuehl"
6. Update frida-gum/src/lib.rs (use different name to avoid conflict with existing memory_map module)
7. Run cargo fmt and cargo clippy
8. Do NOT commit

Report: file path and line count.`,
  { phase: 'Add MemoryMap', schema: { type: 'object', properties: { file: { type: 'string' }, lines: { type: 'number' }, status: { type: 'string' } }, required: ['file', 'lines', 'status'] } }
)

phase('Verify')
const verifyResult = await agent(
  `Verify all implementations build correctly.

**Task**: Build and test

**Requirements**:
1. Run: cargo fmt --all
2. Run: cargo clippy --all-features -- -D warnings
3. Run: cargo build --all-features
4. If errors, fix them
5. Do NOT commit yet

Report: build status and any issues found.`,
  { phase: 'Verify', schema: { type: 'object', properties: { clippy_passed: { type: 'boolean' }, build_passed: { type: 'boolean' }, issues: { type: 'array', items: { type: 'string' } } }, required: ['clippy_passed', 'build_passed', 'issues'] } }
)

return {
  summary: 'All missing GUM APIs implemented',
  apis_added: APIS.length,
  results: {
    thumb: thumbResult,
    mips: mipsResult,
    darwin: darwinResult,
    kernel: kernelResult,
    metal: metalResult,
    spinlock: spinlockResult,
    inspector: inspectorResult,
    memmap: memMapResult,
    verify: verifyResult,
  },
}
