use frida::{DeviceManager, ScriptOptions, ScriptRuntime};

const BYTECODE_PATH: &str = "compiled.bin";

const SCRIPT_SOURCE: &str = r#"
    console.log("Hello from precompiled bytecode! pid=" + Process.id);
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = DeviceManager::new()?;
    let device = manager.get_local_device()?;

    println!("[*] Frida version: {}", frida::version());
    println!("[*] Device: {}", device.name());

    let session = device.attach(0, None, None)?;
    println!("[*] Attached to self (pid=0)");

    // 1. Compile JS -> bytecode with the QJS runtime.
    //    Bytecode is runtime-specific: load with the same runtime.
    let compile_opts = ScriptOptions::new()
        .name("compile_script_example")
        .runtime(ScriptRuntime::Qjs);
    let bytecode = session.compile_script(SCRIPT_SOURCE, Some(&compile_opts), None)?;
    println!("[*] Compiled {} bytes of bytecode", bytecode.len());

    // 2. Demonstrate the ship-as-artifact workflow: write to disk, read back.
    std::fs::write(BYTECODE_PATH, &bytecode)?;
    println!("[*] Wrote bytecode to {}", BYTECODE_PATH);
    let loaded = std::fs::read(BYTECODE_PATH)?;
    println!("[*] Read {} bytes back from disk", loaded.len());

    // 3. Load the bytecode through create_script_from_bytes.
    let load_opts = ScriptOptions::new()
        .name("compile_script_example")
        .runtime(ScriptRuntime::Qjs);
    let script = session.create_script_from_bytes(&loaded, Some(&load_opts), None)?;

    let _handler = script.on_message(|message, _data| {
        println!("- {message:?}");
    });
    script.load(None)?;
    println!("[*] Script loaded from bytecode");

    script.unload(None)?;
    println!("[*] Script unloaded");

    session.detach(None)?;
    println!("[*] Session detached");

    let _ = std::fs::remove_file(BYTECODE_PATH);
    Ok(())
}
