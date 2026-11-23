use frida::DeviceManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = DeviceManager::new()?;
    let device = manager.get_local_device()?;
    let args: Vec<String> = std::env::args().collect();
    let pid = args[1].parse::<u32>()?;

    println!("[*] Frida version: {}", frida::version());
    println!("[*] Device name: {}", device.name());

    #[cfg(target_os = "macos")]
    let script_source = include_bytes!("../../../../target/release/libinject_example.dylib");
    #[cfg(not(target_os = "macos"))]
    let script_source = include_bytes!("../../../../target/release/libinject_example.so");
    let id = device.inject_library_blob(pid, script_source, "injected_function", "w00t", None)?;

    println!("*** Injected, id={id}");
    Ok(())
}
