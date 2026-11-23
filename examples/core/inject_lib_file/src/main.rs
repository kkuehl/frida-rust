use frida::DeviceManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = DeviceManager::new()?;
    let device = manager.get_local_device()?;
    let args: Vec<String> = std::env::args().collect();
    let pid = args[1].parse::<u32>()?;
    let path = args[2].parse::<String>()?;

    println!("[*] Frida version: {}", frida::version());
    println!("[*] Device name: {}", device.name());

    let id = device.inject_library_file(pid, &path, "injected_function", "w00t", None)?;
    println!("*** Injected, id={id}");
    Ok(())
}
