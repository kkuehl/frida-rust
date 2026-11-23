/* This example is in the public domain */

//! The smallest program that uses Frida: nothing needs to be obtained first (frida-core is
//! initialized on first use), and the device manager closes itself when it is dropped.

fn main() -> Result<(), frida::Error> {
    println!("Hello, world!");
    println!("[*] Frida version: {}", frida::version());

    let manager = frida::DeviceManager::new()?;
    let device = manager.get_local_device()?;
    println!("[*] Local device: {}", device.name());
    Ok(())
}
