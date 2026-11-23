use frida::DeviceManager;

fn main() -> Result<(), frida::Error> {
    let manager = DeviceManager::new()?;
    let device = manager.get_local_device()?;
    for process in device.enumerate_processes(None, None)? {
        println!("{} {:?}", process.name(), process.pid());
    }
    Ok(())
}
