use frida::{DeviceManager, DeviceType};

fn main() -> Result<(), frida::Error> {
    let manager = DeviceManager::new()?;

    // get the first usb device (assuming there is one attached)
    let device = manager.get_device_by_type(DeviceType::Usb, None, None)?;
    println!(
        "found {} with type: {}",
        device.name(),
        device.device_type()
    );

    // get the device id and use it to obtain a the device by the id
    let device_id = device.id();
    let device = manager.get_device_by_id(&device_id, None, None)?;
    println!("found {} with id: {}", device.name(), device.id());
    Ok(())
}
