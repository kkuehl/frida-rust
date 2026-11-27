use frida::{DeviceManager, Message, ScriptOptions, ScriptRuntime};
use std::sync::mpsc;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <PID>", args[0]);
        return Ok(());
    }

    let manager = DeviceManager::new()?;
    let pid: u32 = args[1].parse()?;

    if let Some(device) = manager.enumerate_devices(None)?.into_iter().next() {
        println!("[*] First device: {}", device.name());

        let session = device.attach(pid, None, None)?;
        println!("[*] Attached");

        let options = ScriptOptions::new()
            .name("example")
            .runtime(ScriptRuntime::Qjs);
        let script = session.create_script("console.log('Log test');", Some(&options), None)?;

        let (sender, messages) = mpsc::channel();
        let _handler = script.on_message(move |message, _data| {
            let _ = sender.send(message);
        });

        script.load(None)?;
        println!("[*] Script loaded");
        while let Ok(message) = messages.recv_timeout(Duration::from_millis(500)) {
            match message {
                Message::Log(log) => println!("[*] {:?}: {:?}", log.level, log.payload),
                other => println!("{other:?}"),
            }
        }

        script.unload(None)?;
        println!("[*] Script unloaded");

        session.detach(None)?;
        println!("[*] Session detached");
    }
    Ok(())
}
