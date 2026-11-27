use frida::{DeviceManager, Message};
use std::{thread, time::Duration};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manager = DeviceManager::new()?;
    let device = manager.get_local_device()?;
    println!("[*] Frida version: {}", frida::version());
    println!("[*] Device name: {}", device.name());

    // Attach to the program
    let session = device.attach(0, None, None)?;

    let script_source = r#"
        var globalVar = 0;
        console.log("Logging message from JS");
        console.warn("Warning message from JS");
        console.debug("Debug message from JS");
        console.error("Error message from JS");
        send("Send message from JS");

        let send_data = [1, 2 ,3];
        send("Send message with data", send_data);

        rpc.exports = {
            increment: function() {
                globalVar += 1;
                return globalVar;
            },
            getvalue: function() {
                return globalVar;
            }
        };
    "#;
    let script = session.create_script(script_source, None, None)?;

    let _handler = script.on_message(|message, data| match message {
        Message::Log(msg) => println!("[*] {:?}: {:?}", msg.level, msg.payload),
        Message::Send(msg) => {
            if let Some(data) = data {
                println!("[*] Send: {:?}, Data: {:?}", msg.payload, data);
            } else {
                println!("[*] Send: {:?}", msg.payload);
            }
        }
        other => println!("- {other:?}"),
    });

    script.load(None)?;
    println!("[*] Script loaded.");

    println!("{:?}", script.list_exports(None)?);

    for _ in 0..2 {
        thread::sleep(Duration::from_secs(1));
        println!("{:?}", script.list_exports(None)?);
    }

    script.unload(None)?;
    println!("[*] Script unloaded");

    session.detach(None)?;
    println!("[*] Session detached");
    println!("Exiting...");
    Ok(())
}
