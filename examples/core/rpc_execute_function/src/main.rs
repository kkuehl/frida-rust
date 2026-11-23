use frida::{DeviceManager, ErrorKind, Message};
use serde_json::json;

const SCRIPT: &str = r#"
    var globalVar = 0;

    rpc.exports = {
        increment: function() {
            globalVar += 1;
            console.log("globalVar incremented by 1");
        },

        nIncrement: function(n) {
            globalVar += n;
            console.log("globalVar incremented by " + n);
        },

        getValue: function() {
            return globalVar;
        },

        sumVals: function(vals, b) {
            let sum = 0
            for (let i=0; i < vals.length; i++) {
                sum += vals[i]
            }
            return sum;
        },

        bye: function(name) {
            console.log("Bye " + name);
        }
    };
"#;

fn main() -> Result<(), frida::Error> {
    let manager = DeviceManager::new()?;
    let device = manager.get_local_device()?;
    println!("[*] Frida version: {}", frida::version());
    println!("[*] Device name: {}", device.name());

    // Attach to this very program.
    let session = device.attach(0, None, None)?;
    let script = session.create_script(SCRIPT, None, None)?;
    let _handler = script.on_message(|message, _data| match message {
        Message::Log(log) => println!("[*] {:?}: {:?}", log.level, log.payload),
        other => println!("{other:?}"),
    });
    script.load(None)?;
    println!("[*] Script loaded.");

    let exports = script.list_exports(None)?;
    println!("{exports:?}");

    // Calling a function named by `list_exports`. Expect a log message to be printed.
    if let Some(first) = exports.first() {
        script.call_export(first, &[], None)?;
    }

    // Calling a function with a "Number" argument.
    script.call_export("nIncrement", &[json!(2)], None)?;

    // Getting the returned value.
    let value = script.call_export("getValue", &[], None)?;
    println!("js_global_var: {value}");

    // Sending a string as an argument. Expect a log message to be printed.
    script.call_export("bye", &[json!("Potato")], None)?;

    // Sending several arguments.
    let total = script.call_export("sumVals", &[json!([1, 2, 3, 4]), json!(true)], None)?;
    println!("total: {total}");

    // What an error from JavaScript looks like.
    match script.call_export("NonExistentFunc", &[json!([1, 2, 3, 4]), json!(true)], None) {
        Err(error) if error.kind() == ErrorKind::Rpc => {
            println!("This is an error from JS: {error}");
        }
        other => println!("Unexpected: {other:?}"),
    }

    script.unload(None)?;
    println!("[*] Script unloaded");
    session.detach(None)?;
    println!("[*] Session detached");
    println!("Exiting...");
    Ok(())
}
