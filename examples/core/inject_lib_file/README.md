```sh
# Enter the example directory
cd examples/core/inject_lib_file/

# Build the library and the executable
cargo build --release --lib
cargo build --release

# Execute it
../../../target/release/inject_lib_file <PID> <LIB_FILE_PATH>

# Examples (the library is libinject_example.dylib on macOS, and inject_example.dll on Windows):
../../../target/release/inject_lib_file 4178767 ../../../target/release/libinject_example.so
../../../target/release/inject_lib_file $(ps -ax | grep Twitter | grep -v "grep" | awk '{print $1}') ../../../target/release/libinject_example.so
```
