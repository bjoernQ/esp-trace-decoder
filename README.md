# esp-trace-decoder

This is a decoder for traces generated by the ESP32-C6's / ESP32-H2's RISCV TRACE Encoder.

## Usage

Execute one of the examples (`cargo run --release`). Then copy the dumped trace data and save it as a file.

Make sure you have access to the ROM ELF files (https://github.com/espressif/esp-rom-elfs) because in order to decode the trace data we need access to all the traced instructions.

Run the decoder like this:
`cargo run -- YOUR_SAVED_TRACE --elf example-esp32h2\target\riscv32imac-unknown-none-elf\release\example-esp32h2 --elf PATH_TO_ROM_ELF\esp32h2_rev0_rom.elf`

Then you should see the decoded execution path.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.