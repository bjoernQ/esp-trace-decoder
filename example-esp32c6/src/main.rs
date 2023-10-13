#![no_std]
#![no_main]

use hal::{
    clock::ClockControl, peripherals::Peripherals, prelude::*, timer::TimerGroup, trace::*,
};
use esp_backtrace as _;
use esp_println::{print, println};

#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take();
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::boot_defaults(system.clock_control).freeze();

    let timer_group0 = TimerGroup::new(peripherals.TIMG0, &clocks);
    let mut timer0 = timer_group0.timer0;
    timer0.start(1u64.secs());

    let mut trace = Trace::new(peripherals.TRACE);
    let buffer = unsafe { &mut BUFFER[..] };
    trace.start_trace(buffer);

    // traced code
    println!("Hello");
    // end traced code

    let res = trace.stop_trace().unwrap();
    println!("{:?}", res);
    println!("Copy the trace data to a file and use the CLI to decode");
    for i in res.valid_start_index..(res.valid_start_index + res.valid_length) {
        print!("{:02x}", buffer[i % buffer.len()]);
    }
    println!();

    loop {}
}

static mut BUFFER: [u8; 4096 * 4] = [0u8; 4096 * 4];
