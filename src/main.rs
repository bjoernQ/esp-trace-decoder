use clap::Parser;
use std::path::PathBuf;
use tracedecode::parse_trace;

#[derive(Parser)]
struct Cli {
    trace_file: PathBuf,

    #[arg(short, long)]
    elf: Vec<PathBuf>,
}

fn main() {
    pretty_env_logger::init();

    let cli = Cli::parse();

    let hex_trace = std::fs::read_to_string(&cli.trace_file).unwrap();
    let mut data: Vec<u8> = Vec::new();

    let hex_chars: Vec<char> = hex_trace.chars().into_iter().collect();
    for i in (0..hex_trace.len()).step_by(2) {
        let b = u8::from_str_radix(&format!("{}{}", hex_chars[i], hex_chars[i + 1]), 16).unwrap();
        data.push(b);
    }

    let elf_files = &cli.elf;

    let execution_path = parse_trace(data, elf_files);

    println!("{:#x?}", &execution_path);
}
