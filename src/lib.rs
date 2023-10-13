use std::path::PathBuf;
pub(crate) mod inst_decoder;
pub(crate) mod trace_decoder;
use object::{File, Object, ObjectSection};

use crate::trace_decoder::*;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    Corrupted,
}

/// Parse the given trace data by using the given ELF files
pub fn parse_trace(data: Vec<u8>, elf_files: &Vec<PathBuf>) -> Result<Vec<u32>, Error> {
    let mut execution_path = Vec::new();

    let parsed = parse(&data)?;

    // load elfs
    let mut elfs = Vec::new();
    let mut obj_files = Vec::new();
    for elf in elf_files {
        let bin_data = std::fs::read(elf).unwrap();
        elfs.push(bin_data);
    }
    for i in 0..elfs.len() {
        let obj_file = object::File::parse(&*elfs[i]).unwrap();
        obj_files.push(obj_file);
    }

    log::debug!("Parsed {:#x?}", &parsed);

    let (first_sync, _) = parsed
        .iter()
        .enumerate()
        .find(|(_, packet)| matches!(packet, Packet::Sync(_, _)))
        .unwrap();
    log::debug!("first sync packet at index {first_sync}");

    let last_packet = if let Packet::Support(_, _) = *parsed.last().unwrap() {
        parsed.len() - 2
    } else {
        log::debug!("Last packet is not a support packet. Data corrupted?");
        parsed.len() - 1
    };

    let end_pc = if let Packet::Address(_, addr) = parsed[last_packet] {
        addr.address
    } else {
        log::debug!("No data packet before support ending packet.");
        return Err(Error::Corrupted);
    };

    let mut branch_map: Vec<bool> = Vec::new();
    let mut current = first_sync;
    let mut pc = 0;
    let mut uninferable = false;
    let mut last_taken_branch_map = None;

    'outer: loop {
        match parsed[current] {
            Packet::Sync(_, sync) => {
                // should a sync be considered an address for uninferable branches?
                pc = sync.address;

                let insn = get_instruction(&obj_files, pc);
                // if an inferable branch -> push if it should be taken or not
                if crate::inst_decoder::is_inferable_branch(&insn) {
                    log::debug!(
                        "sync is an inferable branch, branch taken = {}",
                        !sync.branch
                    );
                    branch_map.insert(0, !sync.branch);
                }
                current += 1;
            }
            Packet::Address(_, address) => {
                pc = address.address;
                current += 1;
            }
            Packet::AddressBranchMap(_, map) => {
                if uninferable {
                    pc = map.address;
                    current += 1;
                } else {
                    if last_taken_branch_map == Some(current) {
                        current += 1;
                    }
                    last_taken_branch_map = Some(current);
                    let count = if map.branches != 0 { map.branches } else { 32 };
                    for i in 0..count {
                        branch_map.push(((map.branch_map >> i) & 0b1) == 0);
                    }
                }
            }
            Packet::NoAddressBranchMap(_, map) => {
                let count = if map.branches != 0 { map.branches } else { 32 };
                for i in 0..count {
                    branch_map.push(((map.branch_map >> i) & 0b1) == 0);
                }
                current += 1;
            }
            _ => {
                current += 1;
                continue;
            }
        }
        uninferable = false;

        loop {
            if execution_path.is_empty() || execution_path[execution_path.len() - 1] != pc {
                execution_path.push(pc);
            }

            if pc == end_pc {
                break 'outer;
            }

            log::debug!("PC={:x}", pc);
            let insn = get_instruction(&obj_files, pc);
            log::debug!("  Instruction {:x?}", &insn);

            log::debug!(
                "   {:x?} infer={} uninfer={} jmp-infer={}",
                crate::inst_decoder::next_address(&insn, pc),
                crate::inst_decoder::is_inferable_branch(&insn),
                crate::inst_decoder::is_uninferable_branch(&insn),
                crate::inst_decoder::is_inferable_jump(&insn),
            );
            if !crate::inst_decoder::is_inferable_branch(&insn)
                && !crate::inst_decoder::is_uninferable_branch(&insn)
                && !crate::inst_decoder::is_inferable_jump(&insn)
            {
                pc = crate::inst_decoder::next_address(&insn, pc)
                    .next_instruction
                    .unwrap();
            } else if crate::inst_decoder::is_inferable_branch(&insn) {
                if branch_map.is_empty() {
                    log::debug!("empty branch map");
                    continue 'outer;
                }

                log::debug!("take from branch map");
                let taken = *branch_map.first().unwrap();
                branch_map.remove(0);
                let next = crate::inst_decoder::next_address(&insn, pc);
                pc = if taken {
                    next.branched.unwrap()
                } else {
                    next.next_instruction.unwrap()
                };
            } else if crate::inst_decoder::is_inferable_jump(&insn) {
                let next = crate::inst_decoder::next_address(&insn, pc);
                pc = next.next_instruction.unwrap();
            } else if crate::inst_decoder::is_uninferable_branch(&insn) {
                log::info!("uninferable branch");
                uninferable = true;
                continue 'outer;
            }
        }
    }

    Ok(execution_path)
}

pub fn get_instruction(obj_files: &Vec<File<'_>>, address: u32) -> Vec<u8> {
    let mut res = Vec::new();
    for obj_file in obj_files {
        for section in obj_file.sections() {
            let found = section.data_range(address as u64, 2u64);
            if let Ok(Some(data)) = found {
                let found = section.data_range(address as u64, 4u64);
                if let Ok(Some(data)) = found {
                    res.extend_from_slice(data);
                    break;
                }
                res.extend_from_slice(data);
                break;
            }
        }

        if res.len() > 0 {
            break;
        }
    }

    res
}
