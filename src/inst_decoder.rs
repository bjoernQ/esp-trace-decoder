#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub struct RiscvRegisters {
    pub pc: u32,
    pub registers: [u32; 32],
}

#[derive(Debug)]
pub struct NextAddress {
    pub next_instruction: Option<u32>,
    pub branched: Option<u32>,
}

pub fn next_address(insn: &[u8], pc: u32) -> NextAddress {
    let candidates = estimate_next_inferable_pc(insn, pc);

    let next_instruction = if candidates.len() > 0 {
        Some(candidates[0])
    } else {
        None
    };

    let branched = if candidates.len() > 1 {
        Some(candidates[1])
    } else {
        None
    };

    NextAddress {
        next_instruction,
        branched,
    }
}

pub fn estimate_next_inferable_pc(insn: &[u8], pc: u32) -> Vec<u32> {
    let mut candiates = Vec::new();

    let insn_len = if insn[0] & 0b11 == 0b11 { 4 } else { 2 };
    candiates.push(pc + insn_len);

    match insn_len {
        4 => {
            let inst = u32::from_le_bytes(insn.try_into().unwrap());

            if (inst & 0b111_1111) == 0b110_1111 {
                // JAL
                let offset_20 = (inst & 0b100000000000_00000_000_00000_00000_00) >> 31;
                let offset_10_1 = (inst & 0b011111111110_00000_000_00000_00000_00) >> 21;
                let offset_19_12 = (inst & 0b000000000000_11111_111_00000_00000_00) >> 12;
                let offset_11 = (inst & 0b000000000001_00000_000_00000_00000_00) >> 20;
                let offset = (offset_10_1 << 1)
                    | (offset_11 << 11)
                    | (offset_19_12 << 12)
                    | (offset_20 << 20);

                candiates.clear();
                candiates.push(((pc as i64 + sext(offset, 20) as i64) as u32) & !1);
            } else if (inst & 0b11111_11) == 0b11000_11 {
                // BEQ, BNE, BLT, GE, BLTU, BGEU
                let offset_12 = (inst & 0b100000000000_00000_000_00000_00000_00) >> 31;
                let offset_10_5 = (inst & 0b011111100000_00000_000_00000_00000_00) >> 25;
                let offset_4_1 = (inst & 0b1111_0_00000_00) >> 8;
                let offset_11 = (inst & 0b1_00000_00) >> 7;
                let offset =
                    (offset_12 << 12) | (offset_11 << 11) | (offset_10_5 << 5) | (offset_4_1 << 1);

                candiates.push(((pc as i64 + sext(offset, 12) as i64) as u32) & !1);
            }
        }
        2 => {
            let inst = u16::from_le_bytes(insn[0..2].try_into().unwrap());

            if (inst & 0b111_00000000000_11) == 0b101_00000000000_01 {
                // C.J
                let imm = ((inst & 0b000_11111111111_00) as u32) >> 2;
                let offset_5 = imm & 0b1;
                let offset_3_1 = (imm & 0b1110) >> 1;
                let offset_7 = (imm & 0b10000) >> 4;
                let offset_6 = (imm & 0b100000) >> 5;
                let offset_10 = (imm & 0b1000000) >> 6;
                let offset_9_8 = (imm & 0b110000000) >> 7;
                let offset_4 = (imm & 0b1000000000) >> 9;
                let offset_11 = (imm & 0b10000000000) >> 10;

                let offset = (offset_3_1 << 1)
                    | (offset_4 << 4)
                    | (offset_5 << 5)
                    | (offset_6 << 6)
                    | (offset_7 << 7)
                    | (offset_9_8 << 8)
                    | (offset_10 << 10)
                    | (offset_11 << 11);

                candiates.clear();
                candiates.push(((pc as i64 + sext(offset, 11) as i64) as u32) & !1);
            } else if (inst & 0b111_00000000000_11) == 0b110_00000000000_01 {
                // C.BEQZ

                let imm6_2 = ((inst & 0b11111_00) as u32) >> 2;
                let imm12_10 = ((inst & 0b111_0000000000) as u32) >> 10;

                let offset_5 = imm6_2 & 0b1;
                let offset_2_1 = (imm6_2 & 0b110) >> 1;
                let offset_7_6 = (imm6_2 & 0b11000) >> 3;
                let offset_4_3 = imm12_10 & 0b11;
                let offset_8 = (imm12_10 & 0b100) >> 2;

                let offset = (offset_2_1 << 1)
                    | (offset_4_3 << 3)
                    | (offset_5 << 5)
                    | (offset_7_6 << 6)
                    | (offset_8 << 8);

                candiates.push(((pc as i64 + sext(offset, 8) as i64) as u32) & !1);
            } else if (inst & 0b111_00000000000_11) == 0b111_00000000000_01 {
                // C.BNEZ

                let imm6_2 = ((inst & 0b11111_00) as u32) >> 2;
                let imm12_10 = ((inst & 0b111_0000000000) as u32) >> 10;

                let offset_5 = imm6_2 & 0b1;
                let offset_2_1 = (imm6_2 & 0b110) >> 1;
                let offset_7_6 = (imm6_2 & 0b11000) >> 3;
                let offset_4_3 = imm12_10 & 0b11;
                let offset_8 = (imm12_10 & 0b100) >> 2;

                let offset = (offset_2_1 << 1)
                    | (offset_4_3 << 3)
                    | (offset_5 << 5)
                    | (offset_7_6 << 6)
                    | (offset_8 << 8);

                candiates.push(((pc as i64 + sext(offset, 8) as i64) as u32) & !1);
            } else if (inst & 0b111_00000000000_11) == 0b001_00000000000_01 {
                // C.JAL
                let imm = ((inst & 0b000_11111111111_00) as u32) >> 2;
                let offset_5 = imm & 0b1;
                let offset_3_1 = (imm & 0b1110) >> 1;
                let offset_7 = (imm & 0b10000) >> 4;
                let offset_6 = (imm & 0b100000) >> 5;
                let offset_10 = (imm & 0b1000000) >> 6;
                let offset_9_8 = (imm & 0b110000000) >> 7;
                let offset_4 = (imm & 0b1000000000) >> 9;
                let offset_11 = (imm & 0b10000000000) >> 10;

                let offset = (offset_3_1 << 1)
                    | (offset_4 << 4)
                    | (offset_5 << 5)
                    | (offset_6 << 6)
                    | (offset_7 << 7)
                    | (offset_9_8 << 8)
                    | (offset_10 << 10)
                    | (offset_11 << 11);

                candiates.clear();
                candiates.push(((pc as i64 + sext(offset, 11) as i64) as u32) & !1);
            }
        }
        _ => panic!("Unexpected insn_len"),
    }

    candiates
}

pub fn is_inferable_branch(insn: &[u8]) -> bool {
    let insn_len = if insn[0] & 0b11 == 0b11 { 4 } else { 2 };

    match insn_len {
        4 => {
            let inst = u32::from_le_bytes(insn.try_into().unwrap());

            if (inst & 0b11111_11) == 0b11000_11 {
                // BEQ, BNE, BLT, BGE, BLTU, BGEU
                true
            } else {
                false
            }
        }
        2 => {
            let inst = u16::from_le_bytes(insn[0..2].try_into().unwrap());

            if (inst & 0b111_00000000000_11) == 0b110_00000000000_01 {
                // C.BEQZ
                true
            } else if (inst & 0b111_00000000000_11) == 0b111_00000000000_01 {
                // C.BNEZ
                true
            } else {
                false
            }
        }

        _ => panic!("Unexpected insn_len"),
    }
}

pub fn is_inferable_jump(insn: &[u8]) -> bool {
    let insn_len = if insn[0] & 0b11 == 0b11 { 4 } else { 2 };

    match insn_len {
        4 => {
            let inst = u32::from_le_bytes(insn.try_into().unwrap());

            if (inst & 0b111_1111) == 0b110_1111 {
                // JAL
                true
            } else {
                false
            }
        }
        2 => {
            let inst = u16::from_le_bytes(insn[0..2].try_into().unwrap());

            if (inst & 0b111_00000000000_11) == 0b101_00000000000_01 {
                // C.J
                true
            } else if (inst & 0b111_00000000000_11) == 0b001_00000000000_01 {
                // C.JAL
                true
            } else {
                false
            }
        }

        _ => panic!("Unexpected insn_len"),
    }
}

pub fn is_uninferable_branch(insn: &[u8]) -> bool {
    let insn_len = if insn[0] & 0b11 == 0b11 { 4 } else { 2 };

    match insn_len {
        4 => {
            let inst = u32::from_le_bytes(insn.try_into().unwrap());

            if (inst & 0b111_00000_11111_11) == 0b000_00000_11001_11 {
                // JALR
                true
            } else if inst == 0b00110000001000000000000001110011 {
                // MRET
                true
            } else if inst == 0b00000000000000000000000001110011 {
                // ECALL
                true
            } else if inst == 0b00000000000100000000000001110011 {
                // EBREAK
                true
            } else {
                false
            }
        }
        2 => {
            let inst = u16::from_le_bytes(insn[0..2].try_into().unwrap());

            if (inst & 0b111_1_00000_11111_11) == 0b100_00000000000_10 {
                // C.JR incl. C.RET
                true
            } else if (inst & 0b1111_0000_0111_1111) == 0b1001_0000_0000_0010 {
                // C.JALR
                true
            } else if inst == 0b1001000000000010 {
                // C.EBREAK
                true
            } else {
                false
            }
        }
        _ => panic!("Unexpected insn_len"),
    }
}

fn sext(value: u32, sign_bit: usize) -> i32 {
    if value & (1 << sign_bit) != 0 {
        ((0b1 << (sign_bit - 1)) - (value & setbits(sign_bit - 1)) as i32) * -1
    } else {
        value as i32
    }
}

fn setbits(x: usize) -> u32 {
    u32::MAX >> (32 - x)
}

#[test]
fn test_non_branching_uncompressed() {
    let pc = 0x42000070;
    let isn = [0x97, 0x11, 0xc8, 0xfd];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], 0x42000074);
}

#[test]
fn test_non_branching_compressed() {
    let pc = 0x42000060;
    let isn = [0x01, 0x4c, 0xff, 0xff];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], 0x42000062);
}

#[test]
fn test_branching_uncompressed_jal() {
    let pc = 0x42000308;
    let isn = [0xef, 0x00, 0xc0, 0x16];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], 0x42000474);
}

#[test]
fn test_branching_uncompressed_jal2() {
    let pc = 0x40022ce2;
    let isn = [0xef, 0x60, 0x4f, 0xee];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], 0x400193c6);
}

#[test]
fn test_branching_uncompressed_beq() {
    let pc = 0x42000b74;
    let isn = [0x63, 0x05, 0xb5, 0x00];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 2);
    assert_eq!(res[0], 0x42000b78);
    assert_eq!(res[1], 0x42000b7e);
}

#[test]
fn test_branching_uncompressed_bne() {
    let pc = 0x420000cc;
    let isn = [0x63, 0x18, 0xb5, 0x00];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 2);
    assert_eq!(res[0], 0x420000d0);
    assert_eq!(res[1], 0x420000dc);
}

#[test]
fn test_branching_uncompressed_blt() {
    let pc = 0x4200125e;
    let isn = [0x63, 0x44, 0xb5, 0x00];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 2);
    assert_eq!(res[0], 0x42001262);
    assert_eq!(res[1], 0x42001266);
}

#[test]
fn test_branching_compressed_j() {
    let pc = 0x42002322;
    let isn = [0x61, 0xbf, 0x00, 0x00];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], 0x420022ba);
}

#[test]
fn test_branching_compressed_beqz() {
    let pc = 0x420003c4;
    let isn = [0x7d, 0xd9];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 2);
    assert_eq!(res[0], 0x420003c6);
    assert_eq!(res[1], 0x420003ba);
}

#[test]
fn test_branching_compressed_beqz2() {
    let pc = 0x420004f4;
    let isn = [0x11, 0xc9];

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 2);
    assert_eq!(res[0], 0x420004f6);
    assert_eq!(res[1], 0x42000508);
}

#[test]
fn test_branching_compressed_beqz3() {
    let pc = 0x42002dda;
    let isn = [0xd5, 0xcc];

    assert_eq!(true, is_inferable_branch(&isn));
    assert_eq!(false, is_uninferable_branch(&isn));

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 2);
    assert_eq!(res[0], 0x42002ddc);
    assert_eq!(res[1], 0x42002e96);
}

#[test]
fn test_uncompressed_j() {
    let pc = 0x40000058;
    let isn = [0x6f, 0x20, 0x32, 0x48];

    assert_eq!(false, is_inferable_branch(&isn));
    assert_eq!(false, is_uninferable_branch(&isn));
    assert_eq!(true, is_inferable_jump(&isn));

    let res = estimate_next_inferable_pc(&isn, pc);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], 0x40022cda);
}
