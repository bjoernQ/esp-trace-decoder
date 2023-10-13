pub fn parse(data: &[u8]) -> Result<Vec<Packet>, super::Error> {
    let mut res = Vec::new();
    let mut reader = Reader::new(&data);

    let mut previous_index = None;
    while reader.has_data(8) {
        let start_bit_count = reader.current_bit_count();

        let len = reader.get_bits(5);
        let until = start_bit_count + 8 * len as usize;

        if reader.total_bit_count() <= until {
            break;
        }

        reader.get_bits(3);

        if len == 0 {
            continue;
        }

        if !reader.has_data(len as usize * 8 - 8) {
            break;
        }

        let index = reader.get_bits(16);
        if let Some(previous) = previous_index {
            if previous != index.wrapping_sub(1) {
                log::debug!("prev={} index={}", previous, index);
                break;
            }
        }
        previous_index = Some(index);
        let format = reader.get_bits(2);

        if format == 0b01 {
            // format 1

            let branches = reader.get_bits(5);

            let bits = match branches {
                0 => 0,
                1 => 1,
                2..=3 => 3,
                4..=7 => 7,
                8..=15 => 15,
                16..=32 => 31,
                _ => return Err(super::Error::Corrupted),
            };

            let branch_map = reader.get_bits(if bits != 0 { bits } else { 31 });

            if bits != 0 {
                let address = reader.get_bits(31);
                let bits = match branches {
                    1 => 7,
                    2..=3 => 5,
                    4..=7 => 1,
                    8..=15 => 1,
                    16..=32 => 0, // ?? TRM says 31
                    _ => return Err(super::Error::Corrupted),
                };
                let notify = reader.get_bits(1);
                let updiscon = reader.get_bits(1);
                let _sign_extend = reader.get_bits(bits);

                res.push(Packet::AddressBranchMap(
                    index,
                    AddressBranchMap {
                        address: address << 1,
                        branches: branches as u8,
                        branch_map,
                        notify: notify != 0,
                        updiscon: updiscon != 0,
                    },
                ))
            } else {
                let _sign_extend = reader.get_bits(2);

                res.push(Packet::NoAddressBranchMap(
                    index,
                    NoAddressBranchMap {
                        branches: branches as u8,
                        branch_map,
                    },
                ))
            }
        } else if format == 0b10 {
            // format 2

            let address = reader.get_bits(31);
            let notify = reader.get_bits(1);
            let updiscon = reader.get_bits(1);
            let _sign_extend = reader.get_bits(5);

            res.push(Packet::Address(
                index,
                Address {
                    address: address << 1,
                    notify: notify != 0,
                    updiscon: updiscon != 0,
                },
            ))
        } else if format == 0b11 {
            // format 3

            let subformat = reader.get_bits(2);

            if subformat == 0 {
                let branch = reader.get_bits(1);
                let privilege = reader.get_bits(1);
                let address = reader.get_bits(31);
                let _sign_extend = reader.get_bits(3);

                res.push(Packet::Sync(
                    index,
                    Sync {
                        address: address << 1,
                        branch: branch != 0,
                        privilege: privilege != 0,
                    },
                ))
            } else if subformat == 1 {
                let branch = reader.get_bits(1);
                let privilege = reader.get_bits(1);
                let ecause = reader.get_bits(5);
                let interrupt = reader.get_bits(1);
                let address = reader.get_bits(31);
                let tvalepc = reader.get_bits(32);
                let _sign_extend = reader.get_bits(6);

                res.push(Packet::Exception(
                    index,
                    Exception {
                        address: address << 1,
                        branch: branch != 0,
                        privilege: privilege != 0,
                        ecause: ecause as u8,
                        interrupt: interrupt != 0,
                        tvalepc,
                    },
                ))
            }
            if subformat == 3 {
                let enable = reader.get_bits(1);
                let qual_status = reader.get_bits(2);
                let _sign_extend = reader.get_bits(1);

                res.push(Packet::Support(
                    index,
                    Support {
                        enable: enable != 0,
                        qual_status: qual_status as u8,
                    },
                ))
            }
        }

        reader.skip_until(until);
    }

    Ok(res)
}

#[derive(Debug, Clone, Copy)]
pub struct Sync {
    pub branch: bool,
    pub privilege: bool,
    pub address: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Exception {
    pub branch: bool,
    pub privilege: bool,
    pub ecause: u8,
    pub interrupt: bool,
    pub address: u32,
    pub tvalepc: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Support {
    pub enable: bool,
    pub qual_status: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Address {
    pub address: u32,
    pub notify: bool,
    pub updiscon: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct AddressBranchMap {
    pub address: u32,
    pub branches: u8,
    pub branch_map: u32,
    pub notify: bool,
    pub updiscon: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct NoAddressBranchMap {
    pub branches: u8,
    pub branch_map: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum Packet {
    Sync(u32, Sync),
    Exception(u32, Exception),
    Support(u32, Support),
    Address(u32, Address),
    AddressBranchMap(u32, AddressBranchMap),
    NoAddressBranchMap(u32, NoAddressBranchMap),
}

struct Reader<'a> {
    data: &'a [u8],
    index: usize,
    current_bit: u8,
    bit_count: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            index: 0,
            current_bit: 0,
            bit_count: 0,
        }
    }

    pub fn next_bit(&mut self) -> u32 {
        let out = if self.data[self.index] & (1 << self.current_bit as u32) != 0 {
            1
        } else {
            0
        };
        if self.current_bit < 7 {
            self.current_bit += 1
        } else {
            self.index += 1;
            self.current_bit = 0;
        };
        self.bit_count += 1;
        out
    }

    pub fn get_bits(&mut self, bits: usize) -> u32 {
        let mut res = 0;
        for i in 0..bits {
            res |= self.next_bit() << i;
        }
        res
    }

    pub fn current_bit_count(&self) -> usize {
        self.bit_count
    }

    pub fn skip_until(&mut self, until: usize) {
        while self.bit_count < until {
            self.next_bit();
        }
    }

    pub fn has_data(&self, count: usize) -> bool {
        self.bit_count + count <= self.total_bit_count()
    }

    pub fn total_bit_count(&self) -> usize {
        self.data.len() * 8
    }
}
