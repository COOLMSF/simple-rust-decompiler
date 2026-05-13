use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use std::collections::BTreeMap;

use crate::binary::{Arch, LoadedBinary};

#[derive(Debug, Clone)]
pub struct DisasmInstr {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub instr: Instruction,
}

#[derive(Debug, Clone)]
pub struct DisasmFunction {
    pub address: u64,
    pub name: String,
    pub instrs: Vec<DisasmInstr>,
}

pub struct Disassembler<'a> {
    binary: &'a LoadedBinary,
}

impl<'a> Disassembler<'a> {
    pub fn new(binary: &'a LoadedBinary) -> Self {
        Self { binary }
    }

    pub fn disassemble_all(&self) -> Result<Vec<DisasmFunction>> {
        let sym_map = self.binary.symbol_map();
        let mut func_addrs: Vec<(u64, String)> = Vec::new();

        // Collect all known function entry points from symbols
        for sym in &self.binary.symbols {
            if !sym.name.is_empty() {
                func_addrs.push((sym.address, sym.name.clone()));
            }
        }

        // Always include entry point
        func_addrs.push((
            self.binary.entry_point,
            "entry".to_string(),
        ));

        // Discover more functions by scanning for CALL targets
        let call_targets = self.discover_call_targets();
        for addr in call_targets {
            if sym_map.contains_key(&addr) {
                continue;
            }
            func_addrs.push((addr, format!("sub_{:x}", addr)));
        }

        func_addrs.sort_by_key(|(a, _)| *a);
        func_addrs.dedup_by_key(|(a, _)| *a);

        let mut functions = Vec::new();
        for (addr, name) in &func_addrs {
            if let Some(func) = self.disassemble_function(*addr, name.clone()) {
                functions.push(func);
            }
        }

        Ok(functions)
    }

    fn discover_call_targets(&self) -> Vec<u64> {
        let mut targets = Vec::new();
        let bitness = match self.binary.arch {
            Arch::X86 => 32u32,
            Arch::X86_64 => 64u32,
        };

        for sec in self.binary.exec_sections() {
            let mut decoder = Decoder::with_ip(
                bitness,
                &sec.data,
                sec.virtual_address,
                DecoderOptions::NONE,
            );
            let mut instr = Instruction::default();
            while decoder.can_decode() {
                decoder.decode_out(&mut instr);
                if instr.mnemonic() == Mnemonic::Call {
                    if instr.op0_kind() == OpKind::NearBranch64
                        || instr.op0_kind() == OpKind::NearBranch32
                        || instr.op0_kind() == OpKind::NearBranch16
                    {
                        targets.push(instr.near_branch_target());
                    }
                }
            }
        }
        targets
    }

    pub fn disassemble_function(&self, start: u64, name: String) -> Option<DisasmFunction> {
        let bitness = match self.binary.arch {
            Arch::X86 => 32u32,
            Arch::X86_64 => 64u32,
        };

        let mut instrs: Vec<DisasmInstr> = Vec::new();
        // Addresses we still need to decode (for branch targets)
        let mut worklist: Vec<u64> = vec![start];
        let mut visited: BTreeMap<u64, bool> = BTreeMap::new();

        while let Some(addr) = worklist.pop() {
            if visited.contains_key(&addr) {
                continue;
            }
            // Decode linearly from this address until a terminal instruction
            if let Some(slice) = self.binary.bytes_from(addr) {
                let mut dec = Decoder::with_ip(bitness, slice, addr, DecoderOptions::NONE);
                let mut instr = Instruction::default();
                loop {
                    if !dec.can_decode() {
                        break;
                    }
                    dec.decode_out(&mut instr);
                    let ia = instr.ip();
                    if visited.contains_key(&ia) {
                        break;
                    }
                    visited.insert(ia, true);

                    let len = instr.len();
                    let mut ibytes = vec![0u8; len];
                    if let Some(src) = self.binary.bytes_at(ia, len) {
                        ibytes.copy_from_slice(src);
                    }
                    instrs.push(DisasmInstr {
                        address: ia,
                        bytes: ibytes,
                        instr,
                    });

                    // Check for terminal / branch
                    let mnem = instr.mnemonic();
                    if is_unconditional_branch(mnem) {
                        if instr.op0_kind() == OpKind::NearBranch64
                            || instr.op0_kind() == OpKind::NearBranch32
                            || instr.op0_kind() == OpKind::NearBranch16
                        {
                            let t = instr.near_branch_target();
                            if self.is_within_binary(t) {
                                worklist.push(t);
                            }
                        }
                        break;
                    }
                    if is_conditional_branch(mnem) {
                        let t = instr.near_branch_target();
                        if self.is_within_binary(t) {
                            worklist.push(t);
                        }
                        // fall-through continues
                    }
                    if is_return(mnem) {
                        break;
                    }
                    // Stop if we jump into a different known function
                    if instrs.len() > 1 {
                        let next_ip = instr.next_ip();
                        if next_ip != start && is_known_func_start(&next_ip, &self.binary.symbols) {
                            break;
                        }
                    }
                    // Safety limit
                    if instrs.len() > 4096 {
                        break;
                    }
                }
            }
        }

        if instrs.is_empty() {
            return None;
        }

        instrs.sort_by_key(|i| i.address);
        instrs.dedup_by_key(|i| i.address);

        Some(DisasmFunction {
            address: start,
            name,
            instrs,
        })
    }

    fn is_within_binary(&self, addr: u64) -> bool {
        self.binary.bytes_from(addr).is_some()
    }
}

fn is_known_func_start(addr: &u64, symbols: &[crate::binary::Symbol]) -> bool {
    symbols.iter().any(|s| &s.address == addr)
}

pub fn is_unconditional_branch(m: Mnemonic) -> bool {
    matches!(m, Mnemonic::Jmp)
}

pub fn is_conditional_branch(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz
            | Mnemonic::Loop
            | Mnemonic::Loope
            | Mnemonic::Loopne
    )
}

pub fn is_return(m: Mnemonic) -> bool {
    matches!(m, Mnemonic::Ret | Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq)
}

/// Return the 64-bit canonical register (e.g. al/ax/eax → rax)
pub fn canonical_reg(r: Register) -> Register {
    match r {
        Register::AL | Register::AH | Register::AX | Register::EAX => Register::RAX,
        Register::BL | Register::BH | Register::BX | Register::EBX => Register::RBX,
        Register::CL | Register::CH | Register::CX | Register::ECX => Register::RCX,
        Register::DL | Register::DH | Register::DX | Register::EDX => Register::RDX,
        Register::SIL | Register::SI | Register::ESI => Register::RSI,
        Register::DIL | Register::DI | Register::EDI => Register::RDI,
        Register::BPL | Register::BP | Register::EBP => Register::RBP,
        Register::SPL | Register::SP | Register::ESP => Register::RSP,
        Register::R8L | Register::R8W | Register::R8D => Register::R8,
        Register::R9L | Register::R9W | Register::R9D => Register::R9,
        Register::R10L | Register::R10W | Register::R10D => Register::R10,
        Register::R11L | Register::R11W | Register::R11D => Register::R11,
        Register::R12L | Register::R12W | Register::R12D => Register::R12,
        Register::R13L | Register::R13W | Register::R13D => Register::R13,
        Register::R14L | Register::R14W | Register::R14D => Register::R14,
        Register::R15L | Register::R15W | Register::R15D => Register::R15,
        _ => r,
    }
}

/// Return bit-width of a register
pub fn reg_size(r: Register) -> u8 {
    match r {
        Register::AL
        | Register::AH
        | Register::BL
        | Register::BH
        | Register::CL
        | Register::CH
        | Register::DL
        | Register::DH
        | Register::SIL
        | Register::DIL
        | Register::BPL
        | Register::SPL
        | Register::R8L
        | Register::R9L
        | Register::R10L
        | Register::R11L
        | Register::R12L
        | Register::R13L
        | Register::R14L
        | Register::R15L => 8,
        Register::AX
        | Register::BX
        | Register::CX
        | Register::DX
        | Register::SI
        | Register::DI
        | Register::BP
        | Register::SP
        | Register::R8W
        | Register::R9W
        | Register::R10W
        | Register::R11W
        | Register::R12W
        | Register::R13W
        | Register::R14W
        | Register::R15W => 16,
        Register::EAX
        | Register::EBX
        | Register::ECX
        | Register::EDX
        | Register::ESI
        | Register::EDI
        | Register::EBP
        | Register::ESP
        | Register::R8D
        | Register::R9D
        | Register::R10D
        | Register::R11D
        | Register::R12D
        | Register::R13D
        | Register::R14D
        | Register::R15D => 32,
        _ => 64,
    }
}
