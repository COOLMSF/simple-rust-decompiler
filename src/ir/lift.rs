use std::collections::HashMap;

use iced_x86::{Instruction, Mnemonic, MemorySize, OpKind, Register};

use crate::binary::Arch;
use crate::disasm::{canonical_reg, reg_size, DisasmFunction, is_conditional_branch, is_return, is_unconditional_branch};
use super::{BasicBlock, BinOp, Expr, IrFunction, Stmt, UnOp, VReg, Width};

const SYSV_ARGS: &[Register] = &[
    Register::RDI,
    Register::RSI,
    Register::RDX,
    Register::RCX,
    Register::R8,
    Register::R9,
];

pub struct Lifter {
    arch: Arch,
    vreg_ctr: u32,
    /// Map from x86 register → current VReg holding that reg's value
    reg_map: HashMap<Register, VReg>,
    /// Map from instruction address → basic block id
    addr_to_block: HashMap<u64, u32>,
    /// stack slots: frame_offset → vreg
    stack_slots: HashMap<i32, VReg>,
    /// current frame pointer offset for stack accesses
    frame_offset: i32,
    /// track set of parameters
    param_regs_used: Vec<Register>,
}

impl Lifter {
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            vreg_ctr: 0,
            reg_map: HashMap::new(),
            addr_to_block: HashMap::new(),
            stack_slots: HashMap::new(),
            frame_offset: 0,
            param_regs_used: Vec::new(),
        }
    }

    fn fresh_vreg(&mut self) -> VReg {
        let v = VReg(self.vreg_ctr);
        self.vreg_ctr += 1;
        v
    }

    fn width_for_arch(&self) -> Width {
        match self.arch {
            Arch::X86 => Width::W32,
            Arch::X86_64 => Width::W64,
        }
    }

    /// Return a VReg representing the current value of `reg` (canonical form).
    /// Creates a new param VReg if not seen yet.
    fn read_reg(&mut self, reg: Register, width: Width, stmts: &mut Vec<Stmt>) -> Expr {
        let canon = canonical_reg(reg);
        if let Some(&vr) = self.reg_map.get(&canon) {
            // narrow if needed
            let full_w = self.width_for_arch();
            if width == full_w || width == Width::W64 {
                return Expr::Reg(vr, width);
            }
            let trunc = self.fresh_vreg();
            stmts.push(Stmt::Assign(trunc, Expr::UnOp(UnOp::Trunc(width), Box::new(Expr::Reg(vr, full_w)))));
            return Expr::Reg(trunc, width);
        }
        // First read of this register → it's either a parameter or callee-saved
        let param_w = self.width_for_arch();
        let vr = self.fresh_vreg();
        self.reg_map.insert(canon, vr);
        if SYSV_ARGS.contains(&canon) && !self.param_regs_used.contains(&canon) {
            self.param_regs_used.push(canon);
        }
        if width == param_w || width == Width::W64 {
            Expr::Reg(vr, width)
        } else {
            let trunc = self.fresh_vreg();
            stmts.push(Stmt::Assign(trunc, Expr::UnOp(UnOp::Trunc(width), Box::new(Expr::Reg(vr, param_w)))));
            Expr::Reg(trunc, width)
        }
    }

    fn write_reg(&mut self, reg: Register, val: Expr, stmts: &mut Vec<Stmt>) {
        let canon = canonical_reg(reg);
        let w = self.width_for_arch();
        // For partial writes we zero-extend/sign-extend to full width
        let full_val = match val.width() {
            Width::W64 => val,
            Width::W32 => {
                // x86-64: writing 32-bit register zero-extends to 64-bit
                let zext_v = self.fresh_vreg();
                stmts.push(Stmt::Assign(zext_v, Expr::UnOp(UnOp::ZExt(Width::W64), Box::new(val))));
                Expr::Reg(zext_v, Width::W64)
            }
            other => {
                let zext_v = self.fresh_vreg();
                stmts.push(Stmt::Assign(zext_v, Expr::UnOp(UnOp::ZExt(w), Box::new(val))));
                let _ = other;
                Expr::Reg(zext_v, w)
            }
        };
        let vr = self.fresh_vreg();
        stmts.push(Stmt::Assign(vr, full_val));
        self.reg_map.insert(canon, vr);
    }

    fn mem_size_to_width(ms: MemorySize) -> Width {
        match ms {
            MemorySize::UInt8 | MemorySize::Int8 => Width::W8,
            MemorySize::UInt16 | MemorySize::Int16 | MemorySize::WordOffset => Width::W16,
            MemorySize::UInt32 | MemorySize::Int32 | MemorySize::DwordOffset => Width::W32,
            _ => Width::W64,
        }
    }

    fn mem_addr(&mut self, instr: &Instruction, stmts: &mut Vec<Stmt>) -> Expr {
        let base = instr.memory_base();
        let index = instr.memory_index();
        let scale = instr.memory_index_scale();
        let disp = instr.memory_displacement64() as i64;
        let w = self.width_for_arch();

        let mut addr: Option<Expr> = None;

        if base != Register::None && base != Register::RIP && base != Register::EIP {
            let bv = self.read_reg(base, w, stmts);
            addr = Some(bv);
        } else if base == Register::RIP || base == Register::EIP {
            let rip = instr.next_ip();
            addr = Some(Expr::Const(rip as i64, w));
        }

        if index != Register::None {
            let iv = self.read_reg(index, w, stmts);
            let scaled = if scale > 1 {
                let sv = self.fresh_vreg();
                stmts.push(Stmt::Assign(
                    sv,
                    Expr::BinOp(BinOp::Mul, Box::new(iv), Box::new(Expr::Const(scale as i64, w))),
                ));
                Expr::Reg(sv, w)
            } else {
                iv
            };
            addr = Some(match addr {
                Some(a) => {
                    let av = self.fresh_vreg();
                    stmts.push(Stmt::Assign(av, Expr::BinOp(BinOp::Add, Box::new(a), Box::new(scaled))));
                    Expr::Reg(av, w)
                }
                None => scaled,
            });
        }

        if disp != 0 || addr.is_none() {
            let disp_expr = Expr::Const(disp, w);
            addr = Some(match addr {
                Some(a) => {
                    let av = self.fresh_vreg();
                    stmts.push(Stmt::Assign(av, Expr::BinOp(BinOp::Add, Box::new(a), Box::new(disp_expr))));
                    Expr::Reg(av, w)
                }
                None => disp_expr,
            });
        }

        addr.unwrap_or(Expr::Const(0, w))
    }

    fn get_operand(&mut self, instr: &Instruction, op: u32, stmts: &mut Vec<Stmt>) -> Expr {
        match instr.op_kind(op) {
            OpKind::Register => {
                let r = instr.op_register(op);
                let w = Width::from_bits(reg_size(r));
                self.read_reg(r, w, stmts)
            }
            OpKind::Immediate8 => Expr::Const(instr.immediate8() as i8 as i64, Width::W8),
            OpKind::Immediate8_2nd => Expr::Const(instr.immediate8_2nd() as i8 as i64, Width::W8),
            OpKind::Immediate16 => Expr::Const(instr.immediate16() as i64, Width::W16),
            OpKind::Immediate32 => Expr::Const(instr.immediate32() as i64, Width::W32),
            OpKind::Immediate64 => Expr::Const(instr.immediate64() as i64, Width::W64),
            OpKind::Immediate8to16 => Expr::Const(instr.immediate8to16() as i64, Width::W16),
            OpKind::Immediate8to32 => Expr::Const(instr.immediate8to32() as i64, Width::W32),
            OpKind::Immediate8to64 => Expr::Const(instr.immediate8to64(), Width::W64),
            OpKind::Immediate32to64 => Expr::Const(instr.immediate32to64(), Width::W64),
            OpKind::Memory => {
                let width = Self::mem_size_to_width(instr.memory_size());
                let addr = self.mem_addr(instr, stmts);
                Expr::Load(Box::new(addr), width)
            }
            OpKind::NearBranch32 | OpKind::NearBranch64 => {
                Expr::Addr(instr.near_branch_target())
            }
            _ => {
                let w = self.width_for_arch();
                Expr::Const(0, w)
            }
        }
    }

    fn set_operand(&mut self, instr: &Instruction, op: u32, val: Expr, stmts: &mut Vec<Stmt>) {
        match instr.op_kind(op) {
            OpKind::Register => {
                let r = instr.op_register(op);
                self.write_reg(r, val, stmts);
            }
            OpKind::Memory => {
                let width = Self::mem_size_to_width(instr.memory_size());
                let addr = self.mem_addr(instr, stmts);
                stmts.push(Stmt::Store { addr, val, width });
            }
            _ => {
                stmts.push(Stmt::Unhandled(format!("cannot write to op kind {:?}", instr.op_kind(op))));
            }
        }
    }

    fn lift_instr(&mut self, instr: &Instruction, stmts: &mut Vec<Stmt>, block_id: u32, _blocks: &[u32]) {
        let w = self.width_for_arch();
        let mnem = instr.mnemonic();

        match mnem {
            Mnemonic::Nop => stmts.push(Stmt::Nop),

            // ── Data movement ────────────────────────────────────────────────
            Mnemonic::Mov => {
                let src = self.get_operand(instr, 1, stmts);
                self.set_operand(instr, 0, src, stmts);
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let src = self.get_operand(instr, 1, stmts);
                let dst_w = match instr.op_kind(0) {
                    OpKind::Register => Width::from_bits(reg_size(instr.op0_register())),
                    _ => w,
                };
                let v = self.fresh_vreg();
                stmts.push(Stmt::Assign(v, Expr::UnOp(UnOp::SExt(dst_w), Box::new(src))));
                self.set_operand(instr, 0, Expr::Reg(v, dst_w), stmts);
            }
            Mnemonic::Movzx => {
                let src = self.get_operand(instr, 1, stmts);
                let dst_w = match instr.op_kind(0) {
                    OpKind::Register => Width::from_bits(reg_size(instr.op0_register())),
                    _ => w,
                };
                let v = self.fresh_vreg();
                stmts.push(Stmt::Assign(v, Expr::UnOp(UnOp::ZExt(dst_w), Box::new(src))));
                self.set_operand(instr, 0, Expr::Reg(v, dst_w), stmts);
            }
            Mnemonic::Cmove | Mnemonic::Cmovne | Mnemonic::Cmovl | Mnemonic::Cmovle
            | Mnemonic::Cmovg | Mnemonic::Cmovge | Mnemonic::Cmovb | Mnemonic::Cmovbe
            | Mnemonic::Cmova | Mnemonic::Cmovae | Mnemonic::Cmovs | Mnemonic::Cmovns => {
                // Treat CMOVcc as: dst = (cond ? src : dst)
                // We simplify by just doing the move (conservative)
                let src = self.get_operand(instr, 1, stmts);
                self.set_operand(instr, 0, src, stmts);
            }
            Mnemonic::Xchg => {
                let a = self.get_operand(instr, 0, stmts);
                let b = self.get_operand(instr, 1, stmts);
                self.set_operand(instr, 0, b.clone(), stmts);
                self.set_operand(instr, 1, a, stmts);
            }
            Mnemonic::Lea => {
                let addr = self.mem_addr(instr, stmts);
                self.set_operand(instr, 0, addr, stmts);
            }

            // ── Stack operations ─────────────────────────────────────────────
            Mnemonic::Push => {
                let val = self.get_operand(instr, 0, stmts);
                // RSP -= size
                let rsp = self.read_reg(Register::RSP, w, stmts);
                let sz = w.bytes() as i64;
                let new_rsp = self.fresh_vreg();
                stmts.push(Stmt::Assign(
                    new_rsp,
                    Expr::BinOp(BinOp::Sub, Box::new(rsp), Box::new(Expr::Const(sz, w))),
                ));
                self.reg_map.insert(Register::RSP, new_rsp);
                stmts.push(Stmt::Store {
                    addr: Expr::Reg(new_rsp, w),
                    val,
                    width: w,
                });
            }
            Mnemonic::Pop => {
                let rsp = self.read_reg(Register::RSP, w, stmts);
                let loaded = self.fresh_vreg();
                stmts.push(Stmt::Assign(loaded, Expr::Load(Box::new(rsp.clone()), w)));
                self.set_operand(instr, 0, Expr::Reg(loaded, w), stmts);
                // RSP += size
                let sz = w.bytes() as i64;
                let rsp2 = self.read_reg(Register::RSP, w, stmts);
                let new_rsp = self.fresh_vreg();
                stmts.push(Stmt::Assign(
                    new_rsp,
                    Expr::BinOp(BinOp::Add, Box::new(rsp2), Box::new(Expr::Const(sz, w))),
                ));
                self.reg_map.insert(Register::RSP, new_rsp);
            }

            // ── Arithmetic ───────────────────────────────────────────────────
            Mnemonic::Add => self.lift_binop(instr, BinOp::Add, stmts),
            Mnemonic::Sub => self.lift_binop(instr, BinOp::Sub, stmts),
            Mnemonic::Imul => {
                if instr.op_count() == 2 {
                    self.lift_binop(instr, BinOp::Mul, stmts);
                } else if instr.op_count() == 3 {
                    let a = self.get_operand(instr, 1, stmts);
                    let b = self.get_operand(instr, 2, stmts);
                    let r = self.fresh_vreg();
                    stmts.push(Stmt::Assign(r, Expr::BinOp(BinOp::Mul, Box::new(a), Box::new(b))));
                    self.set_operand(instr, 0, Expr::Reg(r, w), stmts);
                } else {
                    // 1-operand form: rdx:rax = rax * src
                    let src = self.get_operand(instr, 0, stmts);
                    let rax = self.read_reg(Register::RAX, w, stmts);
                    let r = self.fresh_vreg();
                    stmts.push(Stmt::Assign(r, Expr::BinOp(BinOp::Mul, Box::new(rax), Box::new(src))));
                    self.write_reg(Register::RAX, Expr::Reg(r, w), stmts);
                }
            }
            Mnemonic::Mul => {
                let src = self.get_operand(instr, 0, stmts);
                let rax = self.read_reg(Register::RAX, w, stmts);
                let r = self.fresh_vreg();
                stmts.push(Stmt::Assign(r, Expr::BinOp(BinOp::Mul, Box::new(rax), Box::new(src))));
                self.write_reg(Register::RAX, Expr::Reg(r, w), stmts);
            }
            Mnemonic::Idiv => {
                let src = self.get_operand(instr, 0, stmts);
                let rax = self.read_reg(Register::RAX, w, stmts);
                let q = self.fresh_vreg();
                let rem = self.fresh_vreg();
                stmts.push(Stmt::Assign(q, Expr::BinOp(BinOp::SDiv, Box::new(rax.clone()), Box::new(src.clone()))));
                stmts.push(Stmt::Assign(rem, Expr::BinOp(BinOp::SMod, Box::new(rax), Box::new(src))));
                self.write_reg(Register::RAX, Expr::Reg(q, w), stmts);
                self.write_reg(Register::RDX, Expr::Reg(rem, w), stmts);
            }
            Mnemonic::Div => {
                let src = self.get_operand(instr, 0, stmts);
                let rax = self.read_reg(Register::RAX, w, stmts);
                let q = self.fresh_vreg();
                let rem = self.fresh_vreg();
                stmts.push(Stmt::Assign(q, Expr::BinOp(BinOp::UDiv, Box::new(rax.clone()), Box::new(src.clone()))));
                stmts.push(Stmt::Assign(rem, Expr::BinOp(BinOp::UMod, Box::new(rax), Box::new(src))));
                self.write_reg(Register::RAX, Expr::Reg(q, w), stmts);
                self.write_reg(Register::RDX, Expr::Reg(rem, w), stmts);
            }
            Mnemonic::Inc => {
                let dst = self.get_operand(instr, 0, stmts);
                let r = self.fresh_vreg();
                stmts.push(Stmt::Assign(r, Expr::BinOp(BinOp::Add, Box::new(dst), Box::new(Expr::Const(1, w)))));
                self.set_operand(instr, 0, Expr::Reg(r, w), stmts);
            }
            Mnemonic::Dec => {
                let dst = self.get_operand(instr, 0, stmts);
                let r = self.fresh_vreg();
                stmts.push(Stmt::Assign(r, Expr::BinOp(BinOp::Sub, Box::new(dst), Box::new(Expr::Const(1, w)))));
                self.set_operand(instr, 0, Expr::Reg(r, w), stmts);
            }
            Mnemonic::Neg => {
                let src = self.get_operand(instr, 0, stmts);
                let r = self.fresh_vreg();
                stmts.push(Stmt::Assign(r, Expr::UnOp(UnOp::Neg, Box::new(src))));
                self.set_operand(instr, 0, Expr::Reg(r, w), stmts);
            }

            // ── Bitwise ──────────────────────────────────────────────────────
            Mnemonic::And => self.lift_binop(instr, BinOp::And, stmts),
            Mnemonic::Or => self.lift_binop(instr, BinOp::Or, stmts),
            Mnemonic::Xor => {
                // xor reg, reg => reg = 0 (common idiom)
                if instr.op0_register() == instr.op1_register()
                    && instr.op_kind(0) == OpKind::Register
                    && instr.op_kind(1) == OpKind::Register
                {
                    self.set_operand(instr, 0, Expr::Const(0, w), stmts);
                } else {
                    self.lift_binop(instr, BinOp::Xor, stmts);
                }
            }
            Mnemonic::Not => {
                let src = self.get_operand(instr, 0, stmts);
                let r = self.fresh_vreg();
                stmts.push(Stmt::Assign(r, Expr::UnOp(UnOp::Not, Box::new(src))));
                self.set_operand(instr, 0, Expr::Reg(r, w), stmts);
            }
            Mnemonic::Shl | Mnemonic::Sal => self.lift_binop(instr, BinOp::Shl, stmts),
            Mnemonic::Shr => self.lift_binop(instr, BinOp::LShr, stmts),
            Mnemonic::Sar => self.lift_binop(instr, BinOp::AShr, stmts),

            // ── Comparison (set flags VRegs) ──────────────────────────────────
            Mnemonic::Cmp => {
                let a = self.get_operand(instr, 0, stmts);
                let b = self.get_operand(instr, 1, stmts);
                // Store comparison result in virtual ZF/SF/CF flags
                let sub = self.fresh_vreg();
                stmts.push(Stmt::Assign(sub, Expr::BinOp(BinOp::Sub, Box::new(a), Box::new(b))));
                self.reg_map.insert(Register::None, sub); // repurpose None as "last cmp result"
            }
            Mnemonic::Test => {
                let a = self.get_operand(instr, 0, stmts);
                let b = self.get_operand(instr, 1, stmts);
                let and = self.fresh_vreg();
                stmts.push(Stmt::Assign(and, Expr::BinOp(BinOp::And, Box::new(a), Box::new(b))));
                self.reg_map.insert(Register::None, and);
            }

            // ── Setcc instructions ────────────────────────────────────────────
            Mnemonic::Sete => {
                self.lift_setcc(instr, BinOp::Eq, false, stmts);
            }
            Mnemonic::Setne => {
                self.lift_setcc(instr, BinOp::Ne, false, stmts);
            }
            Mnemonic::Setl => {
                self.lift_setcc(instr, BinOp::Slt, false, stmts);
            }
            Mnemonic::Setle => {
                self.lift_setcc(instr, BinOp::Sle, false, stmts);
            }
            Mnemonic::Setg => {
                self.lift_setcc(instr, BinOp::Slt, true, stmts);
            }
            Mnemonic::Setge => {
                self.lift_setcc(instr, BinOp::Sle, true, stmts);
            }
            Mnemonic::Setb => {
                self.lift_setcc(instr, BinOp::Ult, false, stmts);
            }
            Mnemonic::Setbe => {
                self.lift_setcc(instr, BinOp::Ule, false, stmts);
            }
            Mnemonic::Seta => {
                self.lift_setcc(instr, BinOp::Ult, true, stmts);
            }
            Mnemonic::Setae => {
                self.lift_setcc(instr, BinOp::Ule, true, stmts);
            }

            // ── Control flow ──────────────────────────────────────────────────
            Mnemonic::Call => {
                let target = self.get_operand(instr, 0, stmts);
                // Build argument list from SysV ABI
                let mut args = Vec::new();
                for &areg in SYSV_ARGS {
                    if let Some(&vr) = self.reg_map.get(&areg) {
                        args.push(Expr::Reg(vr, w));
                    }
                }
                let dst = self.fresh_vreg();
                stmts.push(Stmt::Call {
                    dst: Some(dst),
                    func: target,
                    args,
                });
                self.write_reg(Register::RAX, Expr::Reg(dst, w), stmts);
            }
            Mnemonic::Ret | Mnemonic::Retf => {
                // Return rax if set
                let ret_val = self.reg_map.get(&Register::RAX).copied().map(|v| Expr::Reg(v, w));
                stmts.push(Stmt::Return(ret_val));
            }
            Mnemonic::Jmp => {
                if instr.op0_kind() == OpKind::NearBranch64 || instr.op0_kind() == OpKind::NearBranch32 {
                    let target_addr = instr.near_branch_target();
                    if let Some(&bid) = self.addr_to_block.get(&target_addr) {
                        stmts.push(Stmt::Jump(bid));
                    } else {
                        stmts.push(Stmt::IndirectJump(Expr::Addr(target_addr)));
                    }
                } else {
                    let expr = self.get_operand(instr, 0, stmts);
                    stmts.push(Stmt::IndirectJump(expr));
                }
            }

            m if is_conditional_branch(m) => {
                let cond = self.build_branch_cond(m, stmts);
                let true_addr = instr.near_branch_target();
                let false_addr = instr.next_ip();
                let true_id = self.addr_to_block.get(&true_addr).copied().unwrap_or(0);
                let false_id = self.addr_to_block.get(&false_addr).copied().unwrap_or(block_id + 1);
                stmts.push(Stmt::Branch { cond, true_id, false_id });
            }

            // ── Other ─────────────────────────────────────────────────────────
            Mnemonic::Cdq | Mnemonic::Cqo => {
                // sign extend rax into rdx:rax
                let rax = self.read_reg(Register::RAX, w, stmts);
                let r = self.fresh_vreg();
                stmts.push(Stmt::Assign(r, Expr::BinOp(BinOp::AShr, Box::new(rax), Box::new(Expr::Const(63, w)))));
                self.write_reg(Register::RDX, Expr::Reg(r, w), stmts);
            }
            Mnemonic::Leave => {
                // mov rsp, rbp; pop rbp
                let rbp = self.read_reg(Register::RBP, w, stmts);
                self.write_reg(Register::RSP, rbp, stmts);
                let rsp = self.read_reg(Register::RSP, w, stmts);
                let old_rbp = self.fresh_vreg();
                stmts.push(Stmt::Assign(old_rbp, Expr::Load(Box::new(rsp.clone()), w)));
                self.write_reg(Register::RBP, Expr::Reg(old_rbp, w), stmts);
                let new_rsp = self.fresh_vreg();
                stmts.push(Stmt::Assign(
                    new_rsp,
                    Expr::BinOp(BinOp::Add, Box::new(rsp), Box::new(Expr::Const(w.bytes() as i64, w))),
                ));
                self.reg_map.insert(Register::RSP, new_rsp);
            }
            Mnemonic::Endbr32 | Mnemonic::Endbr64 => stmts.push(Stmt::Nop),

            _ => {
                stmts.push(Stmt::Unhandled(format!("{:?}", mnem)));
            }
        }
    }

    fn lift_binop(&mut self, instr: &Instruction, op: BinOp, stmts: &mut Vec<Stmt>) {
        let w = self.width_for_arch();
        let a = self.get_operand(instr, 0, stmts);
        let b = self.get_operand(instr, 1, stmts);
        let r = self.fresh_vreg();
        stmts.push(Stmt::Assign(r, Expr::BinOp(op, Box::new(a), Box::new(b))));
        self.set_operand(instr, 0, Expr::Reg(r, w), stmts);
    }

    fn lift_setcc(&mut self, instr: &Instruction, op: BinOp, swap: bool, stmts: &mut Vec<Stmt>) {
        let (lhs, rhs) = self.get_cmp_operands(stmts);
        let (l, r) = if swap { (rhs, lhs) } else { (lhs, rhs) };
        let cmp = self.fresh_vreg();
        stmts.push(Stmt::Assign(cmp, Expr::BinOp(op, Box::new(l), Box::new(r))));
        let zext = self.fresh_vreg();
        stmts.push(Stmt::Assign(zext, Expr::UnOp(UnOp::ZExt(Width::W8), Box::new(Expr::Reg(cmp, Width::W8)))));
        self.set_operand(instr, 0, Expr::Reg(zext, Width::W8), stmts);
    }

    /// Get the two operands from the last CMP/TEST
    fn get_cmp_operands(&mut self, _stmts: &mut Vec<Stmt>) -> (Expr, Expr) {
        let w = self.width_for_arch();
        if let Some(&v) = self.reg_map.get(&Register::None) {
            (Expr::Reg(v, w), Expr::Const(0, w))
        } else {
            (Expr::Const(0, w), Expr::Const(0, w))
        }
    }

    fn build_branch_cond(&mut self, mnem: Mnemonic, stmts: &mut Vec<Stmt>) -> Expr {
        let w = self.width_for_arch();
        let (lhs, rhs) = self.get_cmp_operands(stmts);

        let (op, swap) = match mnem {
            Mnemonic::Je | Mnemonic::Loope => (BinOp::Eq, false),
            Mnemonic::Jne | Mnemonic::Loopne => (BinOp::Ne, false),
            Mnemonic::Jl => (BinOp::Slt, false),
            Mnemonic::Jle => (BinOp::Sle, false),
            Mnemonic::Jg => (BinOp::Slt, true),
            Mnemonic::Jge => (BinOp::Sle, true),
            Mnemonic::Jb => (BinOp::Ult, false),
            Mnemonic::Jbe => (BinOp::Ule, false),
            Mnemonic::Ja => (BinOp::Ult, true),
            Mnemonic::Jae => (BinOp::Ule, true),
            Mnemonic::Js => {
                let v = self.fresh_vreg();
                stmts.push(Stmt::Assign(v, Expr::BinOp(BinOp::Slt, Box::new(lhs), Box::new(Expr::Const(0, w)))));
                return Expr::Reg(v, Width::W8);
            }
            Mnemonic::Jns => {
                let v = self.fresh_vreg();
                stmts.push(Stmt::Assign(v, Expr::BinOp(BinOp::Sle, Box::new(Expr::Const(0, w)), Box::new(lhs))));
                return Expr::Reg(v, Width::W8);
            }
            _ => (BinOp::Ne, false),
        };

        let (l, r) = if swap { (rhs, lhs) } else { (lhs, rhs) };
        let v = self.fresh_vreg();
        stmts.push(Stmt::Assign(v, Expr::BinOp(op, Box::new(l), Box::new(r))));
        Expr::Reg(v, Width::W8)
    }

    pub fn lift_function(&mut self, func: &DisasmFunction) -> IrFunction {
        // ── Pass 1: assign a block id to each unique address where a new block starts ──
        // Block starts: first instruction, branch targets, fall-throughs after branches
        let mut block_starts: Vec<u64> = vec![func.address];

        for di in &func.instrs {
            let mnem = di.instr.mnemonic();
            if is_conditional_branch(mnem) {
                block_starts.push(di.instr.near_branch_target());
                block_starts.push(di.instr.next_ip());
            } else if is_unconditional_branch(mnem) {
                if di.instr.op0_kind() == OpKind::NearBranch64
                    || di.instr.op0_kind() == OpKind::NearBranch32
                {
                    block_starts.push(di.instr.near_branch_target());
                }
                block_starts.push(di.instr.next_ip());
            } else if is_return(mnem) {
                block_starts.push(di.instr.next_ip());
            }
        }
        block_starts.sort();
        block_starts.dedup();

        // Map address → block id
        let mut addr_to_id: HashMap<u64, u32> = HashMap::new();
        for (idx, &addr) in block_starts.iter().enumerate() {
            addr_to_id.insert(addr, idx as u32);
        }
        self.addr_to_block = addr_to_id.clone();

        // ── Pass 2: group instructions into blocks ──────────────────────────
        let mut blocks: Vec<BasicBlock> = Vec::new();
        let mut current_id = 0u32;
        let mut current_addr = func.address;

        if let Some(&bid) = addr_to_id.get(&func.address) {
            current_id = bid;
        }
        let mut block = BasicBlock::new(current_id, current_addr);

        for di in &func.instrs {
            // Check if we're starting a new block
            if let Some(&bid) = addr_to_id.get(&di.address) {
                if bid != current_id {
                    // Close previous block (add fall-through jump if needed)
                    if block.terminator().is_none() {
                        block.stmts.push(Stmt::Jump(bid));
                    }
                    blocks.push(block);
                    current_id = bid;
                    current_addr = di.address;
                    block = BasicBlock::new(current_id, current_addr);
                }
            }

            let mnem = di.instr.mnemonic();
            let block_ids: Vec<u32> = blocks.iter().map(|b| b.id).collect();
            self.lift_instr(&di.instr, &mut block.stmts, current_id, &block_ids);

            // After a terminator, mark block done (next iteration handles new block)
            if is_return(mnem) {
                // already pushed Return stmt
            }
        }
        // Push last block
        if !block.stmts.is_empty() || blocks.is_empty() {
            blocks.push(block);
        }

        // ── Pass 3: ensure all blocks have exactly one terminator ───────────
        for b in &mut blocks {
            if b.terminator().is_none() {
                b.stmts.push(Stmt::Return(None));
            }
        }

        let param_count = self.param_regs_used.len();
        let mut ir_func = IrFunction::new(func.address, func.name.clone());
        ir_func.blocks = blocks;
        ir_func.param_count = param_count;
        ir_func.vreg_counter = self.vreg_ctr;
        ir_func
    }
}

pub fn lift(func: &DisasmFunction, arch: Arch) -> IrFunction {
    let mut lifter = Lifter::new(arch);
    lifter.lift_function(func)
}
