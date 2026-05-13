pub mod lift;

use std::fmt;

/// Virtual register ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VReg(pub u32);

impl fmt::Display for VReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Width in bits of an IR value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Width {
    W8,
    W16,
    W32,
    W64,
}

impl Width {
    pub fn bytes(self) -> u64 {
        match self {
            Width::W8 => 1,
            Width::W16 => 2,
            Width::W32 => 4,
            Width::W64 => 8,
        }
    }
    pub fn c_type(self) -> &'static str {
        match self {
            Width::W8 => "uint8_t",
            Width::W16 => "uint16_t",
            Width::W32 => "uint32_t",
            Width::W64 => "uint64_t",
        }
    }
    pub fn c_type_signed(self) -> &'static str {
        match self {
            Width::W8 => "int8_t",
            Width::W16 => "int16_t",
            Width::W32 => "int32_t",
            Width::W64 => "int64_t",
        }
    }
    pub fn from_bits(b: u8) -> Self {
        match b {
            8 => Width::W8,
            16 => Width::W16,
            32 => Width::W32,
            _ => Width::W64,
        }
    }
}

impl fmt::Display for Width {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.c_type())
    }
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    UMod,
    SMod,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    // Comparisons (result is 1-bit boolean)
    Eq,
    Ne,
    Ult,  // unsigned less than
    Ule,  // unsigned less-or-equal
    Slt,  // signed less than
    Sle,  // signed less-or-equal
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::UDiv | BinOp::SDiv => "/",
            BinOp::UMod | BinOp::SMod => "%",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::Shl => "<<",
            BinOp::LShr | BinOp::AShr => ">>",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Ult | BinOp::Slt => "<",
            BinOp::Ule | BinOp::Sle => "<=",
        };
        write!(f, "{}", s)
    }
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    ZExt(Width), // zero-extend to target width
    SExt(Width), // sign-extend to target width
    Trunc(Width),
}

/// An IR expression (pure, no side effects)
#[derive(Debug, Clone)]
pub enum Expr {
    /// Virtual register
    Reg(VReg, Width),
    /// Immediate constant
    Const(i64, Width),
    /// Binary operation
    BinOp(BinOp, Box<Expr>, Box<Expr>),
    /// Unary operation
    UnOp(UnOp, Box<Expr>),
    /// Load from memory: *addr
    Load(Box<Expr>, Width),
    /// Stack slot (offset from function frame base, positive = local)
    StackSlot(i32, Width),
    /// Global / absolute address used as a value
    Addr(u64),
}

impl Expr {
    pub fn width(&self) -> Width {
        match self {
            Expr::Reg(_, w) => *w,
            Expr::Const(_, w) => *w,
            Expr::BinOp(_, l, _) => l.width(),
            Expr::UnOp(op, _) => match op {
                UnOp::ZExt(w) | UnOp::SExt(w) | UnOp::Trunc(w) => *w,
                _ => Width::W64,
            },
            Expr::Load(_, w) => *w,
            Expr::StackSlot(_, w) => *w,
            Expr::Addr(_) => Width::W64,
        }
    }
}

/// An IR statement (has side effects / defines values)
#[derive(Debug, Clone)]
pub enum Stmt {
    /// dst = expr
    Assign(VReg, Expr),
    /// *(addr)[width] = val
    Store { addr: Expr, val: Expr, width: Width },
    /// Call: dst (optional) = func(args)
    Call { dst: Option<VReg>, func: Expr, args: Vec<Expr> },
    /// Return optional value
    Return(Option<Expr>),
    /// Unconditional jump to block id
    Jump(u32),
    /// Conditional branch: if cond jump true_id else false_id
    Branch { cond: Expr, true_id: u32, false_id: u32 },
    /// Indirect jump (switch / computed goto)
    IndirectJump(Expr),
    /// No-op
    Nop,
    /// Unhandled instruction (raw comment)
    Unhandled(String),
}

/// A basic block in the IR
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: u32,
    /// Start address (first instruction)
    pub address: u64,
    pub stmts: Vec<Stmt>,
}

impl BasicBlock {
    pub fn new(id: u32, address: u64) -> Self {
        Self {
            id,
            address,
            stmts: Vec::new(),
        }
    }

    pub fn terminator(&self) -> Option<&Stmt> {
        self.stmts.last().and_then(|s| match s {
            Stmt::Jump(_)
            | Stmt::Branch { .. }
            | Stmt::Return(_)
            | Stmt::IndirectJump(_) => Some(s),
            _ => None,
        })
    }

    pub fn successors(&self) -> Vec<u32> {
        match self.terminator() {
            Some(Stmt::Jump(id)) => vec![*id],
            Some(Stmt::Branch { true_id, false_id, .. }) => vec![*true_id, *false_id],
            _ => vec![],
        }
    }
}

/// A lifted IR function
#[derive(Debug, Clone)]
pub struct IrFunction {
    pub address: u64,
    pub name: String,
    pub blocks: Vec<BasicBlock>,
    /// Number of parameters inferred (SysV AMD64: rdi, rsi, rdx, rcx, r8, r9)
    pub param_count: usize,
    /// Local variable size (stack frame size)
    pub frame_size: u32,
    /// Next VReg counter
    pub vreg_counter: u32,
}

impl IrFunction {
    pub fn new(address: u64, name: String) -> Self {
        Self {
            address,
            name,
            blocks: Vec::new(),
            param_count: 0,
            frame_size: 0,
            vreg_counter: 0,
        }
    }

    pub fn entry_block(&self) -> Option<&BasicBlock> {
        self.blocks.first()
    }
}
