//! The instruction set of the register-based MPC-VM.
use serde::{Deserialize, Serialize};
use std::fmt;

/// Index of a template in [`CompiledProgram::templates`](crate::program::CompiledProgram).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TemplId(pub u32);

/// Index of a function in [`CompiledProgram::functions`](crate::program::CompiledProgram).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FnId(pub u32);

/// A storage address, resolved at compile time where possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Addr {
    /// Absolute slot — the common case.
    Const(u32),
    /// `iregs[ireg] * stride + offset` — loop-variable dependent.
    Affine {
        /// Integer register index.
        ireg: u8,
        /// Stride multiplier.
        stride: u32,
        /// Base offset.
        offset: u32,
    },
    /// Fully dynamic: the value of integer register `.0`.
    Dynamic(u8),
}

/// A readable operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Src {
    /// Field register (expression temporary).
    Reg(u16),
    /// Constant-table entry.
    Const(u32),
    /// Var slot of the current template/function frame.
    Var(Addr),
    /// Signal RAM, relative to the current component offset.
    Signal(Addr),
}

/// A writable operand. Writes to `Var`/`Signal` are predicated under shared ifs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Dst {
    /// Field register (never predicated — temporaries are branch-local).
    Reg(u16),
    /// Var slot.
    Var(Addr),
    /// Signal RAM, relative to the current component offset.
    Signal(Addr),
}

/// A readable integer operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ISrc {
    /// Immediate.
    Const(u32),
    /// Integer register.
    Reg(u8),
}

/// Source of function return values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetSrc {
    /// Return `n` values from consecutive field registers starting here.
    Reg(u16),
    /// Return `n` values from consecutive var slots starting at this address.
    Var(Addr),
}

/// Binary field operations, mapping 1:1 to [`VmDriver`](crate::driver::VmDriver) methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Division.
    Div,
    /// Integer division.
    IntDiv,
    /// Exponentiation.
    Pow,
    /// Modulo.
    Mod,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Equality.
    Eq,
    /// Not equal.
    Neq,
    /// Logical OR.
    BoolOr,
    /// Logical AND.
    BoolAnd,
    /// Bitwise OR.
    BitOr,
    /// Bitwise AND.
    BitAnd,
    /// Bitwise XOR.
    BitXor,
    /// Right shift.
    ShiftR,
    /// Left shift.
    ShiftL,
}

/// One VM instruction. Three-address form: operands are addressing modes, not stack slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instr {
    /// `regs[dst] = op(a, b)`.
    Bin {
        /// The operation to perform.
        op: BinOp,
        /// Destination register.
        dst: u16,
        /// First operand.
        a: Src,
        /// Second operand.
        b: Src,
    },
    /// `regs[dst] = -a`.
    Neg {
        /// Destination register.
        dst: u16,
        /// Operand to negate.
        a: Src,
    },
    /// `regs[dst] = (a[0..n] == b[0..n])` — arrays at consecutive addresses.
    EqN {
        /// Destination register.
        dst: u16,
        /// First array.
        a: Src,
        /// Second array.
        b: Src,
        /// Number of elements to compare.
        n: u32,
    },
    /// `dst = src` (single value; predicated if dst is Var/Signal).
    Mov {
        /// Destination address.
        dst: Dst,
        /// Source operand.
        src: Src,
    },
    /// `regs[dst..dst+n] = src[0..n]` (consecutive source addresses).
    LoadN {
        /// Destination register.
        dst: u16,
        /// Source address.
        src: Src,
        /// Number of elements to load.
        n: u32,
    },
    /// `dst[0..n] = regs[src..src+n]` (predicated if dst is Var/Signal).
    StoreN {
        /// Destination address.
        dst: Dst,
        /// Source register.
        src: u16,
        /// Number of elements to store.
        n: u32,
    },
    /// Elementwise `regs[dst..dst+n] = op(a[0..n], b[0..n])` — one vectorized driver call.
    BinN {
        /// The operation to perform.
        op: BinOp,
        /// Destination register.
        dst: u16,
        /// First array.
        a: Src,
        /// Second array.
        b: Src,
        /// Number of elements.
        n: u32,
    },

    /// `iregs[dst] = val`.
    ISet {
        /// Destination integer register.
        dst: u8,
        /// Immediate value.
        val: u32,
    },
    /// `iregs[dst] = a + b`.
    IAdd {
        /// Destination integer register.
        dst: u8,
        /// First operand.
        a: ISrc,
        /// Second operand.
        b: ISrc,
    },
    /// `iregs[dst] = a * b`.
    IMul {
        /// Destination integer register.
        dst: u8,
        /// First operand.
        a: ISrc,
        /// Second operand.
        b: ISrc,
    },
    /// `iregs[dst] = to_index(src)`; errors if `src` is shared.
    ToIndex {
        /// Destination integer register.
        dst: u8,
        /// Source operand.
        src: Src,
    },

    /// Unconditional jump to absolute instruction index.
    Jmp {
        /// Target instruction index.
        target: u32,
    },
    /// Jump to `target` if `cond == 0`; errors if `cond` is shared (loop conditions must be public).
    JmpIfZero {
        /// Condition to test.
        cond: Src,
        /// Target instruction index.
        target: u32,
    },
    /// Branch entry. Public cond: jump to `else_target` when 0, else fall through.
    /// Shared cond: push predication level, execute both branches.
    SharedIf {
        /// Condition to test.
        cond: Src,
        /// Target of the else branch.
        else_target: u32,
    },
    /// End of truthy branch. Public level: jump to `end_target` (which holds `SharedEnd`).
    /// Shared level: toggle the condition, fall into the else branch.
    SharedElse {
        /// Target at the end of the if-else block.
        end_target: u32,
    },
    /// Pop the predication level.
    SharedEnd,

    /// Create `count` subcomponents of `templ` at signal offsets `base + i*jump`
    /// (relative to the current component). Zero-input components run immediately.
    CreateCmp {
        /// Template index.
        templ: TemplId,
        /// Number of subcomponents to create.
        count: u32,
        /// Base signal offset.
        base: u32,
        /// Jump offset between components.
        jump: u32,
    },
    /// Write `regs[src..src+n]` into subcomponent `cmp`'s signals at `addr`
    /// (+ `mappings[m]` if `mapped = Some(m)`). Runs the component when its last input arrives.
    InputSub {
        /// Subcomponent index.
        cmp: ISrc,
        /// Address in the subcomponent.
        addr: Addr,
        /// Optional mapping index.
        mapped: Option<u32>,
        /// Source register.
        src: u16,
        /// Number of values to write.
        n: u32,
    },
    /// Read `n` signals from subcomponent `cmp` at `addr` (+ mapping) into `regs[dst..]`.
    OutputSub {
        /// Subcomponent index.
        cmp: ISrc,
        /// Address in the subcomponent.
        addr: Addr,
        /// Optional mapping index.
        mapped: Option<u32>,
        /// Destination register.
        dst: u16,
        /// Number of values to read.
        n: u32,
    },
    /// Call function: callee `vars[0..args_n]` are initialized from `regs[args_start..]`;
    /// on return, `ret_n` values are written to `regs[ret..ret+ret_n]`.
    CallFn {
        /// Function index.
        fn_id: FnId,
        /// Starting register for arguments.
        args_start: u16,
        /// Number of arguments.
        args_n: u32,
        /// Destination register for return values.
        ret: u16,
        /// Number of return values.
        ret_n: u32,
    },
    /// Return `n` values from a function (see [`RetSrc`]). Under a shared predication
    /// level this accumulates instead of returning — see exec.rs.
    Ret {
        /// Source of return values.
        src: RetSrc,
        /// Number of values to return.
        n: u32,
    },
    /// End of a template body.
    Return,

    /// Runtime assertion (omitted when compiled with `debug = false`).
    Assert {
        /// Condition to assert.
        cond: Src,
        /// Source line number.
        line: u32,
    },
    /// Append the string form of `src` to the log buffer.
    Log {
        /// Value to log.
        src: Src,
    },
    /// Append string-table entry `id` to the log buffer.
    LogStr {
        /// String table index.
        id: u32,
    },
    /// Flush the log buffer via tracing, tagged with the source line.
    LogFlush {
        /// Source line number.
        line: u32,
    },
}

impl fmt::Display for Instr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instr::Bin { op, dst, a, b } => {
                write!(f, "{:?} r{}, {:?}, {:?}", op, dst, a, b)
            }
            Instr::Neg { dst, a } => {
                write!(f, "NEG r{}, {:?}", dst, a)
            }
            Instr::EqN { dst, a, b, n } => {
                write!(f, "EQN r{}, {:?}, {:?}, {}", dst, a, b, n)
            }
            Instr::Mov { dst, src } => {
                write!(f, "MOV {:?}, {:?}", dst, src)
            }
            Instr::LoadN { dst, src, n } => {
                write!(f, "LOADN r{}, {:?}, {}", dst, src, n)
            }
            Instr::StoreN { dst, src, n } => {
                write!(f, "STOREN {:?}, r{}, {}", dst, src, n)
            }
            Instr::BinN { op, dst, a, b, n } => {
                write!(f, "{:?}N r{}, {:?}, {:?}, {}", op, dst, a, b, n)
            }
            Instr::ISet { dst, val } => {
                write!(f, "ISET ir{}, {}", dst, val)
            }
            Instr::IAdd { dst, a, b } => {
                write!(f, "IADD ir{}, {:?}, {:?}", dst, a, b)
            }
            Instr::IMul { dst, a, b } => {
                write!(f, "IMUL ir{}, {:?}, {:?}", dst, a, b)
            }
            Instr::ToIndex { dst, src } => {
                write!(f, "TOINDEX ir{}, {:?}", dst, src)
            }
            Instr::Jmp { target } => {
                write!(f, "JMP {}", target)
            }
            Instr::JmpIfZero { cond, target } => {
                write!(f, "JMPZ {:?}, {}", cond, target)
            }
            Instr::SharedIf { cond, else_target } => {
                write!(f, "SHAREDIF {:?}, {}", cond, else_target)
            }
            Instr::SharedElse { end_target } => {
                write!(f, "SHAREDELSE {}", end_target)
            }
            Instr::SharedEnd => {
                write!(f, "SHAREDEND")
            }
            Instr::CreateCmp {
                templ,
                count,
                base,
                jump,
            } => {
                write!(f, "CREATECMP t{}, {}, {}, {}", templ.0, count, base, jump)
            }
            Instr::InputSub {
                cmp,
                addr,
                mapped,
                src,
                n,
            } => {
                if let Some(m) = mapped {
                    write!(f, "INPUTSUB {:?}, {:?}, m{}, r{}, {}", cmp, addr, m, src, n)
                } else {
                    write!(f, "INPUTSUB {:?}, {:?}, _, r{}, {}", cmp, addr, src, n)
                }
            }
            Instr::OutputSub {
                cmp,
                addr,
                mapped,
                dst,
                n,
            } => {
                if let Some(m) = mapped {
                    write!(
                        f,
                        "OUTPUTSUB {:?}, {:?}, m{}, r{}, {}",
                        cmp, addr, m, dst, n
                    )
                } else {
                    write!(f, "OUTPUTSUB {:?}, {:?}, _, r{}, {}", cmp, addr, dst, n)
                }
            }
            Instr::CallFn {
                fn_id,
                args_start,
                args_n,
                ret,
                ret_n,
            } => {
                write!(
                    f,
                    "CALLFN f{}, r{}, {}, r{}, {}",
                    fn_id.0, args_start, args_n, ret, ret_n
                )
            }
            Instr::Ret { src, n } => {
                write!(f, "RET {:?}, {}", src, n)
            }
            Instr::Return => {
                write!(f, "RETURN")
            }
            Instr::Assert { cond, line } => {
                write!(f, "ASSERT {:?}, {}", cond, line)
            }
            Instr::Log { src } => {
                write!(f, "LOG {:?}", src)
            }
            Instr::LogStr { id } => {
                write!(f, "LOGSTR {}", id)
            }
            Instr::LogFlush { line } => {
                write!(f, "LOGFLUSH {}", line)
            }
        }
    }
}
