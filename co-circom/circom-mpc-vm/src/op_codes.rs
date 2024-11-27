/// A code block of a circom function or template.
pub type CodeBlock = Vec<MpcOpCode>;

/// All bytecode operations for the MPC-VM.
///
/// Most of the opcodes interact with the stack, while some additionally need information stored in the variant.
/// The MPC-VM iterates over [`CodeBlocks`](CodeBlock) and executes one opcode at a time.
#[derive(Clone)]
pub enum MpcOpCode {
    /// Pushes the constant from the constant table with the provided index onto the field stack.
    PushConstant(usize),
    /// Pushes the provided index on the index stack.
    PushIndex(usize),
    /// Loads the specified amount of signals and pushes them onto the field stack.
    ///
    /// Pops the address of the signals from the index stack.
    LoadSignals(usize),
    /// Pops the specified amount of signals from field stack and stores them at the target address.
    ///
    /// Pops the target address from the index stack.
    StoreSignals(usize),
    /// Loads the specified amount of vars and pushes them onto the field stack.
    ///
    /// Pops the address of the vars from the index stack.
    LoadVars(usize),
    /// Pops the specified amount of vars from field stack and stores them at the target address.
    ///
    /// Pops the target address from the index stack.
    StoreVars(usize),
    /// Fetches the output from a component and pushes the output onto the field stack.
    ///
    /// The first two elements of the variant identify the offset of the component
    /// in the signal RAM. The third element specifies the number of signals that should be loaded.
    OutputSubComp(bool, usize, usize),

    /// Provides input for a component.
    ///
    /// The first two elements of the variant identify the offset of the component
    /// in the signal RAM. The third element specifies the number of signals that should be popped
    /// from the field stack to provide as input.
    ///
    /// If all inputs are provided, the component will run, resulting in a context switch of the VM.
    InputSubComp(bool, usize, usize),
    /// Creates a component identified by its name (`String`).
    ///
    /// The second element specifies the amount of components to create.
    CreateCmp(String, usize),
    /// Call to an unconstrained function identified by its name (`String`).
    ///
    /// The second element specifies the amount of return values of the function.
    Call(String, usize),
    /// Returns from a component (template).
    Return,
    /// Returns from an unconstrained function.
    ReturnFun,
    /// Appended at every unconstrained function's code block.
    ///
    /// This variant is necessary for handling if-statements on shared values, as ReturnFun may not return.
    ReturnSharedIfFun,
    /// Runtime assertion for witness extension.
    ///
    /// Pops the result of a predicate from the field stack and returns an error if the
    /// predicate is false. Stores the line number of the assertion in the circom file.
    Assert(usize),
    /// Branching operation. Pops the result of a predicate from the field stack. If the predicate
    /// is false, jumps the specified amount within the [CodeBlock].
    If(usize),
    /// Signals the end of the truthy branch. Jumps the specified amount within the [CodeBlock] to skip the
    /// falsy branch.
    EndTruthyBranch(usize),
    /// Signals the end of the falsy branch in how we handle if-statements on shared values.
    /// Always placed at the end of the falsy branch to indicate we may leave the shared if context.
    EndFalsyBranch,
    /// Pops two element from the field stack, adds them and pushes them on the stack.
    Add,
    /// Pops two elements from the field stack, subtracts the second popped value from the first, and pushes the result onto the stack.
    Sub,
    /// Pops two elements from the field stack, multiplies them, and pushes the result onto the stack.
    Mul,
    /// Pops two elements from the field stack, divides the first popped value by the second, and pushes the result onto the stack.
    Div,
    /// Pops two elements from the field stack, performs integer division of the first popped value by the second, and pushes the result onto the stack.
    IntDiv,
    /// Pops two elements from the field stack, raises the first popped value to the power of the second, and pushes the result onto the stack.
    Pow,
    /// Pops two elements from the field stack, computes the modulus of the first popped value with the second, and pushes the result onto the stack.
    Mod,
    /// Pops one element from the field stack, negates it, and pushes the result onto the stack.
    Neg,
    /// Pops two elements from the field stack, compares if the first popped value is less than the second, and pushes a boolean result onto the stack.
    Lt,
    /// Pops two elements from the field stack, compares if the first popped value is less than or equal to the second, and pushes a boolean result onto the stack.
    Le,
    /// Pops two elements from the field stack, compares if the first popped value is greater than the second, and pushes a boolean result onto the stack.
    Gt,
    /// Pops two elements from the field stack, compares if the first popped value is greater than or equal to the second, and pushes a boolean result onto the stack.
    Ge,
    /// Pops the provided amount of elements time 2 from the field stack and compares if the first n popped values are equal to the second set, and pushes a boolean result onto the stack.
    Eq(usize),
    /// Pops two elements from the field stack, compares if the first popped value is not equal to the second, and pushes a boolean result onto the stack.
    Neq,
    /// Pops two boolean values from the field stack, computes their boolean OR, and pushes the result onto the stack.
    BoolOr,
    /// Pops two boolean values from the field stack, computes their boolean AND, and pushes the result onto the stack.
    BoolAnd,
    /// Pops two elements from the field stack, computes their bitwise OR, and pushes the result onto the stack.
    BitOr,
    /// Pops two elements from the field stack, computes their bitwise AND, and pushes the result onto the stack.
    BitAnd,
    /// Pops two elements from the field stack, computes their bitwise XOR, and pushes the result onto the stack.
    BitXOr,
    /// Pops two elements from the field stack, shifts the first popped value right by the number of bits specified by the second, and pushes the result onto the stack.
    ShiftR,
    /// Pops two elements from the field stack, shifts the first popped value left by the number of bits specified by the second, and pushes the result onto the stack.
    ShiftL,
    /// Pops two elements from the index stack, multiplies them, and pushes the result onto the index stack.
    MulIndex,
    /// Pops two elements from the index stack, adds them, and pushes the result onto the index stack.
    AddIndex,
    /// Pops an element from the field stack, tries to cast it to a `usize`, and stores it on the index stack.
    ///
    /// Returns an error if this is not possible. This typically happens if the target field element is a
    /// secret shared value, which would leak the value.
    ToIndex,
    /// Jumps backwards by the specified number of lines in the [`CodeBlock`].
    JumpBack(usize),
    /// Pops the result of a predicate from the field stack and jumps the specified number
    /// of lines in the [`CodeBlock`] if the predicate is false.
    JumpIfFalse(usize),
    /// Pops an element from the field stack, converts it to a [`String`], and appends
    /// it to the log buffer.
    Log,
    /// Appends the [`String`] identified by the provided ID in the string table to
    /// the log buffer.
    LogString(usize),
    /// Flushes the log buffer and writes it to stdout. It also writes the
    /// provided line number of the log statement in the circom file.
    LogFlush(usize),
}

impl std::fmt::Display for MpcOpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            MpcOpCode::PushConstant(constant_index) => {
                format!("PUSH_CONSTANT_OP {}", constant_index)
            }
            MpcOpCode::PushIndex(index) => format!("PUSH_INDEX_OP {}", index),
            MpcOpCode::LoadSignals(amount) => format!("LOAD_SIGNALS_OP {amount}"),
            MpcOpCode::StoreSignals(amount) => format!("STORE_SIGNALS_OP {amount}"),
            MpcOpCode::LoadVars(amount) => format!("LOAD_VARS_OP {amount}"),
            MpcOpCode::StoreVars(amount) => format!("STORE_VARS_OP {amount}"),
            MpcOpCode::Call(symbol, return_vals) => {
                format!("CALL_OP {symbol} {return_vals}")
            }
            MpcOpCode::CreateCmp(header, amount) => {
                format!("CREATE_CMP_OP {} [{amount}]", header)
            }
            MpcOpCode::Assert(line) => format!("ASSERT_OP {line}"),
            MpcOpCode::If(jump) => format!("IF_OP {jump}"),
            MpcOpCode::EndTruthyBranch(jump) => format!("END_TRUTHY_OP {jump}"),
            MpcOpCode::EndFalsyBranch => "END_FALSY_OP".to_owned(),
            MpcOpCode::Add => "ADD_OP".to_owned(),
            MpcOpCode::Sub => "SUB_OP".to_owned(),
            MpcOpCode::Mul => "MUL_OP".to_owned(),
            MpcOpCode::Div => "DIV_OP".to_owned(),
            MpcOpCode::IntDiv => "INT_DIV_OP".to_owned(),
            MpcOpCode::Pow => "POW_OP".to_owned(),
            MpcOpCode::Mod => "MOD_OP".to_owned(),
            MpcOpCode::Neg => "NEG_OP".to_owned(),
            MpcOpCode::Lt => "LESS_THAN_OP".to_owned(),
            MpcOpCode::Le => "LESS_EQ_OP".to_owned(),
            MpcOpCode::Gt => "GREATER_THAN_OP".to_owned(),
            MpcOpCode::Ge => "GREATER_EQ_OP".to_owned(),
            MpcOpCode::Eq(size) => format!("IS_EQUAL_OP {size}"),
            MpcOpCode::Neq => "NOT_EQUAL_OP".to_owned(),
            MpcOpCode::BoolOr => "BOOL_OR_OP".to_owned(),
            MpcOpCode::BoolAnd => "BOOL_AND_OP".to_owned(),
            MpcOpCode::BitOr => "BIT_OR_OP".to_owned(),
            MpcOpCode::BitAnd => "BIT_AND_OP".to_owned(),
            MpcOpCode::BitXOr => "BIT_XOR_OP".to_owned(),
            MpcOpCode::ShiftR => "RIGHT_SHIFT_OP".to_owned(),
            MpcOpCode::ShiftL => "LEFT_SHIFT_OP".to_owned(),
            MpcOpCode::AddIndex => "ADD_INDEX_OP".to_owned(),
            MpcOpCode::MulIndex => "MUL_INDEX_OP".to_owned(),
            MpcOpCode::ToIndex => "TO_INDEX_OP".to_owned(),
            MpcOpCode::JumpBack(line) => format!("JUMP_BACK_OP {line}"),
            MpcOpCode::JumpIfFalse(line) => format!("JUMP_IF_FALSE_OP {line}"),
            MpcOpCode::Return => "RETURN_OP".to_owned(),
            MpcOpCode::ReturnFun => "RETURN_FUN_OP".to_owned(),
            MpcOpCode::ReturnSharedIfFun => "RETURN_SHARED_IF_FUN_OP".to_owned(),
            MpcOpCode::OutputSubComp(mapped, signal_code, amount) => {
                format!("OUTPUT_SUB_COMP_OP {mapped} {signal_code} {amount}")
            }
            MpcOpCode::InputSubComp(mapped, signal_code, amount) => {
                format!("INPUT_SUB_COMP_OP {mapped} {signal_code} {amount}")
            }
            MpcOpCode::Log => "LOG".to_owned(),
            MpcOpCode::LogString(idx) => format!("LOG_STR {idx}"),
            MpcOpCode::LogFlush(line) => format!("FLUSH_LOG_BUF {line}"),
        };
        f.write_str(&string)
    }
}
