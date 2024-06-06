pub type CodeBlock = Vec<MpcOpCode>;
#[derive(Clone)]
pub enum MpcOpCode {
    PushConstant(usize),
    PushIndex(usize),
    LoadSignal,
    StoreSignal,
    LoadVar,
    StoreVars,
    StoreVar,
    OutputSubComp(bool, usize),
    InputSubComp(bool, usize),
    CreateCmp(String, usize), //what else do we need?
    Call(String, usize),
    Return,
    ReturnFun,
    Assert,
    Add,
    Sub,
    Mul,
    Div,
    IntDiv,
    Pow,
    Mod,
    Neg,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Neq,
    BoolOr,
    BoolAnd,
    BitOr,
    BitAnd,
    BitXOr,
    ShiftR,
    ShiftL,
    MulIndex,
    AddIndex,
    ToIndex,
    Jump(usize),
    JumpBack(usize),
    JumpIfFalse(usize),
    Log,
    LogString(usize),
    LogFlush(usize),
}

impl std::fmt::Display for MpcOpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            MpcOpCode::PushConstant(constant_index) => {
                format!("PUSH_CONSTANT_OP {}", constant_index)
            }
            MpcOpCode::PushIndex(index) => format!("PUSH_INDEX_OP {}", index),
            MpcOpCode::LoadSignal => "LOAD_SIGNAL_OP".to_owned(),
            MpcOpCode::StoreSignal => "STORE_SIGNAL_OP".to_owned(),
            MpcOpCode::LoadVar => "LOAD_VAR_OP".to_owned(),
            MpcOpCode::StoreVar => "STORE_VAR_OP".to_owned(),
            MpcOpCode::StoreVars => "STORE_VARS_OP".to_owned(),
            MpcOpCode::Call(symbol, return_vals) => {
                format!("CALL_OP {symbol} {return_vals}")
            }
            MpcOpCode::CreateCmp(header, amount) => format!("CREATE_CMP_OP {} [{amount}]", header),
            MpcOpCode::Assert => "ASSERT_OP".to_owned(),
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
            MpcOpCode::Eq => "IS_EQUAL_OP".to_owned(),
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
            MpcOpCode::Jump(line) => format!("JUMP_OP {line}"),
            MpcOpCode::JumpBack(line) => format!("JUMP_BACK_OP {line}"),
            MpcOpCode::JumpIfFalse(line) => format!("JUMP_IF_FALSE_OP {line}"),
            MpcOpCode::Return => "RETURN_OP".to_owned(),
            MpcOpCode::ReturnFun => "RETURN_FUN_OP".to_owned(),
            MpcOpCode::OutputSubComp(mapped, signal_code) => {
                format!("OUTPUT_SUB_COMP_OP {mapped} {signal_code}")
            }
            MpcOpCode::InputSubComp(mapped, signal_code) => {
                format!("INPUT_SUB_COMP_OP {mapped} {signal_code}")
            }
            MpcOpCode::Log => "LOG".to_owned(),
            MpcOpCode::LogString(idx) => format!("LOG_STR {idx}"),
            MpcOpCode::LogFlush(line) => format!("FLUSH_LOG_BUF {line}"),
        };
        f.write_str(&string)
    }
}
