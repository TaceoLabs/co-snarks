use super::{
    compiler::{CollaborativeCircomCompilerParsed, FunDecl, TemplateDecl},
    op_codes::{self, CodeBlock},
    stack::Stack,
};
use ark_ec::pairing::Pairing;
use ark_ff::One;
use eyre::{bail, eyre, Result};
use itertools::Itertools;
use mpc_core::protocols::plain::PlainDriver;
use mpc_core::{
    protocols::aby3::{
        network::{Aby3MpcNet, Aby3Network},
        witness_extension_impl::Aby3VmType,
        Aby3Protocol,
    },
    traits::CircomWitnessExtensionProtocol,
};
use mpc_net::config::NetworkConfig;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use std::{cell::RefCell, collections::HashMap, rc::Rc};
pub struct WitnessExtension<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> {
    driver: C,
    signals: Rc<RefCell<Vec<C::VmType>>>,
    signal_to_witness: Vec<usize>,
    constant_table: Vec<C::VmType>,
    string_table: Vec<String>,
    fun_decls: HashMap<String, FunDecl>,
    templ_decls: HashMap<String, TemplateDecl>,
    main: String,
}

pub type PlainWitnessExtension<P> = WitnessExtension<P, PlainDriver>;
pub type Aby3WitnessExtension<P, N> =
    WitnessExtension<P, Aby3Protocol<<P as Pairing>::ScalarField, N>>;

#[derive(Default, Clone)]
struct Component<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> {
    #[allow(dead_code)]
    symbol: String,
    amount_vars: usize,
    provided_input_signals: usize,
    input_signals: usize,
    output_signals: usize,
    current_return_vals: usize,
    /// the offset inside the signals array
    my_offset: usize,
    /// all signals this component needs including all sub components
    total_signal_size: usize,
    field_stack: Stack<C::VmType>,
    index_stack: Stack<usize>,
    functions_ctx: Stack<FunctionCtx<C::VmType>>,
    signals: Rc<RefCell<Vec<C::VmType>>>,
    mappings: Vec<usize>,
    sub_components: Vec<Component<P, C>>,
    component_body: Rc<CodeBlock>,
    log_buf: String,
}

#[derive(Clone)]
struct FunctionCtx<T> {
    ip: usize,
    return_vals: usize,
    vars: Vec<T>,
    body: Rc<CodeBlock>,
}

impl<T> FunctionCtx<T> {
    fn new(ip: usize, return_vals: usize, vars: Vec<T>, body: Rc<CodeBlock>) -> Self {
        Self {
            ip,
            return_vals,
            vars,
            body,
        }
    }

    fn consume(self) -> (usize, usize, Vec<T>, Rc<CodeBlock>) {
        (self.ip, self.return_vals, self.vars, self.body)
    }
}

impl<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> Component<P, C> {
    fn init(
        templ_decl: &TemplateDecl,
        signal_offset: usize,
        signals: Rc<RefCell<Vec<C::VmType>>>,
    ) -> Self {
        Self {
            symbol: templ_decl.symbol.clone(),
            amount_vars: templ_decl.vars,
            provided_input_signals: 0,
            input_signals: templ_decl.input_signals,
            output_signals: templ_decl.output_signals,
            current_return_vals: 0,
            my_offset: signal_offset,
            total_signal_size: templ_decl.signal_size,
            field_stack: Stack::default(),
            index_stack: Stack::default(),
            functions_ctx: Stack::default(),
            signals,
            mappings: templ_decl.mappings.clone(),
            sub_components: Vec::with_capacity(templ_decl.sub_components),
            component_body: Rc::clone(&templ_decl.body),
            log_buf: String::with_capacity(1024),
        }
    }

    fn set_input_signals(&mut self, input_signals: Vec<C::VmType>) {
        assert_eq!(
            self.input_signals,
            input_signals.len(),
            "You have to provide the input signals"
        );
        let mut signals = self.signals.borrow_mut();
        signals[1 + self.output_signals..1 + self.output_signals + self.input_signals]
            .clone_from_slice(&input_signals);
    }

    #[inline]
    fn push_field(&mut self, val: C::VmType) {
        self.field_stack.push(val)
    }

    #[inline(always)]
    fn pop_field(&mut self) -> C::VmType {
        self.field_stack.pop()
    }

    #[inline(always)]
    fn push_index(&mut self, val: usize) {
        self.index_stack.push(val)
    }

    #[inline(always)]
    fn pop_index(&mut self) -> usize {
        self.index_stack.pop()
    }

    pub fn run(
        &mut self,
        protocol: &mut C,
        fun_decls: &HashMap<String, FunDecl>,
        templ_decls: &HashMap<String, TemplateDecl>,
        constant_table: &[C::VmType],
        string_table: &[String],
    ) -> Result<()> {
        let mut ip = 0;
        let mut current_body = Rc::clone(&self.component_body);
        let mut current_vars = vec![C::VmType::default(); self.amount_vars];
        loop {
            let inst = &current_body[ip];
            tracing::debug!("{ip:0>4}|   {inst}");
            match inst {
                op_codes::MpcOpCode::PushConstant(index) => {
                    self.push_field(constant_table[*index].clone());
                }
                op_codes::MpcOpCode::PushIndex(index) => self.push_index(*index),
                op_codes::MpcOpCode::LoadSignal => {
                    let index = self.pop_index();
                    let signal = self.signals.borrow()[self.my_offset + index].clone();
                    self.push_field(signal);
                }
                op_codes::MpcOpCode::StoreSignal => {
                    //get index
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.signals.borrow_mut()[self.my_offset + index] = signal;
                }
                op_codes::MpcOpCode::LoadVar => {
                    let index = self.pop_index();
                    self.push_field(current_vars[index].clone());
                }
                op_codes::MpcOpCode::StoreVar => {
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    current_vars[index] = signal;
                }
                op_codes::MpcOpCode::StoreVars => {
                    let index = self.pop_index();
                    let amount = self.pop_index();
                    (0..amount).for_each(|i| {
                        current_vars[index + amount - i - 1] = self.pop_field();
                    });
                }
                op_codes::MpcOpCode::Call(symbol, return_vals) => {
                    let fun_decl = fun_decls.get(symbol).ok_or(eyre!(
                        "{symbol} not found in function declaration. This must be a bug.."
                    ))?;
                    for params in fun_decl.params.iter() {
                        assert!(
                            params.length.is_empty(),
                            "TODO we need to check how to call this and when this happens"
                        );
                    }
                    let mut func_vars = vec![C::VmType::default(); fun_decl.vars];
                    let to_copy = self.field_stack.frame_len() - fun_decl.params.len();
                    //copy the parameters
                    for (idx, param) in self.field_stack.peek_stack_frame()[to_copy..]
                        .iter()
                        .enumerate()
                    {
                        func_vars[idx] = param.clone();
                    }
                    std::mem::swap(&mut func_vars, &mut current_vars);
                    //set size of return value
                    self.current_return_vals = *return_vals;
                    self.index_stack.push_stack_frame();
                    self.field_stack.push_stack_frame();
                    self.functions_ctx.push(FunctionCtx::new(
                        ip,
                        self.current_return_vals,
                        func_vars,
                        Rc::clone(&current_body),
                    ));
                    current_body = Rc::clone(&fun_decl.body);
                    ip = 0;
                    continue;
                }
                op_codes::MpcOpCode::CreateCmp(symbol, amount) => {
                    let relative_offset = self.pop_index();
                    let templ_decl = templ_decls.get(symbol).ok_or(eyre!(
                        "{symbol} not found in template declarations. This must be a bug"
                    ))?;
                    let mut offset = self.my_offset + relative_offset;
                    (0..*amount).for_each(|_| {
                        let sub_component =
                            Component::init(templ_decl, offset, Rc::clone(&self.signals));
                        offset += sub_component.total_signal_size;
                        self.sub_components.push(sub_component);
                    });
                }
                op_codes::MpcOpCode::OutputSubComp(mapped, signal_code) => {
                    let sub_comp_index = self.pop_index();
                    let mut index = self.pop_index();
                    let component = &mut self.sub_components[sub_comp_index];
                    if *mapped {
                        index += component.mappings[*signal_code];
                    }
                    let result = component.signals.borrow()[component.my_offset + index].clone();
                    self.push_field(result);
                }
                op_codes::MpcOpCode::InputSubComp(mapped, signal_code) => {
                    let sub_comp_index = self.pop_index();
                    let mut index = self.pop_index();
                    let signal = self.pop_field();
                    let component = &mut self.sub_components[sub_comp_index];
                    if *mapped {
                        index += component.mappings[*signal_code];
                    }
                    component.signals.borrow_mut()[component.my_offset + index] = signal;
                    component.provided_input_signals += 1;
                    if component.provided_input_signals == component.input_signals {
                        component.run(
                            protocol,
                            fun_decls,
                            templ_decls,
                            constant_table,
                            string_table,
                        )?;
                    }
                }
                op_codes::MpcOpCode::Assert => {
                    let assertion = self.pop_field();
                    if protocol.is_zero(assertion) {
                        panic!("assertion failed");
                    }
                }
                op_codes::MpcOpCode::Add => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_add(lhs, rhs));
                }
                op_codes::MpcOpCode::Sub => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_sub(lhs, rhs));
                }
                op_codes::MpcOpCode::Mul => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_mul(lhs, rhs)?);
                }
                op_codes::MpcOpCode::Div => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_div(lhs, rhs)?);
                }
                op_codes::MpcOpCode::Neg => {
                    let x = self.pop_field();
                    self.push_field(protocol.vm_neg(x));
                }
                op_codes::MpcOpCode::IntDiv => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_int_div(lhs, rhs)?);
                }
                op_codes::MpcOpCode::Lt => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_lt(lhs, rhs));
                }
                op_codes::MpcOpCode::Le => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_le(lhs, rhs));
                }
                op_codes::MpcOpCode::Gt => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_gt(lhs, rhs));
                }
                op_codes::MpcOpCode::Ge => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_ge(lhs, rhs));
                }
                op_codes::MpcOpCode::Eq => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_eq(lhs, rhs));
                }
                op_codes::MpcOpCode::Neq => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_neq(lhs, rhs));
                }
                op_codes::MpcOpCode::ShiftR => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_shift_r(lhs, rhs)?);
                }
                op_codes::MpcOpCode::ShiftL => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_shift_l(lhs, rhs)?);
                }
                op_codes::MpcOpCode::BoolOr => todo!(),
                op_codes::MpcOpCode::BoolAnd => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_bool_and(lhs, rhs)?);
                }
                op_codes::MpcOpCode::BitOr => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_bit_or(lhs, rhs)?);
                }
                op_codes::MpcOpCode::BitAnd => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_bit_and(lhs, rhs)?);
                }
                op_codes::MpcOpCode::BitXOr => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_bit_xor(lhs, rhs)?);
                }
                op_codes::MpcOpCode::AddIndex => {
                    let rhs = self.pop_index();
                    let lhs = self.pop_index();
                    self.push_index(lhs + rhs);
                }
                op_codes::MpcOpCode::MulIndex => {
                    let rhs = self.pop_index();
                    let lhs = self.pop_index();
                    self.push_index(lhs * rhs);
                }
                op_codes::MpcOpCode::ToIndex => {
                    let signal = self.pop_field();
                    let opened: BigUint = protocol.to_index(signal).into();
                    let idx = opened
                        .to_u64()
                        .ok_or(eyre!("Cannot convert var into u64"))?;
                    self.push_index(usize::try_from(idx)?);
                }
                op_codes::MpcOpCode::Jump(jump_forward) => {
                    ip += jump_forward;
                    continue;
                }

                op_codes::MpcOpCode::JumpBack(jump_backward) => {
                    ip -= jump_backward;
                    continue;
                }

                op_codes::MpcOpCode::JumpIfFalse(jump_forward) => {
                    let jump_to = jump_forward;
                    let cond = self.pop_field();
                    if protocol.is_zero(cond) {
                        ip += jump_to;
                        continue;
                    }
                }
                op_codes::MpcOpCode::Return => {
                    //we are done
                    //just return
                    break;
                }
                op_codes::MpcOpCode::ReturnFun => {
                    //check if we have multiple return values
                    if self.current_return_vals == 1 {
                        //copy the return value
                        let func_field_stack = self.field_stack.pop_stack_frame();
                        for signal in func_field_stack {
                            self.push_field(signal);
                        }
                    } else {
                        let start = self.pop_index();
                        let end = self.current_return_vals;
                        self.index_stack.pop_stack_frame();
                        self.field_stack.pop_stack_frame();
                        let vals = current_vars[start..start + end]
                            .iter()
                            .cloned()
                            .collect_vec();
                        vals.into_iter().for_each(|var| {
                            self.push_field(var);
                        });
                    }
                    let (old_ip, old_return_vals, mut old_vars, old_body) =
                        self.functions_ctx.pop().consume();
                    ip = old_ip;
                    self.current_return_vals = old_return_vals;
                    std::mem::swap(&mut current_vars, &mut old_vars);
                    current_body = old_body;
                }
                op_codes::MpcOpCode::Log => {
                    let field = self.pop_field();
                    self.log_buf.push_str(&field.to_string());
                    self.log_buf.push(' ');
                }
                op_codes::MpcOpCode::LogString(idx) => {
                    if *idx >= string_table.len() {
                        bail!(
                            "trying to access string on pos: {idx} but len is {}",
                            string_table.len()
                        );
                    }
                    self.log_buf.push_str(&string_table[*idx]);
                    self.log_buf.push(' ');
                }
                op_codes::MpcOpCode::LogFlush(line) => {
                    tracing::info!("line {line:0>4}: {}", self.log_buf);
                    self.log_buf.clear();
                }
            }
            ip += 1;
        }
        Ok(())
    }
}

impl<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> WitnessExtension<P, C> {
    pub fn run(mut self, input_signals: Vec<C::VmType>) -> Result<Vec<C::VmType>> {
        let main_templ = self
            .templ_decls
            .get(&self.main)
            .ok_or(eyre!("cannot find main template: {}", self.main))?;
        let mut main_component = Component::<P, C>::init(main_templ, 1, Rc::clone(&self.signals));
        main_component.set_input_signals(input_signals);
        main_component.run(
            &mut self.driver,
            &self.fun_decls,
            &self.templ_decls,
            &self.constant_table,
            &self.string_table,
        )?;
        std::mem::drop(main_component);
        let ref_cell = Rc::try_unwrap(self.signals).expect("everyone else was dropped");
        let signals = RefCell::into_inner(ref_cell);
        let mut witness = Vec::with_capacity(self.signal_to_witness.len());
        for idx in self.signal_to_witness {
            witness.push(signals[idx].clone());
        }
        Ok(witness)
    }
}

impl<P: Pairing> PlainWitnessExtension<P> {
    pub fn new(parser: CollaborativeCircomCompilerParsed<P>) -> Self {
        let mut signals = vec![P::ScalarField::default(); parser.amount_signals];
        signals[0] = P::ScalarField::one();
        Self {
            driver: PlainDriver {},
            signals: Rc::new(RefCell::new(signals)),
            signal_to_witness: parser.signal_to_witness,
            main: parser.main,
            constant_table: parser.constant_table,
            string_table: parser.string_table,
            fun_decls: parser.fun_decls,
            templ_decls: parser.templ_decls,
        }
    }
}

impl<P: Pairing, N: Aby3Network> Aby3WitnessExtension<P, N> {
    pub fn from_network(parser: CollaborativeCircomCompilerParsed<P>, network: N) -> Result<Self> {
        let driver = Aby3Protocol::<P::ScalarField, N>::new(network)?;
        let mut signals = vec![Aby3VmType::<P::ScalarField>::default(); parser.amount_signals];
        signals[0] = Aby3VmType::<P::ScalarField>::Public(P::ScalarField::one());
        Ok(Self {
            driver,
            signals: Rc::new(RefCell::new(signals)),
            signal_to_witness: parser.signal_to_witness,
            main: parser.main,
            constant_table: parser
                .constant_table
                .into_iter()
                .map(Aby3VmType::<P::ScalarField>::Public)
                .collect_vec(),
            string_table: parser.string_table,
            fun_decls: parser.fun_decls,
            templ_decls: parser.templ_decls,
        })
    }
}

impl<P: Pairing> Aby3WitnessExtension<P, Aby3MpcNet> {
    pub fn new(
        parser: CollaborativeCircomCompilerParsed<P>,
        config: NetworkConfig,
    ) -> Result<Self> {
        Self::from_network(parser, Aby3MpcNet::new(config)?)
    }
}
