use crate::types::{CollaborativeCircomCompilerParsed, FunDecl, InputList, TemplateDecl};

use super::{
    op_codes::{self, CodeBlock},
    stack::Stack,
};
use ark_ec::pairing::Pairing;
use ark_ff::One;
use collaborative_groth16::groth16::{SharedInput, SharedWitness};
use eyre::{bail, eyre, Result};
use itertools::Itertools;
use mpc_core::protocols::plain::PlainDriver;
use mpc_core::{
    protocols::aby3::{
        network::{Aby3MpcNet, Aby3Network},
        witness_extension_impl::Aby3VmType,
        Aby3Protocol,
    },
    to_usize,
    traits::CircomWitnessExtensionProtocol,
};
use mpc_net::config::NetworkConfig;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use std::{collections::HashMap, rc::Rc};
pub struct WitnessExtension<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> {
    main: String,
    ctx: WitnessExtensionCtx<P, C>,
    signal_to_witness: Vec<usize>,
    main_inputs: usize,
    main_outputs: usize,
    main_input_list: InputList,
    driver: C,
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
    current_return_vals: usize,
    /// the offset inside the signals array
    my_offset: usize,
    /// all signals this component needs including all sub components
    total_signal_size: usize,
    field_stack: Stack<C::VmType>,
    index_stack: Stack<usize>,
    functions_ctx: Stack<FunctionCtx<C::VmType>>,
    mappings: Vec<usize>,
    sub_components: Vec<Component<P, C>>,
    component_body: Rc<CodeBlock>,
    log_buf: String,
}

struct WitnessExtensionCtx<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> {
    signals: Vec<C::VmType>,
    fun_decls: HashMap<String, FunDecl>,
    templ_decls: HashMap<String, TemplateDecl>,
    constant_table: Vec<C::VmType>,
    string_table: Vec<String>,
}

impl<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> WitnessExtensionCtx<P, C> {
    fn new(
        signals: Vec<C::VmType>,
        constant_table: Vec<C::VmType>,
        fun_decls: HashMap<String, FunDecl>,
        templ_decls: HashMap<String, TemplateDecl>,
        string_table: Vec<String>,
    ) -> Self {
        Self {
            signals,
            constant_table,
            fun_decls,
            templ_decls,
            string_table,
        }
    }
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
    fn init(templ_decl: &TemplateDecl, signal_offset: usize) -> Self {
        Self {
            symbol: templ_decl.symbol.clone(),
            amount_vars: templ_decl.vars,
            provided_input_signals: 0,
            input_signals: templ_decl.input_signals,
            current_return_vals: 0,
            my_offset: signal_offset,
            total_signal_size: templ_decl.signal_size,
            field_stack: Stack::default(),
            index_stack: Stack::default(),
            functions_ctx: Stack::default(),
            mappings: templ_decl.mappings.clone(),
            sub_components: Vec::with_capacity(templ_decl.sub_components),
            component_body: Rc::clone(&templ_decl.body),
            log_buf: String::with_capacity(1024),
        }
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

    pub fn run(&mut self, protocol: &mut C, ctx: &mut WitnessExtensionCtx<P, C>) -> Result<()> {
        let mut ip = 0;
        let mut current_body = Rc::clone(&self.component_body);
        let mut current_vars = vec![C::VmType::default(); self.amount_vars];
        loop {
            let inst = &current_body[ip];
            tracing::debug!("{ip:0>4}|   {inst}");
            match inst {
                op_codes::MpcOpCode::PushConstant(index) => {
                    self.push_field(ctx.constant_table[*index].clone());
                }
                op_codes::MpcOpCode::PushIndex(index) => self.push_index(*index),
                op_codes::MpcOpCode::LoadSignal => {
                    let index = self.pop_index();
                    let signal = ctx.signals[self.my_offset + index].clone();
                    self.push_field(signal);
                }
                op_codes::MpcOpCode::StoreSignal => {
                    //get index
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    ctx.signals[self.my_offset + index] = signal;
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
                    let fun_decl = ctx.fun_decls.get(symbol).ok_or(eyre!(
                        "{symbol} not found in function declaration. This must be a bug.."
                    ))?;
                    let mut func_vars = vec![C::VmType::default(); fun_decl.vars];
                    let to_copy = self.field_stack.frame_len() - fun_decl.num_params;
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
                    let templ_decl = ctx.templ_decls.get(symbol).ok_or(eyre!(
                        "{symbol} not found in template declarations. This must be a bug"
                    ))?;
                    let mut offset = self.my_offset + relative_offset;
                    (0..*amount).for_each(|_| {
                        let sub_component = Component::init(templ_decl, offset);
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
                    let result = ctx.signals[component.my_offset + index].clone();
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
                    ctx.signals[component.my_offset + index] = signal;
                    component.provided_input_signals += 1;
                    if component.provided_input_signals == component.input_signals {
                        component.run(protocol, ctx)?;
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
                op_codes::MpcOpCode::Pow => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_pow(lhs, rhs)?);
                }
                op_codes::MpcOpCode::Mod => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(protocol.vm_mod(lhs, rhs)?);
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
                    //TODO what to do about that. This may leak some information
                    let signal = self.pop_field();
                    self.push_index(to_usize!(protocol.vm_open(signal)?));
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
                        self.field_stack
                            .pop_stack_frame()
                            .into_iter()
                            .for_each(|signal| {
                                self.push_field(signal);
                            });
                    } else {
                        let start = self.pop_index();
                        let end = self.current_return_vals;
                        self.index_stack.pop_stack_frame();
                        self.field_stack.pop_stack_frame();
                        current_vars[start..start + end]
                            .iter()
                            .cloned()
                            .for_each(|var| {
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
                    if *idx >= ctx.string_table.len() {
                        bail!(
                            "trying to access string on pos: {idx} but len is {}",
                            ctx.string_table.len()
                        );
                    }
                    self.log_buf.push_str(&ctx.string_table[*idx]);
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
    fn post_processing(mut self) -> Result<SharedWitness<C, P>> {
        // TODO: capacities
        let mut public_inputs = Vec::new();
        let mut witness = Vec::new();
        for (count, idx) in self.signal_to_witness.into_iter().enumerate() {
            // the +1 here is for the constant 1 which always is at position 0.
            if count < self.main_outputs + 1 {
                public_inputs.push(self.driver.vm_open(self.ctx.signals[idx].clone())?);
            } else {
                witness.push(self.driver.vm_to_share(self.ctx.signals[idx].clone()));
            }
        }
        Ok(SharedWitness {
            public_inputs,
            witness: witness.into(),
        })
    }

    fn set_input_signals(&mut self, input_signals: SharedInput<C, P>) -> Result<()> {
        for (name, offset, size) in self.main_input_list.iter() {
            let inputs = input_signals
                .shared_inputs
                .get(name)
                .cloned()
                .ok_or(eyre!("Cannot find signal \"{name}\" in provided input"))?;
            let mut counter = 0;
            for input in inputs.into_iter() {
                self.ctx.signals[offset + counter] = C::VmType::from(input);
                counter += 1;
            }
            if counter != *size {
                bail!("for input \"{name}\" expected {size} signals, got {counter}");
            }
        }
        Ok(())
    }

    fn set_flat_input_signals(&mut self, input_signals: Vec<C::VmType>) {
        assert_eq!(
            self.main_inputs,
            input_signals.len(),
            "You have to provide the input signals"
        );
        self.ctx.signals[1 + self.main_outputs..1 + self.main_outputs + self.main_inputs]
            .clone_from_slice(&input_signals);
    }

    fn call_main_component(&mut self) -> Result<()> {
        let main_templ = self
            .ctx
            .templ_decls
            .get(&self.main)
            .ok_or(eyre!("cannot find main template: {}", self.main))?;
        let mut main_component = Component::init(main_templ, 1);
        main_component.run(&mut self.driver, &mut self.ctx)?;
        Ok(())
    }
    pub fn run_with_flat(mut self, input_signals: Vec<C::VmType>) -> Result<SharedWitness<C, P>> {
        self.set_flat_input_signals(input_signals);
        tracing::info!("{:?}", &self.ctx.signals);
        self.call_main_component()?;
        self.post_processing()
    }
    pub fn run(mut self, input_signals: SharedInput<C, P>) -> Result<SharedWitness<C, P>> {
        self.set_input_signals(input_signals)?;
        tracing::info!("{:?}", &self.ctx.signals);
        self.call_main_component()?;
        self.post_processing()
    }
}

impl<P: Pairing> PlainWitnessExtension<P> {
    pub(crate) fn new(parser: CollaborativeCircomCompilerParsed<P>) -> Self {
        let mut signals = vec![P::ScalarField::default(); parser.amount_signals];
        signals[0] = P::ScalarField::one();
        Self {
            driver: PlainDriver {},
            signal_to_witness: parser.signal_to_witness,
            main: parser.main,
            ctx: WitnessExtensionCtx::new(
                signals,
                parser.constant_table,
                parser.fun_decls,
                parser.templ_decls,
                parser.string_table,
            ),
            main_inputs: parser.main_inputs,
            main_outputs: parser.main_outputs,
            main_input_list: parser.main_input_list,
        }
    }
}

impl<P: Pairing, N: Aby3Network> Aby3WitnessExtension<P, N> {
    pub(crate) fn from_network(
        parser: CollaborativeCircomCompilerParsed<P>,
        network: N,
    ) -> Result<Self> {
        let driver = Aby3Protocol::new(network)?;
        let mut signals = vec![Aby3VmType::default(); parser.amount_signals];
        signals[0] = Aby3VmType::Public(P::ScalarField::one());
        let constant_table = parser
            .constant_table
            .into_iter()
            .map(Aby3VmType::Public)
            .collect_vec();
        Ok(Self {
            driver,
            signal_to_witness: parser.signal_to_witness,
            main: parser.main,
            ctx: WitnessExtensionCtx::new(
                signals,
                constant_table,
                parser.fun_decls,
                parser.templ_decls,
                parser.string_table,
            ),
            main_inputs: parser.main_inputs,
            main_outputs: parser.main_outputs,
            main_input_list: parser.main_input_list,
        })
    }
}

impl<P: Pairing> Aby3WitnessExtension<P, Aby3MpcNet> {
    pub(crate) fn new(
        parser: CollaborativeCircomCompilerParsed<P>,
        config: NetworkConfig,
    ) -> Result<Self> {
        Self::from_network(parser, Aby3MpcNet::new(config)?)
    }
}
