use std::{cell::RefCell, collections::HashMap, rc::Rc};

use super::{
    compiler::{FunDecl, TemplateDecl},
    op_codes::{self, CodeBlock},
    stack::Stack,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use color_eyre::eyre::{eyre, Result};
use itertools::Itertools;
use mpc_core::traits::CircomWitnessExtensionProtocol;
pub struct PlainWitnessExtension<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> {
    signals: Rc<RefCell<Vec<C::VmType>>>,
    signal_to_witness: Vec<usize>,
    constant_table: Vec<P::ScalarField>,
    fun_decls: HashMap<String, FunDecl>,
    templ_decls: HashMap<String, TemplateDecl>,
    main: String,
}

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
    ) -> Result<()> {
        let mut ip = 0;
        let mut current_body = Rc::clone(&self.component_body);
        let mut current_vars = vec![C::VmType::default(); self.amount_vars];
        loop {
            let inst = &current_body[ip];
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
                        component.run(protocol, fun_decls, templ_decls, constant_table)?;
                    }
                }
                op_codes::MpcOpCode::Assert => {
                    let assertion = self.pop_field();
                    todo!("is zero needed")
                    //if assertion.is_zero() {
                    //    panic!("assertion failed");
                    //}
                }
                op_codes::MpcOpCode::Add => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    protocol.vm_add(lhs, rhs);
                }
                op_codes::MpcOpCode::Sub => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    protocol.vm_sub(lhs, rhs);
                }
                op_codes::MpcOpCode::Mul => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    protocol.vm_mul(lhs, rhs);
                }
                op_codes::MpcOpCode::Neg => {
                    let x = self.pop_field();
                    protocol.vm_neg(x);
                }
                op_codes::MpcOpCode::Div => {
                    todo!("field div");
                    // let rhs = self.pop_field();
                    // let lhs = self.pop_field();
                    // if rhs == F::zero() {
                    //     panic!("div by zero");
                    // } else if rhs == F::one() {
                    //     self.push_field(lhs);
                    // } else {
                    //     self.push_field(lhs / rhs);
                    // }
                }
                op_codes::MpcOpCode::IntDiv => {
                    todo!("int div");
                    //let rhs = to_usize!(self.pop_field());
                    //let lhs = to_usize!(self.pop_field());
                    //self.push_field(to_field!(lhs / rhs));
                }
                op_codes::MpcOpCode::Lt => {
                    todo!("lt");
                    //let rhs = self.pop_field();
                    //let lhs = self.pop_field();
                    //if lhs < rhs {
                    //    self.push_field(F::one());
                    //} else {
                    //    self.push_field(F::zero());
                    //}
                }
                op_codes::MpcOpCode::Le => {
                    todo!("le")
                    //let rhs = self.pop_field();
                    //let lhs = self.pop_field();
                    //if lhs <= rhs {
                    //    self.push_field(F::one());
                    //} else {
                    //    self.push_field(F::zero());
                    //}
                }
                op_codes::MpcOpCode::Gt => {
                    todo!("gt")
                    //let rhs = self.pop_field();
                    //let lhs = self.pop_field();
                    //if lhs > rhs {
                    //    self.push_field(F::one());
                    //} else {
                    //    self.push_field(F::zero());
                    //}
                }
                op_codes::MpcOpCode::Ge => {
                    todo!("Ge");
                    //let rhs = self.pop_field();
                    //let lhs = self.pop_field();
                    //if lhs >= rhs {
                    //    self.push_field(F::one());
                    //} else {
                    //    self.push_field(F::zero());
                    //}
                }
                op_codes::MpcOpCode::Eq => {
                    todo!("eq")
                    //let rhs = self.pop_field();
                    //let lhs = self.pop_field();
                    //if lhs == rhs {
                    //    self.push_field(F::one());
                    //} else {
                    //    self.push_field(F::zero());
                    //}
                }
                op_codes::MpcOpCode::Neq => {
                    todo!("neq")
                    //let rhs = self.pop_field();
                    //let lhs = self.pop_field();
                    //if lhs != rhs {
                    //    self.push_field(F::one());
                    //} else {
                    //    self.push_field(F::zero());
                    //}
                }
                op_codes::MpcOpCode::ShiftR => {
                    todo!("shiftR");
                    //let rhs = to_usize!(self.pop_field());
                    //let lhs = to_bigint!(self.pop_field());
                    //self.push_field(to_field!(lhs >> rhs));
                }
                op_codes::MpcOpCode::ShiftL => {
                    todo!("ShiftL");
                    //let rhs = to_usize!(self.pop_field());
                    //let lhs = to_bigint!(self.pop_field());
                    //self.push_field(to_field!(lhs << rhs));
                }
                op_codes::MpcOpCode::BoolOr => todo!(),
                op_codes::MpcOpCode::BoolAnd => {
                    todo!("boolAnd");
                    //let rhs = to_usize!(self.pop_field());
                    //let lhs = to_usize!(self.pop_field());
                    //debug_assert!(rhs == 0 || rhs == 1);
                    //debug_assert!(lhs == 0 || lhs == 1);
                    //if rhs == 1 && lhs == 1 {
                    //    self.push_field(F::one());
                    //} else {
                    //    self.push_field(F::zero());
                    //}
                }
                op_codes::MpcOpCode::BitOr => {
                    todo!("bitOr");
                    //let rhs = to_bigint!(self.pop_field());
                    //let lhs = to_bigint!(self.pop_field());
                    //self.push_field(to_field!(lhs | rhs));
                }
                op_codes::MpcOpCode::BitAnd => {
                    todo!("bitAnd");
                    //let rhs = to_bigint!(self.pop_field());
                    //let lhs = to_bigint!(self.pop_field());
                    //self.push_field(to_field!(lhs & rhs));
                }
                op_codes::MpcOpCode::BitXOr => {
                    todo!("bixXor");
                    //let rhs = to_bigint!(self.pop_field());
                    //let lhs = to_bigint!(self.pop_field());
                    //self.push_field(to_field!(lhs ^ rhs));
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
                    todo!("toIndex");
                    //let signal = self.pop_field();
                    //if signal.is_zero() {
                    //    self.push_index(0);
                    //} else {
                    //    self.push_index(to_usize!(signal));
                    //}
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
                    todo!("jumpIfFalse")
                    //let jump_to = jump_forward;
                    //let cond = self.pop_field();
                    //if cond.is_zero() {
                    //    ip += jump_to;
                    //    continue;
                    //}
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
                op_codes::MpcOpCode::Log(line, amount) => {
                    todo!("log");
                    //for now we only want expr log
                    //string log not supported
                    //for _ in 0..*amount {
                    //    eprintln!("line {line:0>3}: \"{}\"", self.pop_field());
                    //}
                }
            }
            ip += 1;
        }
        Ok(())
    }
}
/*
impl<P: Pairing, C: CircomWitnessExtensionProtocol<P::ScalarField>> PlainWitnessExtension<P, C> {
    pub fn run(self, input_signals: Vec<P::ScalarField>) -> Result<Vec<P::ScalarField>> {
        let main_templ = self
            .templ_decls
            .get(&self.main)
            .ok_or(eyre!("cannot find main template: {}", self.main))?;
        let mut main_component =
            Component::<P::ScalarField>::init(main_templ, 1, Rc::clone(&self.signals));
        main_component.set_input_signals(input_signals);
        main_component.run(&self.fun_decls, &self.templ_decls, &self.constant_table)?;
        std::mem::drop(main_component);
        let ref_cell = Rc::try_unwrap(self.signals).expect("everyone else was dropped");
        let signals = RefCell::into_inner(ref_cell);
        let mut witness = Vec::with_capacity(self.signal_to_witness.len());
        for idx in self.signal_to_witness {
            witness.push(signals[idx]);
        }
        Ok(witness)
    }
}
*/
