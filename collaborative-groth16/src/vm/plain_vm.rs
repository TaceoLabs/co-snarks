use std::cell::RefCell;
use std::rc::Rc;
use std::{collections::HashMap, vec};

use super::compiler::{CollaborativeCircomCompilerParsed, FunDecl, TemplateDecl};
use super::op_codes::{self, CodeBlock};
use ark_ec::pairing::Pairing;
use ark_ff::One;
use ark_ff::PrimeField;
use circom_compiler::num_bigint::BigUint;
use color_eyre::eyre::eyre;
use itertools::Itertools;

macro_rules! to_field {
    ($big_int:expr) => {
        F::from_str(&$big_int.to_string())
            .map_err(|_| eyre!("Cannot parse string?"))
            .unwrap()
    };
}

macro_rules! to_usize {
    ($field:expr) => {
        $field.into_bigint().to_string().parse::<usize>().unwrap()
    };
}

macro_rules! to_bigint {
    ($field:expr) => {
        $field.into_bigint().to_string().parse::<BigUint>().unwrap()
    };
}

type StackFrame<F> = Vec<F>;

#[derive(Default, Clone)]
struct Runnable<F: PrimeField> {
    #[allow(dead_code)]
    symbol: String,
    field_stack: StackFrame<F>,
    index_stack: StackFrame<usize>,
    set_input_signals: usize,
    input_signals: usize,
    output_signals: usize,
    /// the offset inside the signals array
    my_offset: usize,
    /// all signals this component needs including all sub components
    total_signal_size: usize,
    signals: Rc<RefCell<Vec<F>>>,
    vars: Vec<F>,
    mappings: Vec<usize>,
    sub_components: Vec<Option<Runnable<F>>>,
    body: Rc<CodeBlock>,
}

impl<F: PrimeField> Runnable<F> {
    fn init(templ_decl: &TemplateDecl, signal_offset: usize, signals: Rc<RefCell<Vec<F>>>) -> Self {
        Self {
            symbol: templ_decl.symbol.clone(),
            set_input_signals: 0,
            output_signals: templ_decl.output_signals,
            input_signals: templ_decl.input_signals,
            my_offset: signal_offset,
            total_signal_size: templ_decl.signal_size,
            signals,
            sub_components: vec![None; templ_decl.sub_components], //vec![Component::default(); templ_decl.sub_comps],
            vars: vec![F::zero(); templ_decl.vars],
            mappings: templ_decl.mappings.clone(),
            field_stack: Default::default(),
            index_stack: Default::default(),
            body: Rc::clone(&templ_decl.body),
        }
    }

    fn from_fun_decl(fun_decl: &FunDecl) -> Self {
        Self {
            symbol: fun_decl.symbol.clone(),
            set_input_signals: 0,
            output_signals: 0,
            input_signals: 0,
            total_signal_size: 0,
            my_offset: 0,
            signals: Rc::new(RefCell::new(vec![])),
            vars: vec![F::zero(); fun_decl.vars],
            mappings: vec![],
            sub_components: vec![],
            field_stack: Default::default(),
            index_stack: Default::default(),
            body: Rc::clone(&fun_decl.body),
        }
    }

    fn set_input_signals(&mut self, input_signals: Vec<F>) {
        assert_eq!(
            self.input_signals,
            input_signals.len(),
            "You have to provide the input signals"
        );
        let mut signals = self.signals.borrow_mut();
        signals[1 + self.output_signals..1 + self.output_signals + self.input_signals]
            .copy_from_slice(&input_signals);
    }

    #[inline]
    fn push_field(&mut self, val: F) {
        self.field_stack.push(val)
    }

    #[inline]
    fn pop_field(&mut self) -> F {
        self.field_stack.pop().unwrap()
    }
    #[inline]
    fn push_index(&mut self, val: usize) {
        self.index_stack.push(val)
    }

    #[inline]
    fn pop_index(&mut self) -> usize {
        self.index_stack.pop().unwrap()
    }

    pub fn run(
        &mut self,
        fun_decls: &HashMap<String, FunDecl>,
        templ_decls: &HashMap<String, TemplateDecl>,
        constant_table: &[F],
    ) {
        let mut ip = 0;
        let current_body = Rc::clone(&self.body);
        loop {
            let inst = &current_body[ip];
            match inst {
                op_codes::MpcOpCode::PushConstant(index) => {
                    self.push_field(constant_table[*index]);
                }
                op_codes::MpcOpCode::PushIndex(index) => self.push_index(*index),
                op_codes::MpcOpCode::LoadSignal => {
                    let index = self.pop_index();
                    let signal = self.signals.borrow()[self.my_offset + index];
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
                    self.push_field(self.vars[index]);
                }
                op_codes::MpcOpCode::StoreVar => {
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.vars[index] = signal;
                }
                op_codes::MpcOpCode::StoreVars => {
                    let index = self.pop_index();
                    let amount = self.pop_index();
                    (0..amount).for_each(|i| {
                        self.vars[index + amount - i - 1] = self.pop_field();
                    });
                }
                op_codes::MpcOpCode::Call(symbol, return_vals) => {
                    let fun_decl = fun_decls.get(symbol).unwrap();
                    for params in fun_decl.params.iter() {
                        assert!(
                            params.length.is_empty(),
                            "TODO we need to check how to call this and when this happens"
                        );
                    }
                    let mut callable = Runnable::<F>::from_fun_decl(fun_decl);
                    let to_copy = self.field_stack.len() - fun_decl.params.len();

                    //copy the parameters
                    for (idx, param) in self.field_stack[to_copy..].iter().enumerate() {
                        callable.vars[idx] = *param;
                    }
                    //set size of return value
                    callable.output_signals = *return_vals;
                    callable.run(fun_decls, templ_decls, constant_table);
                    //copy the return value
                    for signal in callable.field_stack {
                        self.push_field(signal);
                    }
                }
                op_codes::MpcOpCode::CreateCmp(symbol, amount) => {
                    let relative_offset = self.pop_index();
                    let index = self.pop_index();
                    let templ_decl = templ_decls.get(symbol).unwrap();
                    let mut offset = self.my_offset + relative_offset;
                    for i in 0..*amount {
                        let sub_component =
                            Runnable::init(templ_decl, offset, Rc::clone(&self.signals));
                        offset += sub_component.total_signal_size;
                        self.sub_components[index + i] = Some(sub_component);
                    }
                }
                op_codes::MpcOpCode::OutputSubComp(mapped, signal_code) => {
                    let sub_comp_index = self.pop_index();
                    let mut index = self.pop_index();
                    let component = self.sub_components[sub_comp_index].take().unwrap();
                    if *mapped {
                        index += component.mappings[*signal_code];
                    }
                    let result = component.signals.borrow()[component.my_offset + index];
                    self.sub_components[sub_comp_index] = Some(component);
                    self.push_field(result);
                }
                op_codes::MpcOpCode::InputSubComp(mapped, signal_code) => {
                    let sub_comp_index = self.pop_index();
                    let mut index = self.pop_index();
                    let signal = self.pop_field();
                    let mut component = self.sub_components[sub_comp_index].take().unwrap();
                    if *mapped {
                        index += component.mappings[*signal_code];
                    }
                    component.signals.borrow_mut()[component.my_offset + index] = signal;
                    component.set_input_signals += 1;
                    if component.set_input_signals == component.input_signals {
                        component.run(fun_decls, templ_decls, constant_table);
                    }
                    self.sub_components[sub_comp_index] = Some(component);
                }
                op_codes::MpcOpCode::Assert => {
                    let assertion = self.pop_field();
                    if assertion.is_zero() {
                        panic!("assertion failed");
                    }
                }
                op_codes::MpcOpCode::Add => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(lhs + rhs);
                }
                op_codes::MpcOpCode::Sub => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(lhs - rhs);
                }
                op_codes::MpcOpCode::Mul => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(lhs * rhs);
                }
                op_codes::MpcOpCode::Neg => {
                    let x = self.pop_field();
                    self.push_field(-x);
                }
                op_codes::MpcOpCode::Div => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if rhs == F::zero() {
                        panic!("div by zero");
                    } else if rhs == F::one() {
                        self.push_field(lhs);
                    } else {
                        self.push_field(lhs / rhs);
                    }
                }
                op_codes::MpcOpCode::IntDiv => {
                    let rhs = to_usize!(self.pop_field());
                    let lhs = to_usize!(self.pop_field());
                    self.push_field(to_field!(lhs / rhs));
                }
                op_codes::MpcOpCode::Lt => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs < rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                op_codes::MpcOpCode::Le => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs <= rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                op_codes::MpcOpCode::Gt => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs > rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                op_codes::MpcOpCode::Ge => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs >= rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                op_codes::MpcOpCode::Eq => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs == rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                op_codes::MpcOpCode::Neq => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs != rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                op_codes::MpcOpCode::ShiftR => {
                    let rhs = to_usize!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs >> rhs));
                }
                op_codes::MpcOpCode::ShiftL => {
                    let rhs = to_usize!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs << rhs));
                }
                op_codes::MpcOpCode::BoolOr => todo!(),
                op_codes::MpcOpCode::BoolAnd => {
                    let rhs = to_usize!(self.pop_field());
                    let lhs = to_usize!(self.pop_field());
                    debug_assert!(rhs == 0 || rhs == 1);
                    debug_assert!(lhs == 0 || lhs == 1);
                    if rhs == 1 && lhs == 1 {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                op_codes::MpcOpCode::BitOr => {
                    let rhs = to_bigint!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs | rhs));
                }
                op_codes::MpcOpCode::BitAnd => {
                    let rhs = to_bigint!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs & rhs));
                }
                op_codes::MpcOpCode::BitXOr => {
                    let rhs = to_bigint!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs ^ rhs));
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
                    if signal.is_zero() {
                        self.push_index(0);
                    } else {
                        self.push_index(to_usize!(signal));
                    }
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
                    if cond.is_zero() {
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
                    let start = self.pop_index();
                    let end = self.output_signals;
                    let vals = self.vars[start..start + end].iter().cloned().collect_vec();
                    vals.into_iter().for_each(|var| {
                        self.push_field(var);
                    });
                    break;
                }
                op_codes::MpcOpCode::Log(line, amount) => {
                    //for now we only want expr log
                    //string log not supported
                    for _ in 0..*amount {
                        eprintln!("line {line:0>3}: \"{}\"", self.pop_field());
                    }
                }
            }
            ip += 1;
        }
    }
}

pub struct PlainWitnessExtension<P: Pairing> {
    signals: Rc<RefCell<Vec<P::ScalarField>>>,
    signal_to_witness: Vec<usize>,
    constant_table: Vec<P::ScalarField>,
    fun_decls: HashMap<String, FunDecl>,
    templ_decls: HashMap<String, TemplateDecl>,
    main: String,
}

impl<P: Pairing> PlainWitnessExtension<P> {
    pub fn new(parser: CollaborativeCircomCompilerParsed<P>) -> Self {
        let mut signals = vec![P::ScalarField::default(); parser.amount_signals];
        signals[0] = P::ScalarField::one();
        Self {
            signals: Rc::new(RefCell::new(signals)),
            signal_to_witness: parser.signal_to_witness,
            main: parser.main,
            constant_table: parser.constant_table,
            fun_decls: parser.fun_decls,
            templ_decls: parser.templ_decls,
        }
    }

    pub fn run(self, input_signals: Vec<P::ScalarField>) -> Vec<P::ScalarField> {
        let main_templ = self.templ_decls.get(&self.main).unwrap().clone();
        let mut main_component =
            Runnable::<P::ScalarField>::init(&main_templ, 1, Rc::clone(&self.signals));
        main_component.set_input_signals(input_signals);
        main_component.run(&self.fun_decls, &self.templ_decls, &self.constant_table);
        std::mem::drop(main_component);
        let ref_cell = Rc::try_unwrap(self.signals).expect("everyone else was dropped");
        let signals = RefCell::into_inner(ref_cell);
        let mut witness = Vec::with_capacity(self.signal_to_witness.len());
        for idx in self.signal_to_witness {
            witness.push(signals[idx]);
        }
        witness
    }
}
