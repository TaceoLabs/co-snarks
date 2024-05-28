use std::rc::Rc;
use std::{collections::HashMap, vec};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use circom_compiler::num_bigint::BigUint;
use color_eyre::eyre::eyre;
use itertools::Itertools;

use super::compiler::{self, CodeBlock, CollaborativeCircomCompilerParsed, FunDecl, TemplateDecl};

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
    output_signals: usize,
    input_signals: usize,
    has_output: bool,
    signals: Vec<F>,
    vars: Vec<F>,
    mappings: Vec<usize>,
    sub_components: Vec<Option<Runnable<F>>>,
    body: Rc<CodeBlock>,
}

impl<F: PrimeField> Runnable<F> {
    fn init(templ_decl: &TemplateDecl) -> Self {
        Self {
            symbol: templ_decl.symbol.clone(),
            set_input_signals: 0,
            output_signals: templ_decl.output_signals,
            input_signals: templ_decl.input_signals,
            has_output: false,
            signals: vec![
                F::zero();
                templ_decl.input_signals
                    + templ_decl.output_signals
                    + templ_decl.intermediate_signals
            ],
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
            has_output: false,
            signals: vec![],
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
        self.signals[self.output_signals..self.output_signals + self.input_signals]
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
                compiler::MpcOpCode::PushConstant(index) => {
                    self.push_field(constant_table[*index]);
                }
                compiler::MpcOpCode::PushIndex(index) => self.push_index(*index),
                compiler::MpcOpCode::LoadSignal => {
                    let index = self.pop_index();
                    self.push_field(self.signals[index]);
                }
                compiler::MpcOpCode::StoreSignal => {
                    //get index
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.signals[index] = signal;
                }
                compiler::MpcOpCode::LoadVar => {
                    let index = self.pop_index();
                    self.push_field(self.vars[index]);
                }
                compiler::MpcOpCode::StoreVar => {
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.vars[index] = signal;
                }
                compiler::MpcOpCode::StoreVars => {
                    let index = self.pop_index();
                    let amount = self.pop_index();
                    (0..amount).for_each(|i| {
                        self.vars[index + amount - i - 1] = self.pop_field();
                    });
                }
                compiler::MpcOpCode::Call(symbol, return_vals) => {
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
                compiler::MpcOpCode::CreateCmp(symbol, amount) => {
                    let index = self.pop_index();
                    let templ_decl = templ_decls.get(symbol).unwrap();
                    for i in 0..*amount {
                        self.sub_components[index + i] = Some(Runnable::init(templ_decl));
                    }
                }
                compiler::MpcOpCode::OutputSubComp(mapped, signal_code) => {
                    //we have to compute the output signals if we did not do that already
                    let sub_comp_index = self.pop_index();
                    let mut index = self.pop_index();
                    //check whether we have to compute the output
                    let component = self.sub_components[sub_comp_index].take().unwrap();
                    if !component.has_output {
                        panic!("We did not run already????");
                    }
                    if *mapped {
                        index += component.mappings[*signal_code];
                    }
                    let result = component.signals[index];
                    self.sub_components[sub_comp_index] = Some(component);
                    self.push_field(result);
                }
                compiler::MpcOpCode::InputSubComp(mapped, signal_code) => {
                    let sub_comp_index = self.pop_index();
                    let mut index = self.pop_index();
                    let signal = self.pop_field();
                    let mut component = self.sub_components[sub_comp_index].take().unwrap();
                    if *mapped {
                        index += component.mappings[*signal_code];
                    }
                    component.signals[index] = signal;
                    component.set_input_signals += 1;
                    if component.set_input_signals == component.input_signals {
                        debug_assert!(!component.has_output);
                        component.run(fun_decls, templ_decls, constant_table);
                    }
                    self.sub_components[sub_comp_index] = Some(component);
                }
                compiler::MpcOpCode::Assert => {
                    let assertion = self.pop_field();
                    if assertion.is_zero() {
                        panic!("assertion failed");
                    }
                }
                compiler::MpcOpCode::Add => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(lhs + rhs);
                }
                compiler::MpcOpCode::Sub => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(lhs - rhs);
                }
                compiler::MpcOpCode::Mul => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(lhs * rhs);
                }
                compiler::MpcOpCode::Neg => {
                    let x = self.pop_field();
                    self.push_field(-x);
                }
                compiler::MpcOpCode::Div => {
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
                compiler::MpcOpCode::IntDiv => {
                    let rhs = to_usize!(self.pop_field());
                    let lhs = to_usize!(self.pop_field());
                    self.push_field(to_field!(lhs / rhs));
                }
                compiler::MpcOpCode::Lt => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs < rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                compiler::MpcOpCode::Le => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs <= rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                compiler::MpcOpCode::Gt => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs > rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                compiler::MpcOpCode::Ge => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs >= rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                compiler::MpcOpCode::Eq => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs == rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                compiler::MpcOpCode::Neq => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    if lhs != rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                compiler::MpcOpCode::ShiftR => {
                    let rhs = to_usize!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs >> rhs));
                }
                compiler::MpcOpCode::ShiftL => {
                    let rhs = to_usize!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs << rhs));
                }
                compiler::MpcOpCode::BoolOr => todo!(),
                compiler::MpcOpCode::BoolAnd => {
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
                compiler::MpcOpCode::BitOr => {
                    let rhs = to_bigint!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs | rhs));
                }
                compiler::MpcOpCode::BitAnd => {
                    let rhs = to_bigint!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs & rhs));
                }
                compiler::MpcOpCode::BitXOr => {
                    let rhs = to_bigint!(self.pop_field());
                    let lhs = to_bigint!(self.pop_field());
                    self.push_field(to_field!(lhs ^ rhs));
                }
                compiler::MpcOpCode::AddIndex => {
                    let rhs = self.pop_index();
                    let lhs = self.pop_index();
                    self.push_index(lhs + rhs);
                }
                compiler::MpcOpCode::MulIndex => {
                    let rhs = self.pop_index();
                    let lhs = self.pop_index();
                    self.push_index(lhs * rhs);
                }
                compiler::MpcOpCode::ToIndex => {
                    let signal = self.pop_field();
                    if signal.is_zero() {
                        self.push_index(0);
                    } else {
                        self.push_index(to_usize!(signal));
                    }
                }
                compiler::MpcOpCode::Jump(jump_forward) => {
                    ip += *jump_forward;
                    continue;
                }

                compiler::MpcOpCode::JumpBack(jump_backward) => {
                    ip -= *jump_backward;
                    continue;
                }

                compiler::MpcOpCode::JumpIfFalse(jump_forward) => {
                    let jump_to = *jump_forward;
                    let cond = self.pop_field();
                    if cond.is_zero() {
                        ip += jump_to;
                        continue;
                    }
                }
                compiler::MpcOpCode::Return => {
                    //we are done
                    //just return
                    self.has_output = true;
                    break;
                }
                compiler::MpcOpCode::ReturnFun => {
                    let start = self.pop_index();
                    let end = self.output_signals;
                    let vals = self.vars[start..start + end].iter().cloned().collect_vec();
                    vals.into_iter().for_each(|var| {
                        self.push_field(var);
                    });
                    break;
                }
                compiler::MpcOpCode::Panic(message) => panic!("{message}"),
                compiler::MpcOpCode::Log(line, amount) => {
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
    constant_table: Vec<P::ScalarField>,
    fun_decls: HashMap<String, FunDecl>,
    templ_decls: HashMap<String, TemplateDecl>,
    main: String,
}

impl<P: Pairing> PlainWitnessExtension<P> {
    pub fn new(parser: CollaborativeCircomCompilerParsed<P>) -> Self {
        Self {
            main: parser.main,
            constant_table: parser.constant_table,
            fun_decls: parser.fun_decls,
            templ_decls: parser.templ_decls,
        }
    }

    pub fn run(&mut self, input_signals: Vec<P::ScalarField>) -> Vec<P::ScalarField> {
        let main_templ = self.templ_decls.get(&self.main).unwrap().clone();
        let mut main_component = Runnable::<P::ScalarField>::init(&main_templ);
        main_component.set_input_signals(input_signals);
        main_component.run(&self.fun_decls, &self.templ_decls, &self.constant_table);
        main_component.signals[..main_component.output_signals].to_vec()
    }
}
