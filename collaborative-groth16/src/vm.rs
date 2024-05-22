use std::env::vars;
use std::rc::Rc;
use std::{collections::HashMap, vec};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use circom_compiler::num_bigint::BigUint;
use color_eyre::eyre::eyre;

use self::compiler::{CodeBlock, CollaborativeCircomCompiler, FunDecl, TemplateDecl};

pub mod compiler;

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
struct Component<F: PrimeField> {
    //investigate later if we need stack frames
    //like that or if a single stack frame is enough??
    //depends on how complex functions work
    field_stack: StackFrame<F>,
    index_stack: StackFrame<usize>,
    output_signals: usize,
    input_signals: usize,
    intermediate_signals: usize,
    has_output: bool,
    signals: Vec<F>,
    vars: Vec<F>,
    sub_components: Vec<Component<F>>,
    body: Rc<CodeBlock>,
}

impl<F: PrimeField> Component<F> {
    fn init(templ_decl: &TemplateDecl) -> Self {
        Self {
            output_signals: templ_decl.output_signals,
            input_signals: templ_decl.input_signals,
            intermediate_signals: templ_decl.intermediate_signals,
            has_output: false,
            signals: vec![
                F::zero();
                templ_decl.input_signals
                    + templ_decl.output_signals
                    + templ_decl.intermediate_signals
            ],
            sub_components: vec![], //vec![Component::default(); templ_decl.sub_comps],
            vars: vec![F::zero(); templ_decl.vars],
            field_stack: Default::default(),
            index_stack: Default::default(),
            body: Rc::clone(&templ_decl.body),
        }
    }

    fn from_fun_decl(fun_decl: &FunDecl) -> Self {
        Self {
            output_signals: 0,
            input_signals: 0,
            intermediate_signals: 0,
            has_output: false,
            signals: vec![],
            vars: vec![F::zero(); fun_decl.vars],
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
            println!("DEBUG: {ip}    | Doing {inst}");
            match inst {
                compiler::MpcOpCode::PushConstant(index) => self.push_field(constant_table[*index]),
                compiler::MpcOpCode::PushIndex(index) => self.push_index(*index),
                compiler::MpcOpCode::LoadSignal(_template_id) => {
                    let index = self.pop_index();
                    self.push_field(self.signals[index]);
                }
                compiler::MpcOpCode::StoreSignal => {
                    //get index
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.signals[index] = signal;
                }
                compiler::MpcOpCode::LoadVar(_template_id) => {
                    let index = self.pop_index();
                    self.push_field(self.vars[index]);
                }
                compiler::MpcOpCode::StoreVar => {
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.vars[index] = signal;
                }
                compiler::MpcOpCode::Call(symbol) => {
                    let fun_decl = fun_decls.get(symbol).unwrap();
                    for params in fun_decl.params.iter() {
                        assert!(
                            params.length.is_empty(),
                            "TODO we need to check how to call this and when this happens"
                        );
                    }
                    let mut callable = Component::<F>::from_fun_decl(fun_decl);
                    let to_copy = self.field_stack.len() - fun_decl.params.len();

                    //copy the parameters
                    for (idx, param) in self.field_stack[to_copy..].iter().enumerate() {
                        callable.vars[idx] = *param;
                    }
                    callable.run(fun_decls, templ_decls, constant_table);
                    //copy the return value
                    for signal in callable.field_stack {
                        self.push_field(signal);
                    }
                }
                compiler::MpcOpCode::CreateCmp(symbol, dims) => {
                    //todo when we have multiple components we need to check where to put them with ids..
                    //for now we fill and see where it goes
                    let templ_decl = templ_decls.get(symbol).unwrap();
                    let amount = dims.iter().product();
                    (0..amount).for_each(|_| {
                        self.sub_components.push(Component::init(templ_decl));
                    });
                }
                compiler::MpcOpCode::OutputSubComp => {
                    //we have to compute the output signals if we did not do that already
                    let sub_comp_index = self.pop_index();
                    let index = self.pop_index();
                    //check whether we have to compute the output
                    if !self.sub_components[sub_comp_index].has_output {
                        self.sub_components[sub_comp_index].run(
                            fun_decls,
                            templ_decls,
                            constant_table,
                        );
                    }
                    self.push_field(self.sub_components[sub_comp_index].signals[index]);
                }
                compiler::MpcOpCode::InputSubComp => {
                    let sub_comp_index = self.pop_index();
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.sub_components[sub_comp_index].signals[index] = signal;
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
                    self.push_field(lhs / rhs);
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
                compiler::MpcOpCode::Ne => todo!(),
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
                compiler::MpcOpCode::Neq => todo!(),
                compiler::MpcOpCode::BoolOr => todo!(),
                compiler::MpcOpCode::BoolAnd => todo!(),
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
                    //TODO WE WANT SOMETHING BETTER THAN STRING PARSING
                    let signal = self.pop_field();
                    if signal.is_zero() {
                        self.push_index(0);
                    } else {
                        self.push_index(to_usize!(signal));
                    }
                }

                compiler::MpcOpCode::Jump(jump_to) => {
                    ip = *jump_to;
                    continue;
                }

                compiler::MpcOpCode::JumpIfFalse(jump_to) => {
                    let jump_to = *jump_to;
                    let cond = self.pop_field();
                    if cond.is_zero() {
                        ip = jump_to;
                        continue;
                    }
                }
                compiler::MpcOpCode::Return => {
                    //we are done
                    //just return
                    self.has_output = true;
                    break;
                }
                compiler::MpcOpCode::Panic(message) => panic!("{message}"),
            }
            ip += 1;
        }
    }
}

pub struct WitnessExtension<P: Pairing> {
    constant_table: Vec<P::ScalarField>,
    fun_decls: HashMap<String, FunDecl>,
    templ_decls: HashMap<String, TemplateDecl>,
    main: String,
}

impl<P: Pairing> WitnessExtension<P> {
    pub fn new(parser: CollaborativeCircomCompiler<P>, main: String) -> Self {
        Self {
            constant_table: parser.constant_table,
            fun_decls: parser.fun_decls,
            templ_decls: parser.templ_decls,
            main,
        }
    }

    pub fn run(&mut self, input_signals: Vec<P::ScalarField>) -> Vec<P::ScalarField> {
        let main_templ = self.templ_decls.get(&self.main).unwrap().clone();
        let mut main_component = Component::<P::ScalarField>::init(&main_templ);
        main_component.set_input_signals(input_signals);
        main_component.run(&self.fun_decls, &self.templ_decls, &self.constant_table);
        main_component.signals[..main_component.output_signals].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;

    use self::compiler::CompilerBuilder;

    use super::*;
    use std::str::FromStr;
    #[test]
    fn mul2() {
        let file = "../test_vectors/circuits/multiplier2.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned()).build();
        let result = builder.parse().unwrap().run(vec![
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
        ]);
        assert_eq!(result, vec![ark_bn254::Fr::from_str("33").unwrap()])
    }

    #[test]
    fn mul16() {
        let file = "../test_vectors/circuits/multiplier16.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned()).build();
        let result = builder.parse().unwrap().run(vec![
            ark_bn254::Fr::from_str("5").unwrap(),
            ark_bn254::Fr::from_str("10").unwrap(),
            ark_bn254::Fr::from_str("2").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("4").unwrap(),
            ark_bn254::Fr::from_str("5").unwrap(),
            ark_bn254::Fr::from_str("6").unwrap(),
            ark_bn254::Fr::from_str("7").unwrap(),
            ark_bn254::Fr::from_str("8").unwrap(),
            ark_bn254::Fr::from_str("9").unwrap(),
            ark_bn254::Fr::from_str("10").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("12").unwrap(),
            ark_bn254::Fr::from_str("13").unwrap(),
            ark_bn254::Fr::from_str("14").unwrap(),
            ark_bn254::Fr::from_str("15").unwrap(),
        ]);
        assert_eq!(
            result,
            vec![ark_bn254::Fr::from_str("65383718400000").unwrap()]
        );
    }

    #[test]
    fn control_flow() {
        let file = "../test_vectors/circuits/control_flow.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let result = builder
            .build()
            .parse()
            .unwrap()
            .run(vec![ark_bn254::Fr::from_str("1").unwrap()]);
        assert_eq!(result, vec![ark_bn254::Fr::from_str("13").unwrap()]);
    }

    #[test]
    fn functions() {
        let file = "../test_vectors/circuits/functions.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = vec![ark_bn254::Fr::from_str("5").unwrap()];
        let should_result = vec![ark_bn254::Fr::from_str("2").unwrap()];
        let is_result = builder.build().parse().unwrap().run(input);
        assert_eq!(is_result, should_result,);
    }
    #[test]
    fn bin_sum() {
        let file = "../test_vectors/circuits/binsum_caller.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let input = vec![
            //13
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            //12
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            //10
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let should_result = vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("0").unwrap(),
            ark_bn254::Fr::from_str("1").unwrap(),
        ];
        let is_result = builder.build().parse().unwrap().run(input);
        assert_eq!(is_result, should_result,);
    }

    #[test]
    fn mimc() {
        let file = "../test_vectors/circuits/mimc_hasher.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let result = builder.build().parse().unwrap().run(vec![
            ark_bn254::Fr::from_str("1").unwrap(),
            ark_bn254::Fr::from_str("2").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("4").unwrap(),
        ]);

        assert_eq!(
            result,
            vec![ark_bn254::Fr::from_str(
                "11942780089454131051516189009900830211326444317633948057223561824931207289212"
            )
            .unwrap()]
        );
    }

    #[test]
    fn pedersen() {
        let file = "../test_vectors/circuits/pedersen_hasher.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let result = builder
            .build()
            .parse()
            .unwrap()
            .run(vec![ark_bn254::Fr::from_str("5").unwrap()]);

        assert_eq!(
            result,
            vec![
                ark_bn254::Fr::from_str(
                    "19441207193282408010869542901357472504167256274773843225760657733604163132135",
                )
                .unwrap(),
                ark_bn254::Fr::from_str(
                    "19990967530340248564771981790127553242175633003074614939043423483648966286700",
                )
                .unwrap()
            ]
        );
    }

    #[ignore = "wip: known bug. Recursive if-else is not working"]
    #[test]
    fn poseidon() {
        let file = "../test_vectors/circuits/poseidon_hasher.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned())
            .link_library("../test_vectors/circuits/libs/");
        let result = builder
            .build()
            .parse()
            .unwrap()
            .run(vec![ark_bn254::Fr::from_str("5").unwrap()]);
        assert_eq!(
            result,
            vec![ark_bn254::Fr::from_str(
                "19065150524771031435284970883882288895168425523179566388456001105768498065277"
            )
            .unwrap()]
        );
    }
}
