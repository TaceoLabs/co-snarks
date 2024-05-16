use std::rc::Rc;
use std::{collections::HashMap, vec};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use self::compiler::{CodeBlock, CollaborativeCircomCompiler, TemplateDecl};

pub mod compiler;

type StackFrame<F> = Vec<F>;

#[derive(Default, Clone)]
struct Component<F: PrimeField> {
    field_stack: StackFrame<F>,
    index_stack: StackFrame<usize>,
    output_signals: usize,
    input_signals: usize,
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
            has_output: false,
            signals: vec![F::zero(); templ_decl.input_signals + templ_decl.output_signals],
            sub_components: vec![], //vec![Component::default(); templ_decl.sub_comps],
            vars: vec![F::zero(); templ_decl.vars],
            field_stack: Default::default(),
            index_stack: Default::default(),
            body: Rc::clone(&templ_decl.body),
        }
    }
    fn set_input_signals(&mut self, input_signals: Vec<F>) {
        assert_eq!(
            self.input_signals,
            input_signals.len(),
            "You have to provide the input signals"
        );
        self.signals[self.output_signals..].copy_from_slice(&input_signals);
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

    pub fn run(&mut self, templ_decls: &HashMap<String, TemplateDecl>, constant_table: &[F]) {
        let mut ip = 0;
        loop {
            let inst = &self.body[ip];
            println!("DEBUG: {ip}    | Doing {inst}");
            match inst {
                compiler::MpcOpCode::PushConstant(index) => self.push_field(constant_table[*index]),
                compiler::MpcOpCode::PushIndex(index) => self.push_index(*index),
                compiler::MpcOpCode::LoadSignal(_template_id) => {
                    let index = self.pop_index();
                    self.push_field(self.signals[index]);
                }
                compiler::MpcOpCode::StoreSignal(_template_id) => {
                    //get index
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.signals[index] = signal;
                }
                compiler::MpcOpCode::LoadVar(_template_id) => {
                    let index = self.pop_index();
                    self.push_field(self.vars[index]);
                }
                compiler::MpcOpCode::StoreVar(_template_id) => {
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.vars[index] = signal;
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
                        println!("=========================");
                        println!("JUMPING TO SUB COMPONENT!");
                        println!();
                        self.sub_components[sub_comp_index].run(templ_decls, constant_table);
                        println!("RETURNING FROM SUB COMPONENT!");
                        println!("=========================");
                        println!();
                    }
                    self.push_field(self.sub_components[sub_comp_index].signals[index]);
                }
                compiler::MpcOpCode::InputSubComp => {
                    let sub_comp_index = self.pop_index();
                    let index = self.pop_index();
                    let signal = self.pop_field();
                    self.sub_components[sub_comp_index].signals[index] = signal;
                }
                //do we need those???
                compiler::MpcOpCode::PushStackFrame => {
                    // self.field_stack.push(StackFrame::default());
                    // self.index_stack.push(StackFrame::default());
                }
                compiler::MpcOpCode::PopStackFrame => {
                    // self.field_stack.pop().unwrap();
                    // self.index_stack.pop().unwrap();
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
                compiler::MpcOpCode::Div => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    self.push_field(lhs / rhs);
                }
                compiler::MpcOpCode::Lt => {
                    let rhs = self.pop_field();
                    let lhs = self.pop_field();
                    println!("{lhs}<{rhs}");
                    if lhs < rhs {
                        self.push_field(F::one());
                    } else {
                        self.push_field(F::zero());
                    }
                }
                compiler::MpcOpCode::Le => todo!(),
                compiler::MpcOpCode::Gt => todo!(),
                compiler::MpcOpCode::Ge => todo!(),
                compiler::MpcOpCode::Eq => todo!(),
                compiler::MpcOpCode::Ne => todo!(),
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
                        self.push_index(signal.to_string().parse().unwrap());
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
    fun_decls: HashMap<String, CodeBlock>,
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
        main_component.run(&self.templ_decls, &self.constant_table);
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
        let file = "/home/fnieddu/research/circom/circuits/multiplier2.circom";
        let builder = CompilerBuilder::<Bn254>::new(file.to_owned()).build();
        let result = builder.parse().unwrap().run(vec![
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
        ]);
        assert_eq!(result, vec![ark_bn254::Fr::from_str("31594").unwrap()])
    }

    #[test]
    fn mul16() {
        let file = "/home/fnieddu/research/circom/circuits/multiplier16.circom";
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
        )
    }
}
