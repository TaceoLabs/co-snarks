use std::{collections::HashMap, marker::PhantomData, vec};

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use self::compiler::{CodeBlock, CollaborativeCircomCompiler, TemplateDecl};

mod compiler;

type StackFrame<F> = Vec<Value<F>>;

#[derive(Clone)]
enum Value<F: PrimeField> {
    Index(usize),
    Signal(F),
}

impl<F: PrimeField> std::fmt::Display for Value<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Index(index) => f.write_str(&format!("Index({index})")),
            Value::Signal(fr) => f.write_str(&format!("Signal({fr})")),
        }
    }
}

#[derive(Default, Clone)]
struct Component<F: PrimeField> {
    output_signals: usize,
    input_signals: usize,
    signals: Vec<F>,
    vars: Vec<F>,
    sub_components: Vec<Component<F>>,
}

impl<F: PrimeField> Component<F> {
    fn init(templ_decl: &TemplateDecl) -> Self {
        Self {
            signals: vec![F::zero(); templ_decl.input_signals + templ_decl.output_signals],
            output_signals: templ_decl.output_signals,
            input_signals: templ_decl.input_signals,
            sub_components: vec![], //vec![Component::default(); templ_decl.sub_comps],
            vars: vec![F::zero(); templ_decl.vars],
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
}

pub struct WitnessExtension<P: Pairing> {
    stack: Vec<StackFrame<P::ScalarField>>,
    constant_table: Vec<P::ScalarField>,
    fun_decls: HashMap<String, CodeBlock>,
    templ_decls: HashMap<String, TemplateDecl>,
    components: Vec<Component<P::ScalarField>>,
    main: String,
}

impl<P: Pairing> WitnessExtension<P> {
    pub fn new(parser: CollaborativeCircomCompiler<P>, main: String) -> Self {
        Self {
            stack: vec![StackFrame::default()],
            constant_table: parser.constant_table,
            fun_decls: parser.fun_decls,
            templ_decls: parser.templ_decls,
            components: vec![],
            main,
        }
    }

    #[inline]
    fn push_stack(&mut self, val: Value<P::ScalarField>) {
        self.stack.last_mut().unwrap().push(val)
    }

    #[inline]
    fn pop_stack(&mut self) -> Value<P::ScalarField> {
        self.stack.last_mut().unwrap().pop().unwrap()
    }

    pub fn run(&mut self, input_signals: Vec<P::ScalarField>) -> Vec<P::ScalarField> {
        let main_templ = self.templ_decls.get(&self.main).unwrap().clone();
        let mut main_component = Component::<P::ScalarField>::init(&main_templ);
        main_component.set_input_signals(input_signals);
        let mut ip = 0;
        loop {
            let inst = &main_templ.body[ip];
            match inst {
                compiler::MpcOpCode::PushConstant(index) => {
                    self.push_stack(Value::Signal(self.constant_table[*index]))
                }
                compiler::MpcOpCode::PushIndex(index) => self.push_stack(Value::Index(*index)),
                compiler::MpcOpCode::LoadSignal(_template_id) => {
                    if let Value::Index(index) = self.pop_stack() {
                        self.push_stack(Value::Signal(main_component.signals[index]))
                    } else {
                        panic!("todo")
                    }
                }
                compiler::MpcOpCode::StoreSignal(_template_id) => {
                    //get index
                    let index = self.pop_stack();
                    let signal = self.pop_stack();
                    match (index, signal) {
                        (Value::Index(index), Value::Signal(signal)) => {
                            main_component.signals[index] = signal;
                        }
                        _ => todo!(),
                    }
                }
                compiler::MpcOpCode::LoadVar(_template_id) => {
                    if let Value::Index(index) = self.pop_stack() {
                        self.push_stack(Value::Signal(main_component.vars[index]))
                    } else {
                        panic!("todo")
                    }
                }
                compiler::MpcOpCode::StoreVar(_template_id) => {
                    let index = self.pop_stack();
                    let signal = self.pop_stack();
                    match (index, signal) {
                        (Value::Index(index), Value::Signal(signal)) => {
                            main_component.vars[index] = signal;
                        }
                        _ => todo!(),
                    }
                }
                compiler::MpcOpCode::CreateCmp(symbol, dims) => {
                    //todo when we have multiple components we need to check where to put them with ids..
                    //for now we fill and see where it goes
                    let templ_decl = self.templ_decls.get(symbol).unwrap();
                    let amount = dims.iter().fold(0, |a, b| a * b);
                    (0..amount).for_each(|_| {
                        main_component
                            .sub_components
                            .push(Component::init(templ_decl));
                    });
                }
                //do we need those
                compiler::MpcOpCode::PushStackFrame => self.stack.push(StackFrame::default()),
                compiler::MpcOpCode::PopStackFrame => {
                    self.stack.pop().unwrap();
                }
                compiler::MpcOpCode::Add => {
                    let lhs = self.pop_stack();
                    let rhs = self.pop_stack();
                    let result = match (lhs, rhs) {
                        (Value::Signal(lhs), Value::Signal(rhs)) => Value::Signal(lhs + rhs),
                        (Value::Index(_), Value::Signal(_)) => todo!(),
                        (Value::Signal(_), Value::Index(_)) => todo!(),
                        (Value::Index(_), Value::Index(_)) => todo!(),
                    };
                    self.push_stack(result)
                }
                compiler::MpcOpCode::Sub => todo!(),
                compiler::MpcOpCode::Mul => {
                    let lhs = self.pop_stack();
                    let rhs = self.pop_stack();
                    let result = match (lhs, rhs) {
                        (Value::Signal(lhs), Value::Signal(rhs)) => Value::Signal(lhs * rhs),
                        (Value::Index(_), Value::Signal(_)) => todo!(),
                        (Value::Signal(_), Value::Index(_)) => todo!(),
                        (Value::Index(_), Value::Index(_)) => todo!(),
                    };
                    self.push_stack(result)
                }
                compiler::MpcOpCode::Div => todo!(),
                compiler::MpcOpCode::Lt => {
                    let lhs = self.pop_stack();
                    let rhs = self.pop_stack();
                    // let test = lhs < rhs;
                    // P::ScalarField::from(test)
                }
                compiler::MpcOpCode::Le => todo!(),
                compiler::MpcOpCode::Gt => todo!(),
                compiler::MpcOpCode::Ge => todo!(),
                compiler::MpcOpCode::Eq => todo!(),
                compiler::MpcOpCode::Ne => todo!(),
                compiler::MpcOpCode::Jump(_) => todo!(),
                compiler::MpcOpCode::JumpIfFalse(_) => todo!(),
                compiler::MpcOpCode::Return => {
                    //for time being just return from main component
                    return main_component.signals[..main_component.output_signals].to_vec();
                }
                compiler::MpcOpCode::Panic(message) => panic!("{message}"),
            }
            ip += 1;
        }
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
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
            ark_bn254::Fr::from_str("3").unwrap(),
            ark_bn254::Fr::from_str("11").unwrap(),
        ]);
        let test = ark_bn254::Fr::from_str("11").unwrap();
        assert_eq!(result, vec![ark_bn254::Fr::from_str("31594").unwrap()])
    }
}
