use std::collections::HashMap;

use ark_ff::PrimeField;
use eyre::bail;

use crate::mpc::VmCircomWitnessExtension;

type AcceleratorFunction<F, C> = Box<
    dyn Fn(
            &mut C,
            &[<C as VmCircomWitnessExtension<F>>::VmType],
        ) -> eyre::Result<Vec<<C as VmCircomWitnessExtension<F>>::VmType>>
        + Send,
>;

pub struct ComponentAcceleratorOutput<T> {
    pub(crate) output: Vec<T>,
    pub(crate) intermediate: Vec<T>,
}

type AcceleratorComponent<F, C> = Box<
    dyn Fn(
            &mut C,
            &[<C as VmCircomWitnessExtension<F>>::VmType],
            usize,
        )
            -> eyre::Result<ComponentAcceleratorOutput<<C as VmCircomWitnessExtension<F>>::VmType>>
        + Send,
>;

#[derive(Default)]
pub struct MpcAccelerator<F: PrimeField, C: VmCircomWitnessExtension<F>> {
    registered_functions: HashMap<String, AcceleratorFunction<F, C>>,
    registered_component: HashMap<String, AcceleratorComponent<F, C>>,
}

impl<F: PrimeField, C: VmCircomWitnessExtension<F>> MpcAccelerator<F, C> {
    pub fn empty_accelerator() -> Self {
        Self {
            registered_functions: HashMap::default(),
            registered_component: HashMap::default(),
        }
    }

    pub fn full_mpc_accelerator() -> Self {
        let mut accelerator = Self::empty_accelerator();
        accelerator.register_sqrt();
        accelerator.register_num2bits();
        accelerator.register_addbits();
        accelerator.register_iszero();
        accelerator
    }

    pub fn register_function(
        &mut self,
        name: String,
        fun: impl Fn(&mut C, &[C::VmType]) -> eyre::Result<Vec<C::VmType>> + Send + 'static,
    ) {
        self.registered_functions.insert(name, Box::new(fun));
    }

    pub fn register_component(
        &mut self,
        name: String,
        fun: impl Fn(&mut C, &[C::VmType], usize) -> eyre::Result<ComponentAcceleratorOutput<C::VmType>>
            + Send
            + 'static,
    ) {
        self.registered_component.insert(name, Box::new(fun));
    }

    pub(crate) fn has_fn_accelerator(&self, name: &str) -> bool {
        self.registered_functions.contains_key(name)
    }

    pub(crate) fn has_cmp_accelerator(&self, name: &str) -> bool {
        self.registered_component.contains_key(name)
    }

    fn register_sqrt(&mut self) {
        self.register_function("sqrt_0".to_owned(), |protocol, args| {
            tracing::debug!("calling pre-defined sqrt accelerator");
            if args.len() != 1 {
                bail!("Calling SQRT accelerator with more than one argument!");
            }
            Ok(vec![protocol.sqrt(args[0].to_owned())?])
        });
    }

    fn register_num2bits(&mut self) {
        self.register_component("Num2Bits".to_string(), |protocol, args, amount_outputs| {
            tracing::debug!("calling pre-defined Num2Bits accelerator");
            if args.len() != 1 {
                bail!("Calling Num2Bits accelerator with more than one argument!");
            }
            protocol
                .num2bits(args[0].to_owned(), amount_outputs)
                .map(|output| ComponentAcceleratorOutput {
                    output,
                    intermediate: Vec::new(),
                })
        });
    }

    fn register_addbits(&mut self) {
        self.register_component("AddBits".to_string(), |protocol, args, amount_outputs| {
            tracing::debug!("calling pre-defined AddBits accelerator");
            Ok(ComponentAcceleratorOutput {
                output: Vec::new(),
                intermediate: Vec::new(),
            })
        });
    }

    fn register_iszero(&mut self) {
        self.register_component("IsZero".to_string(), |protocol, args, _amount_outputs| {
            tracing::debug!("calling pre-defined IsZero accelerator");
            if args.len() != 1 {
                bail!("Calling IsZero accelerator with more than one argument!");
            }
            let is_zero = protocol.eq(args[0].to_owned(), protocol.public_zero())?;
            let inv_input =
                protocol.cmux(is_zero.clone(), protocol.public_one(), args[0].to_owned())?;
            let inv = protocol.div(protocol.public_one(), inv_input)?;
            let helper = protocol.cmux(is_zero.clone(), protocol.public_zero(), inv)?;
            Ok(ComponentAcceleratorOutput {
                output: vec![is_zero],
                intermediate: vec![helper],
            })
        });
    }

    pub(crate) fn run_cmp_accelerator(
        &self,
        name: &str,
        protocol: &mut C,
        args: &[C::VmType],
        amount_outputs: usize,
    ) -> eyre::Result<ComponentAcceleratorOutput<C::VmType>> {
        let fun = self
            .registered_component
            .get(name)
            .ok_or(eyre::eyre!("cannot find accelerator {name}"))?;
        fun(protocol, args, amount_outputs)
    }

    pub(crate) fn run_fn_accelerator(
        &self,
        name: &str,
        protocol: &mut C,
        args: &[C::VmType],
    ) -> eyre::Result<Vec<C::VmType>> {
        let fun = self
            .registered_functions
            .get(name)
            .ok_or(eyre::eyre!("cannot find accelerator {name}"))?;
        fun(protocol, args)
    }
}
