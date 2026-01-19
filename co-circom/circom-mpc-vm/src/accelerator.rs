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

/// Output of a component accelerator for Co-Circom witness extension
#[derive(Clone)]
pub struct ComponentAcceleratorOutput<T> {
    pub(crate) output: Vec<T>,
    pub(crate) intermediate: Vec<T>,
}

impl<T> ComponentAcceleratorOutput<T> {
    /// Creates a new ComponentAcceleratorOutput
    pub fn new(output: Vec<T>, intermediate: Vec<T>) -> Self {
        Self {
            output,
            intermediate,
        }
    }
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

#[derive(Debug, Clone)]
pub struct MpcAcceleratorConfig {
    /// Whether to use the pre-defined SQRT accelerator
    /// Default: true
    pub(crate) sqrt: bool,
    /// Whether to use the pre-defined NUM2BITS accelerator
    /// Default: true
    pub(crate) num2bits: bool,
    /// Whether to use the pre-defined ADDBITS accelerator
    /// Default: true
    pub(crate) addbits: bool,
    /// Whether to use the pre-defined ISZERO accelerator
    /// Default: true
    pub(crate) iszero: bool,
    /// Whether to use the pre-defined POSEIDON2 accelerator
    /// Default: true
    pub(crate) poseidon2: bool,
}

impl Default for MpcAcceleratorConfig {
    fn default() -> Self {
        Self {
            sqrt: true,
            num2bits: true,
            addbits: true,
            iszero: true,
            poseidon2: true,
        }
    }
}

fn map_env_string_to_bool(value: &str) -> bool {
    match value.to_ascii_lowercase().as_str() {
        "1" => true,
        "true" => true,
        "on" => true,
        "0" => false,
        "false" => false,
        "off" => false,
        _ => {
            tracing::warn!("Invalid value for boolean ENV var, defaulting to true");
            true
        }
    }
}

impl MpcAcceleratorConfig {
    /// Constructs an MpcAcceleratorConfig from the environment variables
    ///
    /// If a variable is not set, it defaults to true
    /// The variables are of the form `CIRCOM_MPC_ACCELERATOR_<NAME>` where `<NAME>` is the name of the accelerator.
    ///
    /// Supported accelerators:
    /// - SQRT
    /// - NUM2BITS
    /// - ADDBITS
    /// - ISZERO
    /// - POSEIDON2
    ///
    /// Possible values for the boolean variables are: "1", "true", "on", "0", "false", "off"
    pub fn from_env() -> Self {
        Self {
            sqrt: std::env::var("CIRCOM_MPC_ACCELERATOR_SQRT")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            num2bits: std::env::var("CIRCOM_MPC_ACCELERATOR_NUM2BITS")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            addbits: std::env::var("CIRCOM_MPC_ACCELERATOR_ADDBITS")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            iszero: std::env::var("CIRCOM_MPC_ACCELERATOR_ISZERO")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
            poseidon2: std::env::var("CIRCOM_MPC_ACCELERATOR_POSEIDON2")
                .map(|x| map_env_string_to_bool(&x))
                .unwrap_or(true),
        }
    }
}

#[derive(Default)]
pub struct MpcAccelerator<F: PrimeField, C: VmCircomWitnessExtension<F>> {
    registered_functions: HashMap<String, AcceleratorFunction<F, C>>,
    registered_component: HashMap<String, AcceleratorComponent<F, C>>,
}

impl<F: PrimeField, C: VmCircomWitnessExtension<F>> MpcAccelerator<F, C> {
    pub fn empty() -> Self {
        Self {
            registered_functions: HashMap::default(),
            registered_component: HashMap::default(),
        }
    }

    #[expect(unused)]
    pub fn full() -> Self {
        Self::from_config(Default::default())
    }

    pub fn from_config(config: MpcAcceleratorConfig) -> Self {
        let mut accelerator = Self::empty();
        if config.sqrt {
            accelerator.register_sqrt();
        }
        if config.num2bits {
            accelerator.register_num2bits();
        }
        if config.addbits {
            accelerator.register_addbits();
        }
        if config.iszero {
            accelerator.register_iszero();
        }
        if config.poseidon2 {
            accelerator.register_poseidon2();
        }
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
        self.register_component("AddBits".to_string(), |protocol, args, _amount_outputs| {
            tracing::debug!("calling pre-defined AddBits accelerator");
            if args.len() % 2 != 0 {
                bail!("Calling AddBits accelerator with odd number of arguments!");
            }
            let a = args[0..args.len() / 2].to_vec();
            let b = args[args.len() / 2..].to_vec();
            let (output, carry) = protocol.addbits(a, b)?;
            Ok(ComponentAcceleratorOutput {
                output,
                intermediate: vec![carry],
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
            let inv_input = protocol.add(args[0].to_owned(), is_zero.clone())?;
            let maybe_masked_inv = protocol.div(protocol.public_one(), inv_input)?;
            let helper = protocol.sub(maybe_masked_inv, is_zero.clone())?;
            Ok(ComponentAcceleratorOutput {
                output: vec![is_zero],
                intermediate: vec![helper],
            })
        });
    }

    fn register_poseidon2(&mut self) {
        self.register_component(
            "Poseidon2".to_string(),
            |protocol, args, _amount_outputs| {
                tracing::debug!("calling pre-defined Poseidon2 accelerator");
                let args_len = args.len();
                let (state, traces) = if args_len == 2 {
                    protocol.poseidon2_accelerator::<2>(args.to_vec())?
                } else if args_len == 3 {
                    protocol.poseidon2_accelerator::<3>(args.to_vec())?
                } else if args_len == 4 {
                    protocol.poseidon2_accelerator::<4>(args.to_vec())?
                } else if args_len == 16 {
                    protocol.poseidon2_accelerator::<16>(args.to_vec())?
                } else {
                    bail!(
                        "Poseidon2 accelerator currently only supports input lengths 2, 3, 4 or 16, got {}",
                        args_len
                    );
                };
                Ok(ComponentAcceleratorOutput {
                    output: state,
                    intermediate: traces,
                })
            },
        );
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
