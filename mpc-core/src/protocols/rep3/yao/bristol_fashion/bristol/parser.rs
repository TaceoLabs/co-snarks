use nom::{
    Finish, IResult,
    branch::alt,
    bytes::complete::tag,
    character::complete::{line_ending, multispace0, one_of, space1, u32 as char_u32},
    combinator::{all_consuming, opt},
    multi::{count, length_count},
    sequence::{preceded, separated_pair, terminated, tuple},
};

use crate::protocols::rep3::yao::bristol_fashion::CircuitBuilderError;

use super::{BristolFashionGate, builder::UnverifiedBristolFashionCircuit};

fn wire_and_gate_count(input: &str) -> IResult<&str, (u32, u32)> {
    // 123 123/n
    terminated(separated_pair(char_u32, space1, char_u32), line_ending)(input)
}

fn io_and_their_sizes(input: &str) -> IResult<&str, Vec<u32>> {
    // 2 123 123/n
    terminated(
        terminated(
            length_count(char_u32, preceded(space1, char_u32)),
            opt(space1),
        ),
        line_ending,
    )(input)
}
fn bool1(input: &str) -> IResult<&str, bool> {
    let (stream, c) = one_of("01")(input)?;
    Ok((stream, c == '1'))
}

fn eq_gate(input: &str) -> IResult<&str, BristolFashionGate> {
    let (stream, (_, _, _, _, val, _, wire, _, _)) = tuple((
        tag("1"),
        space1,
        tag("1"),
        space1,
        bool1,
        space1,
        char_u32,
        space1,
        tag("EQ"),
    ))(input)?;

    Ok((
        stream,
        BristolFashionGate::EqConst {
            input: val,
            outwire: wire as usize,
        },
    ))
}
fn eqw_gate(input: &str) -> IResult<&str, BristolFashionGate> {
    let (stream, (_, _, _, _, wire1, _, wire2, _, _)) = tuple((
        tag("1"),
        space1,
        tag("1"),
        space1,
        char_u32,
        space1,
        char_u32,
        space1,
        tag("EQW"),
    ))(input)?;

    Ok((
        stream,
        BristolFashionGate::EqWire {
            inwire: wire1 as usize,
            outwire: wire2 as usize,
        },
    ))
}
fn inv_gate(input: &str) -> IResult<&str, BristolFashionGate> {
    let (stream, (_, _, _, _, wire1, _, wire2, _, _)) = tuple((
        tag("1"),
        space1,
        tag("1"),
        space1,
        char_u32,
        space1,
        char_u32,
        space1,
        tag("INV"),
    ))(input)?;

    Ok((
        stream,
        BristolFashionGate::Inv {
            inwire: wire1 as usize,
            outwire: wire2 as usize,
        },
    ))
}
fn and_gate(input: &str) -> IResult<&str, BristolFashionGate> {
    let (stream, (_, _, _, _, wire1, _, wire2, _, wire3, _, _)) = tuple((
        tag("2"),
        space1,
        tag("1"),
        space1,
        char_u32,
        space1,
        char_u32,
        space1,
        char_u32,
        space1,
        tag("AND"),
    ))(input)?;

    Ok((
        stream,
        BristolFashionGate::And {
            inwire1: wire1 as usize,
            inwire2: wire2 as usize,
            outwire: wire3 as usize,
        },
    ))
}
fn xor_gate(input: &str) -> IResult<&str, BristolFashionGate> {
    let (stream, (_, _, _, _, wire1, _, wire2, _, wire3, _, _)) = tuple((
        tag("2"),
        space1,
        tag("1"),
        space1,
        char_u32,
        space1,
        char_u32,
        space1,
        char_u32,
        space1,
        tag("XOR"),
    ))(input)?;

    Ok((
        stream,
        BristolFashionGate::Xor {
            inwire1: wire1 as usize,
            inwire2: wire2 as usize,
            outwire: wire3 as usize,
        },
    ))
}

fn gate(input: &str) -> IResult<&str, BristolFashionGate> {
    terminated(
        alt((xor_gate, and_gate, inv_gate, eq_gate, eqw_gate)),
        line_ending,
    )(input)
}

fn gates(input: &str, num_gates: usize) -> IResult<&str, Vec<BristolFashionGate>> {
    all_consuming(terminated(count(gate, num_gates), multispace0))(input)
}

type BristolCircuitHeader = ((u32, u32), Vec<u32>, Vec<u32>);

fn header(input: &str) -> IResult<&str, BristolCircuitHeader> {
    terminated(
        tuple((wire_and_gate_count, io_and_their_sizes, io_and_their_sizes)),
        line_ending,
    )(input)
}

pub fn parse(input: &str) -> Result<UnverifiedBristolFashionCircuit, CircuitBuilderError> {
    // parse the header
    let (input, ((num_gates, num_wires), inputs, outputs)) =
        header(input).map_err(|e| CircuitBuilderError::ParseError(e.to_string()))?;

    // parse the gates
    let (_, gates) = gates(input, num_gates as usize)
        .finish()
        .map_err(|e| CircuitBuilderError::ParseError(e.to_string()))?;

    let mut cur_idx = 0;

    // first wires are inputs
    let input_wires = inputs
        .into_iter()
        .map(|wires_i| {
            let wires = (cur_idx..cur_idx + wires_i as usize).collect();
            cur_idx += wires_i as usize;
            wires
        })
        .collect();

    // last wires are outputs
    let mut cur_idx = (num_wires - outputs.iter().sum::<u32>()) as usize;
    let output_wires = outputs
        .into_iter()
        .map(|wires_i| {
            let wires = (cur_idx..cur_idx + wires_i as usize).collect();
            cur_idx += wires_i as usize;
            wires
        })
        .collect();

    Ok(UnverifiedBristolFashionCircuit {
        num_wires: num_wires as usize,
        input_wires,
        output_wires,
        gates,
    })
}
