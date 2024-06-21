#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE, STDOUT
import json

TIMEOUT = None

Lib = "/home/rwalch/Work/Taceo/product_dev/demo-guessing-game/circuit/"
WinnerScript = "/home/rwalch/Work/Taceo/product_dev/demo-guessing-game/circuit/winner.circom"
CommitScript = "/home/rwalch/Work/Taceo/product_dev/demo-guessing-game/circuit/commit-and-check.circom"
Input = "input.json"
WitnessOut = "tmp_public_input_snarkjs.json"


def run_circom(circuit, input, lib, print_out=False):
    args = ["cargo", "run", "--bin", "bench-co-circom", "--release", "--", "--gen-wtns", "--gen-zkey", "--zkey", "key.out", "--circom", circuit, "--input", input, "--co-circom-bin", "target/release/co-circom", "-l", lib, "--keep-pub-inp"]

    try:
        process = Popen(args, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        output = process.communicate(timeout=TIMEOUT)[0].decode("utf-8")
        if (process.returncode != 0):
            print("  Process did not return 0")
            return None
    except Exception as ex:
        print("  Exception: " + str(ex))
        return None

    if print_out:
        print("  Output: " + output)

def gen_input_for_guess(guess, address, r, filename):
    input = {
        "guess": str(guess),
        "address": str(address),
        "r": str(r),
    }

    with open(filename, 'w') as f:
        json.dump(input, f)

def read_commitment(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    return data[0]

def gen_commitments(guesses, addresses, rs):
    assert(len(guesses) == len(addresses))
    assert(len(addresses) == len(rs))
    commitments = []

    for i in range(len(guesses)):
        gen_input_for_guess(guesses[i], addresses[i], rs[i], Input)
        run_circom(CommitScript, Input, Lib)
        commitment = read_commitment(WitnessOut)
        commitments.append(commitment)
    return commitments

def gen_input_for_winner(guesses, addresses, rs, commitments, filename):
    guesses_ = [str(guess) for guess in guesses]
    addresses_ = [str(address) for address in addresses]
    rs_ = [str(r) for r in rs]
    commitments_ = [str(commitment) for commitment in commitments]
    input = {
        "guesses": guesses_,
        "addresses": addresses_,
        "rs": rs_,
        "commitments": commitments_,
    }

    with open(filename, 'w') as f:
        json.dump(input, f)

def get_winner(guesses, addresses, rs, commitments):
    assert(len(guesses) == len(addresses))
    assert(len(addresses) == len(rs))
    assert(len(addresses) == len(commitments))

    gen_input_for_winner(guesses, addresses, rs, commitments, Input)

def simple_test():
    inputs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    addresses = [11234, 21234, 31234, 41234, 51234, 61234, 71234, 81234, 91234, 101234]
    rs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    commitments = [17660950052793789338846535647010310943115365052465965984594839884317189760558,
                   19419749357797242979307080512708369202649717601670852496817766911240828788005,
                   18187005881235717470120233611072721963014281029289607179986126362361378616695,
                   5507518149273522353615102086700760603100664989393552285706975605196257193127,
                   10966403894369504007711479599925189441285385767384073801636545675493706787019,
                   17901809754194165384322203103689575509367317728486928441055708960488198742884,
                   11074388361027330911358208526660020236590689655323424189983500685178235289210,
                   10970886821402655826975010425177590843887247523128210417681077350353809149055,
                   18500534457700787187656582364470295975618137149948757736173710668048658281625,
                   17022984694292426943119506844957968103043396951112418133670821897099510063346]
    # commitments = gen_commitments(inputs, addresses, rs)
    # print(commitments)

    get_winner(inputs, addresses, rs, commitments)

def main():
    simple_test()

if __name__ == "__main__":
    main()
