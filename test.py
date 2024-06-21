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


def run_circom(circuit, input, lib, key, print_out=False):
    args = ["cargo", "run", "--bin", "bench-co-circom", "--release", "--", "--gen-wtns", "--gen-zkey", "--zkey", key, "--circom", circuit, "--input", input, "--co-circom-bin", "target/release/co-circom", "-l", lib, "--keep-pub-inp"]

    try:
        process = Popen(args, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        output = process.communicate(timeout=TIMEOUT)[0].decode("utf-8")
        if (process.returncode != 0):
            print("  Process did not return 0")
            if print_out:
                print("  Output: " + output)
            return None
    except Exception as ex:
        print("  Exception: " + str(ex))
        if print_out:
            print("  Output: " + output)
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
        run_circom(CommitScript, Input, Lib, "key_commitment.out")
        commitment = read_commitment(WitnessOut)
        commitments.append(commitment)
    return commitments

def gen_input_for_winner(guesses, addresses, rs, commitments, filename):
    guesses_ = [str(guess) for guess in guesses]
    addresses_ = [str(address) for address in addresses]
    rs_ = [str(r) for r in rs]
    commitments_ = [str(commitment) for commitment in commitments]
    input = {
        "inp_guess": guesses_,
        "inp_address": addresses_,
        "inp_r": rs_,
        "commitments": commitments_,
    }

    with open(filename, 'w') as f:
        json.dump(input, f)

def read_winner(filename):
    with open(filename, 'r') as f:
        data = json.load(f)
    return (data[0], data[1])

def get_winner(guesses, addresses, rs, commitments):
    assert(len(guesses) == len(addresses))
    assert(len(addresses) == len(rs))
    assert(len(addresses) == len(commitments))

    gen_input_for_winner(guesses, addresses, rs, commitments, Input)
    run_circom(WinnerScript, Input, Lib, "key_winner.out", True)
    (guess, address) = read_winner(WitnessOut)
    return (int(guess), int(address))

def simple_test():
    print("Running simple test")
    winner_guess = 10
    winner_address = 51234
    inputs = [1, 2, 3, 4, 10, 5, 6, 7, 8, 9]
    addresses = [11234, 21234, 31234, 41234, 51234, 61234, 71234, 81234, 91234, 101234]
    rs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    commitments = [17660950052793789338846535647010310943115365052465965984594839884317189760558,
                   19419749357797242979307080512708369202649717601670852496817766911240828788005,
                   18187005881235717470120233611072721963014281029289607179986126362361378616695,
                   5507518149273522353615102086700760603100664989393552285706975605196257193127,
                   2475690448749226027322145421948391845501550161241100289484830552342021324457,
                   11279421452133669707663404530446531535895317345396688475536010999548572301117,
                   1157021152856309157132391607263393053996185945062524241107223218932391113942,
                   9594722210078747211981377172396306455177959150910585877486460212074081068915,
                   16742472601479666432793333983477806361361931201809389920935457334537528163106,
                   17038158294209681557027224212349614200810543668638889833635182636398763090088]
    # commitments = gen_commitments(inputs, addresses, rs)
    # print(commitments)

    (guess, address) = get_winner(inputs, addresses, rs, commitments)
    print("  Guess: " + str(guess))
    print("  Address: " + str(address))
    if guess == winner_guess and address == winner_address:
        print("  Test passed\n")
    else:
        print("  Test failed\n")

def duplicate_test():
    print("Running duplicate test")
    winner_guess = 7
    winner_address = 21234
    inputs = [10, 7, 10, 10, 5, 5, 5, 5, 10, 10]
    addresses = [11234, 21234, 31234, 41234, 51234, 61234, 71234, 81234, 91234, 101234]
    rs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    commitments = [786444130315058214928863960319583990748806750640493686922585198472607207614,
                   4571057433704097393757436162012609404061671305691068339995526451122230408365,
                   6309268307675882796512860634140437709170530010322894909456385848007670782411,
                   1346635485676904118812477054879350024240621816238802994155898474929308610196,
                   10966403894369504007711479599925189441285385767384073801636545675493706787019,
                   11279421452133669707663404530446531535895317345396688475536010999548572301117,
                   3683580278739243152152564371577148370794832649779680213061357783998508787334,
                   5955993173339637070131199730729724080837523205832528831417575792944644566786,
                   1183877823059998751292840941179186587854254206049679077630262313761360967777,
                   17022984694292426943119506844957968103043396951112418133670821897099510063346]
    # commitments = gen_commitments(inputs, addresses, rs)
    # print(commitments)

    (guess, address) = get_winner(inputs, addresses, rs, commitments)
    print("  Guess: " + str(guess))
    print("  Address: " + str(address))
    if guess == winner_guess and address == winner_address:
        print("  Test passed\n")
    else:
        print("  Test failed\n")

def default_test():
    print("Running default test")
    winner_guess = 0
    winner_address = 0
    inputs = [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]
    addresses = [11234, 21234, 31234, 41234, 51234, 61234, 71234, 81234, 91234, 101234]
    rs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    commitments = [786444130315058214928863960319583990748806750640493686922585198472607207614,
                   4295304222364290685602906131057339403195343195346346411529470378045508591025,
                   6309268307675882796512860634140437709170530010322894909456385848007670782411,
                   1346635485676904118812477054879350024240621816238802994155898474929308610196,
                   2475690448749226027322145421948391845501550161241100289484830552342021324457,
                   19650604491865341696366854179891984182302468693611940364889797724610406653328,
                   11189930006062851703999264387452473310044676912124310781669161714516089587189,
                   14262605079078306440468811175317193553861610045968884767713615855226745988648,
                   1183877823059998751292840941179186587854254206049679077630262313761360967777,
                   17022984694292426943119506844957968103043396951112418133670821897099510063346]
    # commitments = gen_commitments(inputs, addresses, rs)
    # print(commitments)

    (guess, address) = get_winner(inputs, addresses, rs, commitments)
    print("  Guess: " + str(guess))
    print("  Address: " + str(address))
    if guess == winner_guess and address == winner_address:
        print("  Test passed\n")
    else:
        print("  Test failed\n")

def main():
    simple_test()
    duplicate_test()
    default_test()

if __name__ == "__main__":
    main()
