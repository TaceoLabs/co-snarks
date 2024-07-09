import argparse
import subprocess
import os
import sys 

        

def run_command(command, input_data=None):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if input_data is not None:
        input_data = input_data + "\n"
    stdout, stderr = process.communicate(input=input_data)
    
    if process.returncode == 0:
        print("Command succeeded")
        return True
    else:
        print("Command failed with return code", process.returncode)
        print("Error:")
        for line in stdout.splitlines():
            print(f"{line}")
        for line in stderr.splitlines():
            print(f"{line}")
        return False

def get_pot(size):
    print("===============================")
    snarkjs_link = f"https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_{size:02}.ptau";
    print(f"Downloading pot from {snarkjs_link}...")
    return run_command(["wget", snarkjs_link])

def create_zkey(size, name):
    print("===============================")
    print("Creating zkey (this can take some time)...")
    return run_command(["snarkjs", "groth16", "setup", f"{name}.r1cs", f"powersOfTau28_hez_final_{size:02}.ptau", f"{name}.0.zkey"])

def add_entropy(name):
    print("===============================")
    print("Type your entropy> ", end="", flush=True)
    entropy = sys.stdin.readline().strip()
    print("Adding entropy (this can take some time)...")
    return run_command(["snarkjs", "zkey", "contribute", f"{name}.0.zkey", f"{name}.zkey", "--name=\"1st Contributor Name\""], entropy)

def cleanup(size, name):
    print("===============================")
    print("Cleaning up...")
    run_command(["rm", f"powersOfTau28_hez_final_{size:02}.ptau", f"{name}.0.zkey"])



def main():
    parser = argparse.ArgumentParser(description="Performs a groth16 ceremony with snarkjs.")
    parser.add_argument('name', type=str, help="The name of the circuit (there must be a .r1cs file with this prefix)")
    parser.add_argument('size', type=int, help="The necessary size for the pot. (constraints * 2 < 2**size)")
    
    args = parser.parse_args()
    
    name = args.name
    size = args.size
    if size < 8 or size > 27:
        print("Size must be between 8 and 27")
        return
    if not os.path.exists(f"{name}.r1cs"):
        print(f"We cannot find {name}.r1cs")
        return

    
    get_pot(size)
    create_zkey(size, name);
    add_entropy(name);
    cleanup(size, name);


if __name__ == "__main__":
    main()
