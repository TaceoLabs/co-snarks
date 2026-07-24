pragma circom 2.0.0;

// factorial(n) -- circom functions can be recursive (per the front end's own docs,
// `mkdocs/docs/circom-language/functions.md`: "Functions can be recursive"). Every
// recursive level lowers to one `Instr::CallFn`, recursing into a fresh
// `circom_mpc_vm2::exec::Machine::run_function` activation via ordinary Rust call-stack
// depth.
function factorial(n) {
    if (n == 0) {
        return 1;
    }
    return n * factorial(n - 1);
}

template Factorial() {
    signal input n;
    signal output out;
    var f = factorial(n);
    out <-- f;
}

component main = Factorial();
