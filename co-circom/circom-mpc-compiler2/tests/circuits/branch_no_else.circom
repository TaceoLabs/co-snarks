pragma circom 2.0.0;

// The Task 6 "without else" milestone circuit for `codegen::stmt::lower_branch`: an `if`
// with no `else` at all — `BranchBucket::else_branch` is an empty `InstructionList`, not a
// synthesized empty block (a direct read of circom's own IR) — must compile to a
// `SharedIf`/`SharedEnd` pair with **no** `SharedElse` instruction anywhere in the
// program: the Rep3-round-saving elision the brief mandates (see `lower_branch`'s doc
// comment). `v` stays `0` (its declared initial value) whenever the condition is false,
// exactly as plain circom semantics require for an `if` with no `else`.
//
// `out <-- v` (witness-only), not `<==`: `v`'s value depends on a genuinely runtime/shared
// condition (`a < 5`, `a` a signal), so it isn't a concrete value the constraint generator
// can fold into a real constraint (T3001 otherwise) — see `branch_if_else.circom`'s own
// comment for the same reasoning applied to the branch body itself.
template BranchNoElse() {
    signal input a;
    signal output out;
    var v = 0;
    if (a < 5) {
        v = 100;
    }
    out <-- v;
}

component main = BranchNoElse();
