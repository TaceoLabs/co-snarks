# Know Your Customer (KYC)

A classic example of ZK proofing involves verifying a user's age to a
third-party without disclosing their birthdate. This scenario is crucial in the
financial industry, where banks need to confirm that a customer is over 18 years
old without accessing their exact birthdate. Additionally, compliance might
require verifying that the user is not from a blacklisted country.

We provide a
[simple circuit](https://github.com/TaceoLabs/collaborative-circom/blob/main/co-circom/examples/test_vectors/kyc/circuit.circom)
to demonstrate this use case:

```c++
pragma circom 2.0.0;

include "lib/comparators.circom";

template Kyc(t) {
  signal input blacklist[t];
  signal input country;
  signal input min_age;
  signal input age;

  component blacklist_checks[t];

  for (var i = 0;i<t;i++) {
    blacklist_checks[i] = IsZero();
    blacklist_checks[i].in <== country - blacklist[i];
    blacklist_checks[i].out === 0;
  }

  component geq = GreaterEqThan(8);
  geq.in[0] <== age;
  geq.in[1] <== min_age;
  geq.out === 1;
}

component main {public [blacklist, min_age]} = Kyc(3);
```

In this circuit, we define two public inputs: a numerical blacklist of countries
and a minimum age requirement. The private inputs are the user's age and
country. The circuit evaluates whether the user's country is not blacklisted and
if the user's age meets or exceeds the specified minimum.

To run this example, simply execute:

```bash
sh run_full_kyc.sh
```
