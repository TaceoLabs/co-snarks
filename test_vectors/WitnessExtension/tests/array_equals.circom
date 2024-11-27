pragma circom 2.0.0;

template Main() {
	signal input a[2];
	signal input b[2];

	a === b;
}

component main = Main();
