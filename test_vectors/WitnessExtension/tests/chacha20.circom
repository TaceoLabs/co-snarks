pragma circom 2.0.0;

// Start of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./chacha20-bits.circom"

// Start of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./chacha-round.circom"

// Start of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./chacha-qr.circom"

// Start of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./generics-bits.circom"

/**
 * Add N bit numbers together
 * copied in from: https://github.com/iden3/circomlib/blob/master/circuits/binsum.circom
 * but rewritten slightly to reduce the final number of wires & labels
 * and possibly look at reducing the number of constraints
 */
template AddBits(BITS) {
    signal input a[BITS];
    signal input b[BITS];
    signal output out[BITS];
    signal carrybit;

    var lin = 0;
    var lout = 0;

    var k;
    var j = 0;

    var e2;

    // create e2 which
    // is the numerical sum of 2^k
    e2 = 1;
    for (k = BITS - 1; k >= 0; k--) {
        lin += (a[k] + b[k]) * e2;
        e2 *= 2;
    }

    e2 = 1;
    for (k = BITS - 1; k >= 0; k--) {
        out[k] <-- (lin >> j) & 1;
        // Ensure out is binary
        out[k] * (out[k] - 1) === 0;
        lout += out[k] * e2;
        e2 *= 2;
        j += 1;
    }

    carrybit <-- (lin >> j) & 1;
    // Ensure out is binary
    carrybit * (carrybit - 1) === 0;
    lout += carrybit * e2;

    // Ensure the sum matches
    lin === lout;
}

/**
 * Rotate left a BITS bit integer L bits
 */
template RotateLeftBits(BITS, L) {
	signal input in[BITS];
    signal output out[BITS];
    for (var i = 0; i < BITS; i++) {
        out[i] <== in[(i + L) % BITS];
    }
}

/**
 * XOR BITS-bit words
*/
template XorBits(BITS) {
	signal input a[BITS];
    signal input b[BITS];
    signal output out[BITS];
    
    for (var k=0; k<BITS; k++) {
        out[k] <== a[k] + b[k] - 2*a[k]*b[k];
    }
}
// End of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./generics-bits.circom"

/**
 * Perform ChaCha Quarter Round
 * Assume 4 words of 32 bits each
 * Each word must be little endian
 */
template QR(BITS_PER_WORD) {
	signal input in[4][BITS_PER_WORD];
	signal output out[4][BITS_PER_WORD];

	var tmp[4][BITS_PER_WORD] = in;

	// a += b
	component add1 = AddBits(BITS_PER_WORD);
	add1.a <== tmp[0];
	add1.b <== tmp[1];

	tmp[0] = add1.out;

	// d ^= a
	component xor1 = XorBits(BITS_PER_WORD);
	xor1.a <== tmp[3];
	xor1.b <== tmp[0];
	tmp[3] = xor1.out;

	// d = RotateLeft32BitsUnsafe(d, 16)
	component rot1 = RotateLeftBits(BITS_PER_WORD, 16);
	rot1.in <== tmp[3];
	tmp[3] = rot1.out;

	// c += d
	component add2 = AddBits(BITS_PER_WORD);
	add2.a <== tmp[2];
	add2.b <== tmp[3];
	tmp[2] = add2.out;

	// b ^= c
	component xor2 = XorBits(BITS_PER_WORD);
	xor2.a <== tmp[1];
	xor2.b <== tmp[2];
	tmp[1] = xor2.out;

	// b = RotateLeft32BitsUnsafe(b, 12)
	component rot2 = RotateLeftBits(BITS_PER_WORD, 12);
	rot2.in <== tmp[1];
	tmp[1] = rot2.out;
	
	// a += b
	component add3 = AddBits(BITS_PER_WORD);
	add3.a <== tmp[0];
	add3.b <== tmp[1];
	tmp[0] = add3.out;

	// d ^= a
	component xor3 = XorBits(BITS_PER_WORD);
	xor3.a <== tmp[3];
	xor3.b <== tmp[0];
	tmp[3] = xor3.out;

	// d = RotateLeft32BitsUnsafe(d, 8)
	component rot3 = RotateLeftBits(BITS_PER_WORD, 8);
	rot3.in <== tmp[3];
	tmp[3] = rot3.out;

	// c += d
	component add4 = AddBits(BITS_PER_WORD);
	add4.a <== tmp[2];
	add4.b <== tmp[3];
	tmp[2] = add4.out;

	// b ^= c
	component xor4 = XorBits(BITS_PER_WORD);
	xor4.a <== tmp[1];
	xor4.b <== tmp[2];
	tmp[1] = xor4.out;

	// b = RotateLeft32BitsUnsafe(b, 7)
	component rot4 = RotateLeftBits(BITS_PER_WORD, 7);
	rot4.in <== tmp[1];
	tmp[1] = rot4.out;

	out <== tmp;
}
// End of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./chacha-qr.circom"

template Round(BITS_PER_WORD) {
	// in => 16 32-bit words
	signal input in[16][BITS_PER_WORD];
	// out => 16 32-bit words
	signal output out[16][BITS_PER_WORD];

	var tmp[16][BITS_PER_WORD] = in;

	component rounds[10 * 8];
	component finalAdd[16];
	// i-th round
	var i = 0;
	// col loop counter
	var j = 0;
	// counter for the rounds array
	var k = 0;
	for(i = 0; i < 10; i++) {
		// columns of the matrix in a loop
		// 0, 4, 8, 12
		// 1, 5, 9, 13
		// 2, 6, 10, 14
		// 3, 7, 11, 15
		for(j = 0; j < 4; j++) {
			rounds[k] = QR(BITS_PER_WORD);
			rounds[k].in[0] <== tmp[j];
			rounds[k].in[1] <== tmp[j + 4];
			rounds[k].in[2] <== tmp[j + 8];
			rounds[k].in[3] <== tmp[j + 12];

			tmp[j] = rounds[k].out[0];
			tmp[j + 4] = rounds[k].out[1];
			tmp[j + 8] = rounds[k].out[2];
			tmp[j + 12] = rounds[k].out[3];

			k ++;
		}

		// 4 diagnals
		// 0, 5, 10, 15
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[0];
		rounds[k].in[1] <== tmp[5];
		rounds[k].in[2] <== tmp[10];
		rounds[k].in[3] <== tmp[15];

		tmp[0] = rounds[k].out[0];
		tmp[5] = rounds[k].out[1];
		tmp[10] = rounds[k].out[2];
		tmp[15] = rounds[k].out[3];

		k ++;

		// 1, 6, 11, 12
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[1];
		rounds[k].in[1] <== tmp[6];
		rounds[k].in[2] <== tmp[11];
		rounds[k].in[3] <== tmp[12];

		tmp[1] = rounds[k].out[0];
		tmp[6] = rounds[k].out[1];
		tmp[11] = rounds[k].out[2];
		tmp[12] = rounds[k].out[3];

		k ++;

		// 2, 7, 8, 13
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[2];
		rounds[k].in[1] <== tmp[7];
		rounds[k].in[2] <== tmp[8];
		rounds[k].in[3] <== tmp[13];

		tmp[2] = rounds[k].out[0];
		tmp[7] = rounds[k].out[1];
		tmp[8] = rounds[k].out[2];
		tmp[13] = rounds[k].out[3];

		k ++;

		// 3, 4, 9, 14
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[3];
		rounds[k].in[1] <== tmp[4];
		rounds[k].in[2] <== tmp[9];
		rounds[k].in[3] <== tmp[14];

		tmp[3] = rounds[k].out[0];
		tmp[4] = rounds[k].out[1];
		tmp[9] = rounds[k].out[2];
		tmp[14] = rounds[k].out[3];

		k ++;
	}

	// add the result to the input
	for(i = 0; i < 16; i++) {
		finalAdd[i] = AddBits(BITS_PER_WORD);
		finalAdd[i].a <== tmp[i];
		finalAdd[i].b <== in[i];
		tmp[i] = finalAdd[i].out;
	}

	out <== tmp;
}
// End of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./chacha-round.circom"

/** ChaCha20 in counter mode */
// BITS_PER_WORD = 32
template ChaCha20(N, BITS_PER_WORD) {
	// key => 8 32-bit words = 32 bytes
	signal input key[8][BITS_PER_WORD];
	// nonce => 3 32-bit words = 12 bytes
	signal input nonce[3][BITS_PER_WORD];
	// counter => 32-bit word to apply w nonce
	signal input counter[BITS_PER_WORD];
	// in => N 32-bit words => N 4 byte words
	signal input in[N][BITS_PER_WORD];
	// out => N 32-bit words => N 4 byte words
	signal output out[N][BITS_PER_WORD];

	var tmp[16][BITS_PER_WORD] = [
		[
			// 0x61707865
			0, 1, 1, 0, 0, 0, 0, 1, 0,
			1, 1, 1, 0, 0, 0, 0, 0, 1,
			1, 1, 1, 0, 0, 0, 0, 1, 1,
			0, 0, 1, 0, 1
		],
		[
			// 0x3320646e
			0, 0, 1, 1, 0, 0, 1, 1, 0,
			0, 1, 0, 0, 0, 0, 0, 0, 1,
			1, 0, 0, 1, 0, 0, 0, 1, 1,
			0, 1, 1, 1, 0
		],
		[
			// 0x79622d32
			0, 1, 1, 1, 1, 0, 0, 1, 0,
			1, 1, 0, 0, 0, 1, 0, 0, 0,
			1, 0, 1, 1, 0, 1, 0, 0, 1,
			1, 0, 0, 1, 0
		],
		[
			// 0x6b206574
			0, 1, 1, 0, 1, 0, 1, 1, 0,
			0, 1, 0, 0, 0, 0, 0, 0, 1,
			1, 0, 0, 1, 0, 1, 0, 1, 1,
			1, 0, 1, 0, 0
		],
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
		counter,
		nonce[0], nonce[1], nonce[2]
	];
	var i = 0;
	var j = 0;

	// do the ChaCha20 rounds
	component rounds[N/16];
	component xors[N];
	for(i = 0; i < N/16; i++) {
		rounds[i] = Round(BITS_PER_WORD);
		rounds[i].in <== tmp;
		// XOR block with input
		for(j = 0; j < 16; j++) {
			xors[i*16 + j] = XorBits(BITS_PER_WORD);
			xors[i*16 + j].a <== in[i*16 + j];
			xors[i*16 + j].b <== rounds[i].out[j];
			out[i*16 + j] <== xors[i*16 + j].out;
		}
		// increment the counter
		// TODO: we only use one block
		// at a time, so isn't required
		// tmp[12] = tmp[12] + 1;
	}
}
// End of inlined file: "../reclaim/zk-symmetric-crypto/circom/circuits/chacha20/./chacha20-bits.circom"

component main{public [in, nonce, counter]} = ChaCha20(16, 32);
