package galois

func Gadd(a byte, b byte) byte {
	return a ^ b
}

func Gsub(a byte, b byte) byte {
	return a ^ b
}

// private byte GMul(byte a, byte b) { // Galois Field (256) Multiplication of two Bytes
//     byte p = 0;

//     for (int counter = 0; counter < 8; counter++) {
//         if ((b & 1) != 0) {
//             p ^= a;
//         }

//         bool hi_bit_set = (a & 0x80) != 0;
//         a <<= 1;
//         if (hi_bit_set) {
//             a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
//         }
//         b >>= 1;
//     }

//     return p;
// }

func Gmul(a byte, b byte) byte {
	var p byte = 0

	for i := 0; i < 8; i++ {
		if b&1 != 0 {
			p ^= a
		}

		hiBitSet := a&0x80 != 0
		a <<= 1

		if hiBitSet {
			a ^= 0x1b
		}

		b >>= 1
	}

	return p
}
