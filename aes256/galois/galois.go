package galois

func Gadd(a byte, b byte) byte {
	return a ^ b
}

func Gsub(a byte, b byte) byte {
	return a ^ b
}

func Gmul(a byte, b byte) byte {
	var p byte = 0

	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			p ^= a
		}

		hiBit := a & 0x80
		a <<= 1

		if hiBit == 0x80 {
			a ^= 0x1b
		}

		b >>= 1
	}

	return p
}
