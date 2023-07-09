package galois

import "github.com/wedkarz02/aes256go/src/consts"

func Gadd(a byte, b byte) byte {
	return a ^ b
}

func Gsub(a byte, b byte) byte {
	return a ^ b
}

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

func GXorBlock(a []byte, b []byte) []byte {
	var result []byte

	for i, val := range a {
		result = append(result, Gadd(val, b[i]))
	}

	return result
}

func GmulBlocks(x []byte, y []byte) []byte {
	prod := make([]byte, consts.BLOCK_SIZE)

	for i := 0; i < 16; i++ {
		for j := 0; j < 8; j++ {
			if (y[i]>>uint(j))&1 == 1 {
				for k := 0; k < 16; k++ {
					prod[k] = Gadd(prod[k], x[(i+k)%16])
				}
			}
		}
	}

	return prod
}

func Ghash(x []byte, h []byte) []byte {
	hash := make([]byte, consts.BLOCK_SIZE)

	for i := 0; i < len(x); i += consts.BLOCK_SIZE {
		hash = GXorBlock(x[i:i+consts.BLOCK_SIZE], hash)
		hash = GmulBlocks(hash, h)
	}

	return hash
}
