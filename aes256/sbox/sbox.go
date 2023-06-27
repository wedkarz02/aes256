package sbox

type SBOX [256]byte

func RotL8(x byte, shift byte) byte {
	return byte((x << shift) | (x >> (8 - shift)))
}

func InitSBOX() *SBOX {
	sbox := new(SBOX)

	var p byte = 1
	var q byte = 1

	for {
		if p&0x80 != 0 {
			p = p ^ (p << 1) ^ 0x1b
		} else {
			p = p ^ (p << 1)
		}

		q ^= q << 1
		q ^= q << 2
		q ^= q << 4

		if q&0x80 != 0 {
			q ^= 0x09
		}

		xformed := q ^ RotL8(q, (1)) ^ RotL8(q, 2) ^ RotL8(q, 3) ^ RotL8(q, 4)
		sbox[p] = xformed ^ 0x63

		if p == 1 {
			break
		}
	}

	sbox[0] = 0x63

	return sbox
}

func InitInvSBOX(sbox *SBOX) *SBOX {
	invsbox := new(SBOX)

	for i := 0; i < len(sbox); i++ {
		invsbox[sbox[i]] = byte(i)
	}

	return invsbox
}
