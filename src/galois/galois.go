// Copyright (c) 2023 Paweł Rybak
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package galois implements Galois Finite Field arithmetic used in AES.
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

func GxorBlocks(a []byte, b []byte) []byte {
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
		hash = GxorBlocks(x[i:i+consts.BLOCK_SIZE], hash)
		hash = GmulBlocks(hash, h)
	}

	return hash
}
