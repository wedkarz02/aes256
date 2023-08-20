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

// Package sbox implements AES lookup tables used in SubBytes step.
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
