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

// Package consts defines constant values used by the AES implementation.
package consts

const (
	// Size of the AES block.
	BLOCK_SIZE = 16

	// Size of the AES key in the 256 bit variant.
	KEY_SIZE = 32

	// Size of the key segments used in key expansion.
	WORD_SIZE = 4

	// Number of words in the key.
	NK = 8

	// Number of AES rounds.
	NR = 14

	// Number of words in key expansion block.
	NB = 4

	// Number of derived keys needed.
	ROUND_KEYS = NR + 1

	// Total size of the expanded key.
	EXP_KEY_SIZE = BLOCK_SIZE * ROUND_KEYS

	// Size of the initializing vector.
	IV_SIZE = 16

	// Size of the number-used-once used in CTR modes.
	NONCE_SIZE = 12

	// Size of the counter used in CTR modes.
	COUNTER_SIZE = BLOCK_SIZE - NONCE_SIZE

	// Size of the GMAC tag.
	TAG_SIZE = 16
)
