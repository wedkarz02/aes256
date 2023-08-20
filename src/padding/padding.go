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

// Big portion of this package has been heavily inspired by CrackedPoly's
// implementation.
//
// Copyright (c) 2021 CrackedPoly
// https://github.com/CrackedPoly/AES-go

// Package padding implemets padding functions needed in some AES
// modes of operation.
package padding

import "github.com/wedkarz02/aes256go/src/consts"

type Pad func([]byte) []byte
type UnPad func([]byte) []byte

func ZeroPadding(data []byte) []byte {
	paddedData := make([]byte, len(data))
	copy(paddedData, data)

	remainder := len(paddedData) % consts.BLOCK_SIZE
	padLength := consts.BLOCK_SIZE - remainder

	for i := 0; i < padLength; i++ {
		paddedData = append(paddedData, 0x00)
	}

	return paddedData
}

func ZeroUnpadding(paddedData []byte) []byte {
	for paddedData[len(paddedData)-1] == 0x00 {
		paddedData = paddedData[:len(paddedData)-1]
	}

	data := make([]byte, len(paddedData))
	copy(data, paddedData)

	return data
}

func PKCS7Padding(data []byte) []byte {
	paddedData := make([]byte, len(data))
	copy(paddedData, data)

	remainder := len(paddedData) % consts.BLOCK_SIZE
	padLength := consts.BLOCK_SIZE - remainder

	for i := 0; i < padLength; i++ {
		paddedData = append(paddedData, byte(padLength))
	}

	return paddedData
}

func PKCS7Unpadding(paddedData []byte) []byte {
	padLength := paddedData[len(paddedData)-1]

	data := make([]byte, len(paddedData)-int(padLength))
	copy(data, paddedData[:len(paddedData)-int(padLength)])

	return data
}
