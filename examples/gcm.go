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

// Package examples contains code guides and should not be imported.
package examples

import (
	"log"

	"github.com/wedkarz02/aes256go"
	"github.com/wedkarz02/aes256go/src/consts"
)

// This is an example usage of GCM mode encryption.
func EncryptGCMExample(key []byte, plainText []byte, authData []byte) ([]byte, []byte, []byte) {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText using GCM mode.
	// authData will bee authenticated but not encrypted.
	// authData can be nil.
	cipherText, err := cipher.EncryptGCM(plainText, authData)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	// If you need the nonce, it is prepended to the cipherText.
	nonce := cipherText[:consts.NONCE_SIZE]

	// If you need the tag, it is appended to the cipherText.
	tag := cipherText[len(cipherText)-consts.TAG_SIZE:]

	return cipherText, nonce, tag
}

// This is an example usage of GCM mode decryption.
func DecryptGCMExample(key []byte, cipherText []byte, authData []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText using GCM mode.
	// authData will bee authenticated but not decrypted.
	// authData can be nil.
	//
	// If the authentication fails, returned values are nil and an error message.
	plainText, err := cipher.DecryptGCM(cipherText, authData)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Decryption error: %v\n", err)
	}

	return plainText
}
