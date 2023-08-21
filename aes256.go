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

// Package aes256go implements the Advanced Encryption Standard algorithm
// with many modes of operation granting AEAD encryption (Authenticated
// Encryption with Additional Data).
package aes256go

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/wedkarz02/aes256go/src/consts"
	"github.com/wedkarz02/aes256go/src/counter"
	g "github.com/wedkarz02/aes256go/src/galois"
	"github.com/wedkarz02/aes256go/src/key"
	"github.com/wedkarz02/aes256go/src/padding"
	"github.com/wedkarz02/aes256go/src/sbox"
)

// AES256 structure contains key and extended key data.
type AES256 struct {
	Key         []byte
	expandedKey *key.ExpandedKey
}

// NewAES256 initializes new AES cipher
// with the key hashed to the right size
// using SHA256
// and calculates round keys.
func NewAES256(k []byte) (*AES256, error) {
	hashedKey := newSHA256(k)

	if len(hashedKey) != consts.KEY_SIZE {
		return nil, errors.New("invalid key size")
	}

	a := AES256{Key: hashedKey}

	var err error
	a.expandedKey, err = a.newExpKey()

	if err != nil {
		return nil, err
	}

	return &a, nil
}

// ClearKey sets all bytes of Key and ExpandedKey to 0x00
// to make sure that they can't be retrieved from memory.
func (a *AES256) ClearKey() {
	for i := range a.Key {
		a.Key[i] = 0x00
	}

	for i := range a.expandedKey {
		a.expandedKey[i] = 0x00
	}
}

// NewSHA256 returns a hashed byte slice of the input.
// Used to make sure that the key is exactly 32 bytes.
//
// https://en.wikipedia.org/wiki/SHA-2
func newSHA256(k []byte) []byte {
	hash := sha256.New()
	hash.Write(k)
	return hash.Sum(nil)
}

// NewSBox returns a byte slice representation of
// the AES substitution look up table.
//
// https://en.wikipedia.org/wiki/Rijndael_S-box
func newSBox() *sbox.SBOX {
	return sbox.InitSBOX()
}

// NewInvSBox returns a byte slice representation of
// the AES inverse substitution look up table.
//
// https://en.wikipedia.org/wiki/Rijndael_S-box
func newInvSBox(sb *sbox.SBOX) *sbox.SBOX {
	return sbox.InitInvSBOX(sb)
}

// NewExpKey returns a key expanded by a key
// schedule to a slice of unique round keys.
//
// https://en.wikipedia.org/wiki/AES_key_schedule
//
// https://www.samiam.org/key-schedule.html
func (a *AES256) newExpKey() (*key.ExpandedKey, error) {
	xKey, err := key.ExpandKey(a.Key)

	if err != nil {
		return nil, err
	}

	return xKey, nil
}

// SubBytes returns a state with every
// byte replaced with it's corresponding
// byte from the sbox.
//
// https://pl.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) subBytes(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	var subState []byte

	sbox := newSBox()
	for i := range state {
		subState = append(subState, sbox[state[i]])
	}

	return subState, nil
}

// InvSubBytes undoes the SubBytes operation
// allowing decryption.
//
// https://pl.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) invSubBytes(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	var invSubState []byte

	invsbox := newInvSBox(newSBox())
	for i := range state {
		invSubState = append(invSubState, invsbox[state[i]])
	}

	return invSubState, nil
}

// ShiftRows returns a state where the last three
// rows has been transposed in an AES specific way.
//
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) shiftRows(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	shiftedState := make([]byte, len(state))
	copy(shiftedState, state)

	for i := 1; i < 4; i++ {
		j := i

		shiftedState[i+(4*0)] = state[i+4*((j+0)%4)]
		shiftedState[i+(4*1)] = state[i+4*((j+1)%4)]
		shiftedState[i+(4*2)] = state[i+4*((j+2)%4)]
		shiftedState[i+(4*3)] = state[i+4*((j+3)%4)]
	}

	return shiftedState, nil
}

// InvShiftRows undoes the ShiftRows operation
// allowing decryption.
//
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) invShiftRows(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	invShiftedState := make([]byte, len(state))
	copy(invShiftedState, state)

	for i := 1; i < 4; i++ {
		j := 4 - i
		invShiftedState[i+(4*0)] = state[i+4*((j+0)%4)]
		invShiftedState[i+(4*1)] = state[i+4*((j+1)%4)]
		invShiftedState[i+(4*2)] = state[i+4*((j+2)%4)]
		invShiftedState[i+(4*3)] = state[i+4*((j+3)%4)]
	}

	return invShiftedState, nil
}

// MixColumns performs a matrix multiplication
// inside Galois Finite Field (GF(2^8)).
// Used with ShiftRows in order to create diffusion.
//
// https://en.wikipedia.org/wiki/Rijndael_MixColumns
func (a *AES256) mixColumns(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	mixed := make([]byte, len(state))
	copy(mixed, state)

	for i := 0; i < 4; i++ {
		mixed[4*i+0] = g.Gmul(0x02, state[4*i+0]) ^ g.Gmul(0x03, state[4*i+1]) ^ state[4*i+2] ^ state[4*i+3]
		mixed[4*i+1] = state[4*i+0] ^ g.Gmul(0x02, state[4*i+1]) ^ g.Gmul(0x03, state[4*i+2]) ^ state[4*i+3]
		mixed[4*i+2] = state[4*i+0] ^ state[4*i+1] ^ g.Gmul(0x02, state[4*i+2]) ^ g.Gmul(0x03, state[4*i+3])
		mixed[4*i+3] = g.Gmul(0x03, state[4*i+0]) ^ state[4*i+1] ^ state[4*i+2] ^ g.Gmul(0x02, state[4*i+3])
	}

	return mixed, nil
}

// InvMixColumns undoes the MixColumns operation
// allowing decryption.
//
// https://en.wikipedia.org/wiki/Rijndael_MixColumns
func (a *AES256) invMixColumns(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	invMixed := make([]byte, len(state))
	copy(invMixed, state)

	for i := 0; i < 4; i++ {
		invMixed[4*i+0] = g.Gmul(0x0e, state[4*i+0]) ^ g.Gmul(0x0b, state[4*i+1]) ^ g.Gmul(0x0d, state[4*i+2]) ^ g.Gmul(0x09, state[4*i+3])
		invMixed[4*i+1] = g.Gmul(0x09, state[4*i+0]) ^ g.Gmul(0x0e, state[4*i+1]) ^ g.Gmul(0x0b, state[4*i+2]) ^ g.Gmul(0x0d, state[4*i+3])
		invMixed[4*i+2] = g.Gmul(0x0d, state[4*i+0]) ^ g.Gmul(0x09, state[4*i+1]) ^ g.Gmul(0x0e, state[4*i+2]) ^ g.Gmul(0x0b, state[4*i+3])
		invMixed[4*i+3] = g.Gmul(0x0b, state[4*i+0]) ^ g.Gmul(0x0d, state[4*i+1]) ^ g.Gmul(0x09, state[4*i+2]) ^ g.Gmul(0x0e, state[4*i+3])
	}

	return invMixed, nil
}

// AddRoundKey performs a round key byte addition
// inside Galois Finite Field (GF(2^8))
// for each round of encryption/decryption.
//
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) addRoundKey(state []byte, roundIdx int) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	if roundIdx > consts.NR {
		return nil, errors.New("round index out of range")
	}

	roundKey := a.expandedKey[roundIdx*consts.BLOCK_SIZE : (roundIdx+1)*consts.BLOCK_SIZE]

	newState := make([]byte, len(state))
	copy(newState, state)

	for i, b := range state {
		newState[i] = g.Gadd(b, roundKey[i])
	}

	return newState, nil
}

// EncryptBlock performs 256 bit AES encryption
// of one 16 byte block.
//
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) EncryptBlock(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	var err error
	cipherText := make([]byte, len(state))
	copy(cipherText, state)

	cipherText, err = a.addRoundKey(cipherText, 0)
	if err != nil {
		return nil, err
	}

	for roundIdx := 1; roundIdx < consts.NR; roundIdx++ {
		cipherText, err = a.subBytes(cipherText)
		if err != nil {
			return nil, err
		}

		cipherText, err = a.shiftRows(cipherText)
		if err != nil {
			return nil, err
		}

		cipherText, err = a.mixColumns(cipherText)
		if err != nil {
			return nil, err
		}

		cipherText, err = a.addRoundKey(cipherText, roundIdx)
		if err != nil {
			return nil, err
		}
	}

	cipherText, err = a.subBytes(cipherText)
	if err != nil {
		return nil, err
	}

	cipherText, err = a.shiftRows(cipherText)
	if err != nil {
		return nil, err
	}

	cipherText, err = a.addRoundKey(cipherText, consts.NR)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

// DecryptBlock performs 256 bit AES decryption
// of one 16 byte block.
//
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) DecryptBlock(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	var err error
	plainText := make([]byte, len(state))
	copy(plainText, state)

	plainText, err = a.addRoundKey(plainText, consts.NR)
	if err != nil {
		return nil, err
	}

	for roundIdx := consts.NR - 1; roundIdx > 0; roundIdx-- {
		plainText, err = a.invShiftRows(plainText)
		if err != nil {
			return nil, err
		}

		plainText, err = a.invSubBytes(plainText)
		if err != nil {
			return nil, err
		}

		plainText, err = a.addRoundKey(plainText, roundIdx)
		if err != nil {
			return nil, err
		}

		plainText, err = a.invMixColumns(plainText)
		if err != nil {
			return nil, err
		}
	}

	plainText, err = a.invShiftRows(plainText)
	if err != nil {
		return nil, err
	}

	plainText, err = a.invSubBytes(plainText)
	if err != nil {
		return nil, err
	}

	plainText, err = a.addRoundKey(plainText, 0)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Data encryption using ECB mode.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
func (a *AES256) EncryptECB(plainText []byte, pad padding.Pad) ([]byte, error) {
	paddedPlain := pad(plainText)
	var cipherText []byte

	for i := 0; i < len(paddedPlain); i += consts.BLOCK_SIZE {
		encBlock, err := a.EncryptBlock(paddedPlain[i : i+consts.BLOCK_SIZE])

		if err != nil {
			return nil, err
		}

		cipherText = append(cipherText, encBlock...)
	}

	return cipherText, nil
}

// Data decryption using ECB mode.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
func (a *AES256) DecryptECB(cipherText []byte, unpad padding.UnPad) ([]byte, error) {
	var paddedPlain []byte

	for i := 0; i < len(cipherText); i += consts.BLOCK_SIZE {
		decBlock, err := a.DecryptBlock(cipherText[i : i+consts.BLOCK_SIZE])

		if err != nil {
			return nil, err
		}

		paddedPlain = append(paddedPlain, decBlock...)
	}

	plainText := unpad(paddedPlain)
	return plainText, nil
}

// Data encryption using CBC mode.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
func (a *AES256) EncryptCBC(plainText []byte, pad padding.Pad) ([]byte, error) {
	paddedPlain := pad(plainText)
	var cipherText []byte

	iv := make([]byte, consts.IV_SIZE)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("iv initialization failed")
	}

	cipherText = append(cipherText, iv...)

	for i := 0; i < len(paddedPlain); i += consts.BLOCK_SIZE {
		maskedBlock := g.GxorBlocks(paddedPlain[i:i+consts.BLOCK_SIZE], iv)
		encBlock, err := a.EncryptBlock(maskedBlock)

		if err != nil {
			return nil, err
		}

		cipherText = append(cipherText, encBlock...)
		copy(iv, encBlock)
	}

	return cipherText, nil
}

// Data decryption using CBC mode.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
func (a *AES256) DecryptCBC(cipherText []byte, unpad padding.UnPad) ([]byte, error) {
	iv := cipherText[:consts.IV_SIZE]
	var strippedCipher []byte
	var paddedPlain []byte

	strippedCipher = append(strippedCipher, cipherText[consts.IV_SIZE:]...)

	for i := 0; i < len(strippedCipher); i += consts.BLOCK_SIZE {
		decBlock, err := a.DecryptBlock(strippedCipher[i : i+consts.BLOCK_SIZE])

		if err != nil {
			return nil, err
		}

		decBlock = g.GxorBlocks(decBlock, iv)
		copy(iv, strippedCipher[i:i+consts.BLOCK_SIZE])

		paddedPlain = append(paddedPlain, decBlock...)
	}

	plainText := unpad(paddedPlain)
	return plainText, nil
}

// Data encryption using CFB mode.
//
// 1 <= s <= 16 (block size)
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
func (a *AES256) EncryptCFB(plainText []byte, s int) ([]byte, error) {
	if s < 1 || s > consts.BLOCK_SIZE {
		return nil, errors.New("invalid segment size")
	}

	iv := make([]byte, consts.IV_SIZE)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("iv initialization failed")
	}

	initialIV := make([]byte, len(iv))
	copy(initialIV, iv)

	var cipherText []byte
	var i int

	for i = 0; i < len(plainText)-s; i += s {
		encIV, err := a.EncryptBlock(iv)

		if err != nil {
			return nil, err
		}

		streamBlock := encIV[:s]
		cipherBlock := g.GxorBlocks(plainText[i:i+s], streamBlock)
		cipherText = append(cipherText, cipherBlock...)

		shiftReg := append(iv[s:], cipherBlock...)
		copy(iv, shiftReg)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastStreamBlock := lastEncIV[:s]
	lastCipherBlock := g.GxorBlocks(plainText[i:], lastStreamBlock)
	cipherText = append(cipherText, lastCipherBlock...)

	cipherText = append(initialIV, cipherText...)
	return cipherText, nil
}

// Data decryption using CFB mode.
//
// 1 <= s <= 16 (block size)
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)
func (a *AES256) DecryptCFB(cipherText []byte, s int) ([]byte, error) {
	if s < 1 || s > consts.BLOCK_SIZE {
		return nil, errors.New("invalid segment size")
	}

	iv := make([]byte, consts.IV_SIZE)
	copy(iv, cipherText[:consts.IV_SIZE])

	cipherText = cipherText[consts.IV_SIZE:]
	var plainText []byte
	var i int

	for i = 0; i < len(cipherText)-s; i += s {
		encIV, err := a.EncryptBlock(iv)

		if err != nil {
			return nil, err
		}

		streamBlock := encIV[:s]
		plainBlock := g.GxorBlocks(cipherText[i:i+s], streamBlock)
		plainText = append(plainText, plainBlock...)

		shiftReg := append(iv[s:], cipherText[i:i+s]...)
		copy(iv, shiftReg)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastStreamBlock := lastEncIV[:s]
	lastPlainBlock := g.GxorBlocks(cipherText[i:], lastStreamBlock)
	plainText = append(plainText, lastPlainBlock...)

	return plainText, nil
}

// Data encryption using OFB mode.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
func (a *AES256) EncryptOFB(plainText []byte) ([]byte, error) {
	iv := make([]byte, consts.IV_SIZE)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.New("iv initialization failed")
	}

	initialIV := make([]byte, len(iv))
	copy(initialIV, iv)

	var cipherText []byte
	var i int

	lastLen := len(plainText) % consts.BLOCK_SIZE

	for i = 0; i < len(plainText)-lastLen; i += consts.BLOCK_SIZE {
		encIV, err := a.EncryptBlock(iv)

		if err != nil {
			return nil, err
		}

		copy(iv, encIV)
		cipherBlock := g.GxorBlocks(plainText[i:i+consts.BLOCK_SIZE], encIV)
		cipherText = append(cipherText, cipherBlock...)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastCipherBlock := g.GxorBlocks(plainText[i:], lastEncIV[:lastLen])
	cipherText = append(cipherText, lastCipherBlock...)

	cipherText = append(initialIV, cipherText...)
	return cipherText, nil
}

// Data decryption using OFB mode.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
func (a *AES256) DecryptOFB(cipherText []byte) ([]byte, error) {
	iv := make([]byte, consts.IV_SIZE)
	copy(iv, cipherText[:consts.IV_SIZE])

	cipherText = cipherText[consts.IV_SIZE:]

	var plainText []byte
	var i int

	lastLen := len(cipherText) % consts.BLOCK_SIZE

	for i = 0; i < len(cipherText)-lastLen; i += consts.BLOCK_SIZE {
		encIV, err := a.EncryptBlock(iv)

		if err != nil {
			return nil, err
		}

		copy(iv, encIV)
		plainBlock := g.GxorBlocks(cipherText[i:i+consts.BLOCK_SIZE], encIV)
		plainText = append(plainText, plainBlock...)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastPlainBlock := g.GxorBlocks(cipherText[i:], lastEncIV[:lastLen])
	plainText = append(plainText, lastPlainBlock...)

	return plainText, nil
}

// Data encryption using CTR mode.
//
// Please keep in mind that the counter is a 32 bit number, therefore you can
// encrypt 2^32 blocks of data (roughly 68 gigabytes) before it resets. If you need to encrypt more
// data than that, split it to multiple chunks and run the function for each one.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
func (a *AES256) EncryptCTR(plainText []byte) ([]byte, error) {
	nonce := make([]byte, consts.NONCE_SIZE)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ctr := counter.NewCounter()
	cipherText, err := a.coreBlockCTR(plainText, nonce, ctr)

	if err != nil {
		return nil, err
	}

	cipherText = append(nonce, cipherText...)
	return cipherText, nil
}

// Data decryption using CTR mode.
//
// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
func (a *AES256) DecryptCTR(cipherText []byte) ([]byte, error) {
	nonce := make([]byte, consts.NONCE_SIZE)
	copy(nonce, cipherText[:consts.NONCE_SIZE])

	cipherText = cipherText[consts.NONCE_SIZE:]

	ctr := counter.NewCounter()
	plainText, err := a.coreBlockCTR(cipherText, nonce, ctr)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// CoreBlockCTR is used to encrypt/decrypt the data in counter modes (CTR and GCM).
func (a *AES256) coreBlockCTR(data []byte, nonce []byte, ctr *counter.Counter) ([]byte, error) {
	if len(nonce) != consts.NONCE_SIZE {
		return nil, errors.New("invalid nonce size")
	}

	if data == nil {
		return data, nil
	}

	var inputBlock []byte
	inputBlock = append(inputBlock, nonce...)
	inputBlock = append(inputBlock, ctr.Bytes[:]...)

	var outputData []byte
	var i int

	lastLen := len(data) % consts.BLOCK_SIZE

	for i = 0; i < len(data)-lastLen; i += consts.BLOCK_SIZE {
		encBlock, err := a.EncryptBlock(inputBlock)

		if err != nil {
			return nil, err
		}

		cipherBlock := g.GxorBlocks(data[i:i+consts.BLOCK_SIZE], encBlock)
		outputData = append(outputData, cipherBlock...)

		ctr.Increment()

		var incrementedBlock []byte
		incrementedBlock = append(incrementedBlock, nonce...)
		incrementedBlock = append(incrementedBlock, ctr.Bytes[:]...)

		copy(inputBlock, incrementedBlock)
	}

	lastEncBlock, err := a.EncryptBlock(inputBlock)

	if err != nil {
		return nil, err
	}

	lastCipherBlock := g.GxorBlocks(data[i:], lastEncBlock[:lastLen])
	outputData = append(outputData, lastCipherBlock...)

	return outputData, nil
}

// Data encryption and authentication using GCM mode. Nonce is prepended to the cipherText
// and the authentication tag is appended to the cipherText.
//
// Both plainText and authData will be authenticated, but only plainText is encrypted.
//
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
func (a *AES256) EncryptGCM(plainText []byte, authData []byte) ([]byte, error) {
	nonce := make([]byte, consts.NONCE_SIZE)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ctr := counter.NewCounter()
	ctr.Increment()

	cipherText, err := a.coreBlockCTR(plainText, nonce, ctr)

	if err != nil {
		return nil, err
	}

	tag, err := a.GMAC(cipherText, authData, nonce)

	if err != nil {
		return nil, err
	}

	cipherText = append(nonce, cipherText...)
	cipherText = append(cipherText, tag...)

	return cipherText, nil
}

// Data decryption and authentication using GCM mode. Nonce is prepended to the cipherText
// and the authentication tag is appended to the cipherText.
//
// Both cipherText and authData will be authenticated, but only cipherText is decrypted.
//
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
func (a *AES256) DecryptGCM(cipherText []byte, authData []byte) ([]byte, error) {
	nonce := make([]byte, consts.NONCE_SIZE)
	copy(nonce, cipherText[:consts.NONCE_SIZE])

	tag := make([]byte, consts.TAG_SIZE)
	copy(tag, cipherText[len(cipherText)-consts.TAG_SIZE:])

	cipherText = cipherText[consts.NONCE_SIZE : len(cipherText)-consts.TAG_SIZE]

	testTag, err := a.GMAC(cipherText, authData, nonce)

	if err != nil {
		return nil, err
	}

	if !bytes.Equal(tag, testTag) {
		return nil, errors.New("GCM authentication failed: Invalid authentication tag")
	}

	ctr := counter.NewCounter()
	ctr.Increment()

	plainText, err := a.coreBlockCTR(cipherText, nonce, ctr)

	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// GMAC calculates a tag used to authenticate data during GCM encryption/decryption.
//
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
func (a *AES256) GMAC(cipherData []byte, authData []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != consts.NONCE_SIZE {
		return nil, errors.New("invalid nonce size")
	}

	hashSubKey := make([]byte, consts.BLOCK_SIZE)
	hashSubKey, err := a.EncryptBlock(hashSubKey)

	if err != nil {
		return nil, err
	}

	preCtr := counter.NewCounter()
	preCtr.Increment()

	cipherPadding := make([]byte, 16*int(math.Ceil(float64(8*len(cipherData))/128.0))-len(cipherData))
	authPadding := make([]byte, 16*int(math.Ceil(float64(8*len(authData))/128.0))-len(authData))

	lenC := make([]byte, 8)
	lenA := make([]byte, 8)
	binary.BigEndian.PutUint64(lenC, uint64(len(cipherData)))
	binary.BigEndian.PutUint64(lenA, uint64(len(authData)))

	paddedAuth := append(authData, authPadding...)
	paddedCipher := append(cipherData, cipherPadding...)
	totalLen := append(lenA, lenC...)
	hashData := append(append(paddedAuth, paddedCipher...), totalLen...)

	s := g.Ghash(hashData, hashSubKey)
	tag, err := a.coreBlockCTR(s, nonce, preCtr)

	if err != nil {
		return nil, err
	}

	return tag[:consts.TAG_SIZE], nil
}
