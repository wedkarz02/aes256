package aes256go

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/wedkarz02/aes256go/src/consts"
	"github.com/wedkarz02/aes256go/src/counter"
	g "github.com/wedkarz02/aes256go/src/galois"
	"github.com/wedkarz02/aes256go/src/key"
	"github.com/wedkarz02/aes256go/src/padding"
	"github.com/wedkarz02/aes256go/src/sbox"
)

type AES256 struct {
	Key         []byte
	ExpandedKey *key.ExpandedKey
}

// NewAES256 initializes new AES cipher
// with the key hashed to the right size
// using SHA256
// and calculates round keys.
func NewAES256(k []byte) (*AES256, error) {
	hashedKey := NewSHA256(k)

	if len(hashedKey) != consts.KEY_SIZE {
		return nil, errors.New("invalid key size")
	}

	a := AES256{Key: hashedKey}

	var err error
	a.ExpandedKey, err = a.NewExpKey()

	if err != nil {
		return nil, err
	}

	return &a, nil
}

// NewSHA256 returns a hashed byte slice of the input.
// Used to make sure that the key is exactly 32 bytes.
//
// https://en.wikipedia.org/wiki/SHA-2
func NewSHA256(k []byte) []byte {
	hash := sha256.New()
	hash.Write(k)
	return hash.Sum(nil)
}

// NewSBox returns a byte slice representation of
// the AES substitution look up table.
//
// https://en.wikipedia.org/wiki/Rijndael_S-box
func NewSBox() *sbox.SBOX {
	return sbox.InitSBOX()
}

// NewInvSBox returns a byte slice representation of
// the AES inverse substitution look up table.
//
// https://en.wikipedia.org/wiki/Rijndael_S-box
func NewInvSBox(sb *sbox.SBOX) *sbox.SBOX {
	return sbox.InitInvSBOX(sb)
}

// NewExpKey returns a key expanded by a key
// schedule to a slice of unique round keys.
//
// https://en.wikipedia.org/wiki/AES_key_schedule
//
// https://www.samiam.org/key-schedule.html
func (a *AES256) NewExpKey() (*key.ExpandedKey, error) {
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
func (a *AES256) SubBytes(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	var subState []byte

	sbox := NewSBox()
	for i := range state {
		subState = append(subState, sbox[state[i]])
	}

	return subState, nil
}

// InvSubBytes undoes the SubBytes operation
// allowing decryption.
//
// https://pl.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) InvSubBytes(state []byte) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	var invSubState []byte

	invsbox := NewInvSBox(NewSBox())
	for i := range state {
		invSubState = append(invSubState, invsbox[state[i]])
	}

	return invSubState, nil
}

// ShiftRows returns a state where the last three
// rows has been transposed in an AES specific way.
//
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
func (a *AES256) ShiftRows(state []byte) ([]byte, error) {
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
func (a *AES256) InvShiftRows(state []byte) ([]byte, error) {
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
func (a *AES256) MixColumns(state []byte) ([]byte, error) {
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
func (a *AES256) InvMixColumns(state []byte) ([]byte, error) {
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
func (a *AES256) AddRoundKey(state []byte, roundIdx int) ([]byte, error) {
	if len(state) != consts.BLOCK_SIZE {
		return nil, errors.New("state size not matching the block size")
	}

	if roundIdx > consts.NR {
		return nil, errors.New("round index out of range")
	}

	roundKey := a.ExpandedKey[roundIdx*consts.BLOCK_SIZE : (roundIdx+1)*consts.BLOCK_SIZE]

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

	cipherText, err = a.AddRoundKey(cipherText, 0)
	if err != nil {
		return nil, err
	}

	for roundIdx := 1; roundIdx < consts.NR; roundIdx++ {
		cipherText, err = a.SubBytes(cipherText)
		if err != nil {
			return nil, err
		}

		cipherText, err = a.ShiftRows(cipherText)
		if err != nil {
			return nil, err
		}

		cipherText, err = a.MixColumns(cipherText)
		if err != nil {
			return nil, err
		}

		cipherText, err = a.AddRoundKey(cipherText, roundIdx)
		if err != nil {
			return nil, err
		}
	}

	cipherText, err = a.SubBytes(cipherText)
	if err != nil {
		return nil, err
	}

	cipherText, err = a.ShiftRows(cipherText)
	if err != nil {
		return nil, err
	}

	cipherText, err = a.AddRoundKey(cipherText, consts.NR)
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

	plainText, err = a.AddRoundKey(plainText, consts.NR)
	if err != nil {
		return nil, err
	}

	for roundIdx := consts.NR - 1; roundIdx > 0; roundIdx-- {
		plainText, err = a.InvShiftRows(plainText)
		if err != nil {
			return nil, err
		}

		plainText, err = a.InvSubBytes(plainText)
		if err != nil {
			return nil, err
		}

		plainText, err = a.AddRoundKey(plainText, roundIdx)
		if err != nil {
			return nil, err
		}

		plainText, err = a.InvMixColumns(plainText)
		if err != nil {
			return nil, err
		}
	}

	plainText, err = a.InvShiftRows(plainText)
	if err != nil {
		return nil, err
	}

	plainText, err = a.InvSubBytes(plainText)
	if err != nil {
		return nil, err
	}

	plainText, err = a.AddRoundKey(plainText, 0)
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
		maskedBlock := g.GXorBlock(paddedPlain[i:i+consts.BLOCK_SIZE], iv)
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

		decBlock = g.GXorBlock(decBlock, iv)
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
		cipherBlock := g.GXorBlock(plainText[i:i+s], streamBlock)
		cipherText = append(cipherText, cipherBlock...)

		shiftReg := append(iv[s:], cipherBlock...)
		copy(iv, shiftReg)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastStreamBlock := lastEncIV[:s]
	lastCipherBlock := g.GXorBlock(plainText[i:], lastStreamBlock)
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
		plainBlock := g.GXorBlock(cipherText[i:i+s], streamBlock)
		plainText = append(plainText, plainBlock...)

		shiftReg := append(iv[s:], cipherText[i:i+s]...)
		copy(iv, shiftReg)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastStreamBlock := lastEncIV[:s]
	lastPlainBlock := g.GXorBlock(cipherText[i:], lastStreamBlock)
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
		cipherBlock := g.GXorBlock(plainText[i:i+consts.BLOCK_SIZE], encIV)
		cipherText = append(cipherText, cipherBlock...)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastCipherBlock := g.GXorBlock(plainText[i:], lastEncIV[:lastLen])
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
		plainBlock := g.GXorBlock(cipherText[i:i+consts.BLOCK_SIZE], encIV)
		plainText = append(plainText, plainBlock...)
	}

	lastEncIV, err := a.EncryptBlock(iv)

	if err != nil {
		return nil, err
	}

	lastPlainBlock := g.GXorBlock(cipherText[i:], lastEncIV[:lastLen])
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

	var inputBlock []byte
	inputBlock = append(inputBlock, nonce...)
	inputBlock = append(inputBlock, ctr.Bytes[:]...)

	if len(inputBlock) != consts.BLOCK_SIZE {
		return nil, errors.New("input block seeding failed")
	}

	var cipherText []byte
	var i int

	lastLen := len(plainText) % consts.BLOCK_SIZE

	for i = 0; i < len(plainText)-lastLen; i += consts.BLOCK_SIZE {
		encBlock, err := a.EncryptBlock(inputBlock)

		if err != nil {
			return nil, err
		}

		cipherBlock := g.GXorBlock(plainText[i:i+consts.BLOCK_SIZE], encBlock)
		cipherText = append(cipherText, cipherBlock...)

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

	lastCipherBlock := g.GXorBlock(plainText[i:], lastEncBlock[:lastLen])
	cipherText = append(cipherText, lastCipherBlock...)

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

	var inputBlock []byte
	inputBlock = append(inputBlock, nonce...)
	inputBlock = append(inputBlock, ctr.Bytes[:]...)

	if len(inputBlock) != consts.BLOCK_SIZE {
		return nil, errors.New("input block seeding failed")
	}

	var plainText []byte
	var i int

	lastLen := len(cipherText) % consts.BLOCK_SIZE

	for i = 0; i < len(cipherText)-lastLen; i += consts.BLOCK_SIZE {
		encBlock, err := a.EncryptBlock(inputBlock)

		if err != nil {
			return nil, err
		}

		plainBlock := g.GXorBlock(cipherText[i:i+consts.BLOCK_SIZE], encBlock)
		plainText = append(plainText, plainBlock...)

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

	lastPlainBlock := g.GXorBlock(cipherText[i:], lastEncBlock[:lastLen])
	plainText = append(plainText, lastPlainBlock...)

	return plainText, nil
}

func (a *AES256) CoreBlockCTR(dataBlock []byte, nonce []byte, ctr *counter.Counter) ([]byte, error) {
	if len(dataBlock) != consts.BLOCK_SIZE {
		return nil, errors.New("invalid data block size")
	}

	if len(nonce) != consts.NONCE_SIZE {
		return nil, errors.New("invalid nonce size")
	}

	var inputBlock []byte
	inputBlock = append(inputBlock, nonce...)
	inputBlock = append(inputBlock, ctr.Bytes[:]...)

	streamBlock, err := a.EncryptBlock(inputBlock)

	if err != nil {
		return nil, err
	}

	outputBlock := g.GXorBlock(dataBlock, streamBlock)
	ctr.Increment()

	return outputBlock, nil
}

// TODO: Method scope.
//       Break CTR/OFB/CFB into many functions so that decryption can just call
//       encryption where possible -> less repeated code.
//       Examples for CTR and GCM.
