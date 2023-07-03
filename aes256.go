package aes256go

import (
	"errors"

	"github.com/wedkarz02/aes256go/src/consts"
	g "github.com/wedkarz02/aes256go/src/galois"
	"github.com/wedkarz02/aes256go/src/key"
	"github.com/wedkarz02/aes256go/src/padding"
	"github.com/wedkarz02/aes256go/src/sbox"
)

type AES256 struct {
	Key         [consts.KEY_SIZE]byte
	ExpandedKey *key.ExpandedKey
}

// NewAES256 initializes new AES cipher
// and calculates round keys.
func NewAES256(k []byte) (*AES256, error) {
	if len(k) != consts.KEY_SIZE {
		return nil, errors.New("invalid key size")
	}

	a := AES256{Key: [32]byte(k)}

	var err error
	a.ExpandedKey, err = a.NewExpKey()

	if err != nil {
		return nil, err
	}

	return &a, nil
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
	xKey, err := key.ExpandKey(a.Key[:])

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
