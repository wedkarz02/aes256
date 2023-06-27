package aes256

import (
	"errors"

	"github.com/wedkarz02/aes256-go/aes256/consts"
	"github.com/wedkarz02/aes256-go/aes256/key"
	"github.com/wedkarz02/aes256-go/aes256/sbox"
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
