package aes256

import (
	"github.com/wedkarz02/aes256-go/aes256/key"
	"github.com/wedkarz02/aes256-go/aes256/sbox"
)

// NewSBox returns a byte slice representation of
// the AES substitution look up table.
func NewSBox() *sbox.SBOX {
	return sbox.InitSBOX()
}

// NewInvSBox returns a byte slice representation of
// the AES inverse substitution look up table.
func NewInvSBox(sb *sbox.SBOX) *sbox.SBOX {
	return sbox.InitInvSBOX(sb)
}

// NewEncKey returns an encryption key expanded by
// a key schedule to a slice of unique round keys
func NewEncKey(k []byte) (*key.ExpandedKey, error) {
	xKey, err := key.ExpandEncKey(k)

	if err != nil {
		return nil, err
	}

	return xKey, nil
}
