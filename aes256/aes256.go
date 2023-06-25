package aes256

import (
	"github.com/wedkarz02/aes256-go/aes256/key"
	"github.com/wedkarz02/aes256-go/aes256/sbox"
)

func NewSBox() *sbox.SBOX {
	return sbox.InitSBOX()
}

func InitExpandedKey(k []byte) (*key.ExpandedKey, error) {
	xKey, err := key.ExpandEncKey(k)

	if err != nil {
		return nil, err
	}

	return xKey, nil
}
