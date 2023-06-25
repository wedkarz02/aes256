package aes256

import (
	"github.com/wedkarz02/aes256-go/aes256/sbox"
)

func NewSBox() *sbox.SBOX {
	return sbox.InitSBOX()
}
