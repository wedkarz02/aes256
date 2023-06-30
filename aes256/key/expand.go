package key

import (
	"errors"

	"github.com/wedkarz02/aes256go/aes256/consts"
	"github.com/wedkarz02/aes256go/aes256/galois"
	"github.com/wedkarz02/aes256go/aes256/sbox"
)

type ExpandedKey [consts.EXP_KEY_SIZE]byte

func Rcon(idx byte) byte {
	if idx == 0 {
		return 0
	}

	var rcon byte = 1

	for idx != 1 {
		rcon = galois.Gmul(rcon, 2)
		idx--
	}

	return rcon
}

func RotWord(word [consts.WORD_SIZE]byte) ([consts.WORD_SIZE]byte, error) {
	if len(word) != consts.WORD_SIZE {
		return [consts.WORD_SIZE]byte{}, errors.New("invalid round key word size")
	}

	var rotated [consts.WORD_SIZE]byte

	for i := 0; i < consts.WORD_SIZE-1; i++ {
		rotated[i] = word[i+1]
	}

	rotated[consts.WORD_SIZE-1] = word[0]
	return rotated, nil
}

func SubWord(word [consts.WORD_SIZE]byte, sbox *sbox.SBOX) ([consts.WORD_SIZE]byte, error) {
	if len(word) != consts.WORD_SIZE {
		return [consts.WORD_SIZE]byte{}, errors.New("invalid round key word size")
	}

	var subw [consts.WORD_SIZE]byte

	for i := 0; i < consts.WORD_SIZE; i++ {
		subw[i] = sbox[word[i]]
	}

	return subw, nil
}

func ScheduleCore(word [consts.WORD_SIZE]byte, idx byte) ([consts.WORD_SIZE]byte, error) {
	if len(word) != consts.WORD_SIZE {
		return [consts.WORD_SIZE]byte{}, errors.New("invalid round key word size")
	}

	word, err := RotWord(word)

	if err != nil {
		return [consts.WORD_SIZE]byte{}, err
	}

	sbox := sbox.InitSBOX()
	word, err = SubWord(word, sbox)

	if err != nil {
		return [consts.WORD_SIZE]byte{}, err
	}

	word[0] ^= Rcon(idx)

	return word, nil
}

func ExpandKey(k []byte) (*ExpandedKey, error) {
	if len(k) != consts.KEY_SIZE {
		return nil, errors.New("invalid key size")
	}

	var xKey ExpandedKey
	copy(xKey[:], k)

	sbox := sbox.InitSBOX()
	var tmpKey [consts.WORD_SIZE]byte
	var c byte = consts.KEY_SIZE
	var idx byte = 1
	var a byte
	var err error

	for c < consts.EXP_KEY_SIZE {
		for a = 0; a < consts.WORD_SIZE; a++ {
			tmpKey[a] = xKey[a+c-consts.WORD_SIZE]
		}

		if c%consts.KEY_SIZE == 0 {
			tmpKey, err = ScheduleCore(tmpKey, idx)
			idx++

			if err != nil {
				return nil, err
			}
		}

		if c%consts.KEY_SIZE == consts.BLOCK_SIZE {
			tmpKey, err = SubWord(tmpKey, sbox)

			if err != nil {
				return nil, err
			}
		}

		for a = 0; a < consts.WORD_SIZE; a++ {
			xKey[c] = xKey[c-consts.KEY_SIZE] ^ tmpKey[a]
			c++
		}
	}

	return &xKey, nil
}
