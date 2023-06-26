package key

import (
	"errors"

	"github.com/wedkarz02/aes256-go/aes256/consts"
	"github.com/wedkarz02/aes256-go/aes256/sbox"
)

type ExpandedKey [consts.KEY_SIZE * consts.ROUND_KEYS_COUNT]byte

func Rcon(idx byte) []byte {
	rcon := []byte{0x02, 0x00, 0x00, 0x00}

	if idx == 1 {
		rcon[0] = 0x01
		return rcon
	}

	if idx > 1 {
		rcon[0] = 0x02
		idx--

		for idx > 1 {
			rcon[0] ^= 0x02
			idx--
		}
	}

	return rcon
}

func RotWord(word [consts.ROUND_KEY_WORD_SIZE]byte) ([consts.ROUND_KEY_WORD_SIZE]byte, error) {
	if len(word) != consts.ROUND_KEY_WORD_SIZE {
		return [consts.ROUND_KEY_WORD_SIZE]byte{}, errors.New("invalid round key word size")
	}

	var rotated [consts.ROUND_KEY_WORD_SIZE]byte

	for i := 0; i < consts.ROUND_KEY_WORD_SIZE-1; i++ {
		rotated[i] = word[i+1]
	}

	rotated[consts.ROUND_KEY_WORD_SIZE-1] = word[0]
	return rotated, nil
}

func SubWord(word [consts.ROUND_KEY_WORD_SIZE]byte, sbox *sbox.SBOX) ([consts.ROUND_KEY_WORD_SIZE]byte, error) {
	if len(word) != consts.ROUND_KEY_WORD_SIZE {
		return [consts.ROUND_KEY_WORD_SIZE]byte{}, errors.New("invalid round key word size")
	}

	var subw [consts.ROUND_KEY_WORD_SIZE]byte

	for i := 0; i < consts.ROUND_KEY_WORD_SIZE; i++ {
		subw[i] = sbox[word[i]]
	}

	return subw, nil
}

func ExpandKey(k []byte) (*ExpandedKey, error) {
	if len(k) != consts.KEY_SIZE {
		return nil, errors.New("invalid key size")
	}

	var xKey ExpandedKey
	var tmpKey [consts.ROUND_KEY_WORD_SIZE]byte
	var err error

	sbox := sbox.InitSBOX()

	for i := 0; i < consts.ROUND_KEY_WORD_COUNT; i++ {
		xKey[4*i+0] = k[4*i+0]
		xKey[4*i+1] = k[4*i+1]
		xKey[4*i+2] = k[4*i+2]
		xKey[4*i+3] = k[4*i+3]
	}

	byteLength := consts.ROUND_KEYS_COUNT * consts.ROUND_KEY_WORD_COUNT

	for i := consts.ROUND_KEY_WORD_COUNT; i < byteLength; i++ {
		tmpKey[0] = xKey[4*(i-1)+0]
		tmpKey[1] = xKey[4*(i-1)+1]
		tmpKey[2] = xKey[4*(i-1)+2]
		tmpKey[3] = xKey[4*(i-1)+3]

		if i%consts.ROUND_KEY_WORD_COUNT == 0 {
			tmpKey, err = RotWord(tmpKey)
			if err != nil {
				return nil, err
			}

			tmpKey, err = SubWord(tmpKey, sbox)
			if err != nil {
				return nil, err
			}

			rCon := Rcon(byte(i / consts.ROUND_KEY_WORD_COUNT))
			tmpKey[0] ^= rCon[0]
			tmpKey[1] ^= rCon[1]
			tmpKey[2] ^= rCon[2]
			tmpKey[3] ^= rCon[3]
		} else if i%consts.ROUND_KEY_WORD_COUNT == 4 {
			tmpKey, err = SubWord(tmpKey, sbox)
			if err != nil {
				return nil, err
			}
		}

		xKey[4*i+0] = xKey[4*(i-consts.ROUND_KEY_WORD_COUNT)+0] ^ tmpKey[0]
		xKey[4*i+1] = xKey[4*(i-consts.ROUND_KEY_WORD_COUNT)+1] ^ tmpKey[1]
		xKey[4*i+2] = xKey[4*(i-consts.ROUND_KEY_WORD_COUNT)+2] ^ tmpKey[2]
		xKey[4*i+3] = xKey[4*(i-consts.ROUND_KEY_WORD_COUNT)+3] ^ tmpKey[3]
	}

	return &xKey, nil
}
