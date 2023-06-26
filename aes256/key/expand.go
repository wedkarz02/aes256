package key

import (
	"errors"

	"github.com/wedkarz02/aes256-go/aes256/consts"
)

type ExpandedKey [][]byte

func RotWord(word []byte) ([]byte, error) {
	if len(word) != consts.ROUND_KEY_WORD_SIZE {
		return nil, errors.New("invalid round key word size")
	}

	rotated := make([]byte, len(word))

	for i := 0; i < 3; i++ {
		rotated[i] = word[i+1]
	}

	rotated[3] = word[0]
	return rotated, nil
}

func ExpandEncKey(k []byte) (*ExpandedKey, error) {
	if len(k) != consts.KEY_SIZE {
		return nil, errors.New("invalid key size")
	}

	var xKey ExpandedKey
	xKey = append(xKey, k)
	xKey = append(xKey, []byte{})

	j := 0
	for i := 4; i < len(xKey[0])+1; i += 4 {
		tmp, err := RotWord(k[j:i])
		j += 4
		if err != nil {
			return nil, errors.New("invalid round key word size")
		}

		xKey[1] = append(xKey[1], tmp...)
	}

	return &xKey, nil
}
