package padding

import "github.com/wedkarz02/aes256go/src/consts"

type Pad func([]byte) []byte
type UnPad func([]byte) []byte

func ZeroPadding(data []byte) []byte {
	paddedData := make([]byte, len(data))
	copy(paddedData, data)

	remainder := len(paddedData) % consts.BLOCK_SIZE
	padLength := consts.BLOCK_SIZE - remainder

	for i := 0; i < padLength; i++ {
		paddedData = append(paddedData, 0x00)
	}

	return paddedData
}

func ZeroUnpadding(paddedData []byte) []byte {
	for paddedData[len(paddedData)-1] == 0x00 {
		paddedData = paddedData[:len(paddedData)-1]
	}

	data := make([]byte, len(paddedData))
	copy(data, paddedData)

	return data
}

func PKCS7Padding(data []byte) []byte {
	paddedData := make([]byte, len(data))
	copy(paddedData, data)

	remainder := len(paddedData) % consts.BLOCK_SIZE
	padLength := consts.BLOCK_SIZE - remainder

	for i := 0; i < padLength; i++ {
		paddedData = append(paddedData, byte(padLength))
	}

	return paddedData
}

func PKCS7Unpadding(paddedData []byte) []byte {
	padLength := paddedData[len(paddedData)-1]

	data := make([]byte, len(paddedData)-int(padLength))
	copy(data, paddedData[:len(paddedData)-int(padLength)])

	return data
}
