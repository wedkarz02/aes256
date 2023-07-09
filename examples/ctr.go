package examples

import (
	"log"

	"github.com/wedkarz02/aes256go"
)

// This is an example usage of CTR mode encryption.
func EncryptCTRExample(key []byte, plainText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText using CTR mode.
	cipherText, err := cipher.EncryptCTR(plainText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return cipherText
}

// This is an example usage of CTR mode decryption.
func DecryptCTRExample(key []byte, cipherText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText using CTR mode.
	plainText, err := cipher.DecryptCTR(cipherText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Decryption error: %v\n", err)
	}

	return plainText
}
