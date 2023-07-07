package examples

import (
	"log"

	"github.com/wedkarz02/aes256go"
)

// This is an example usage of OFB mode encryption.
func EncryptOFBExample(key []byte, plainText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText using OFB mode.
	cipherText, err := cipher.EncryptOFB(plainText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return cipherText
}

// This is an example usage of OFB mode decryption.
func DecryptOFBExample(key []byte, cipherText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText using OFB mode.
	plainText, err := cipher.DecryptOFB(cipherText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return plainText
}
