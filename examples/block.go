package examples

import (
	"log"

	"github.com/wedkarz02/aes256go"
)

// This is an example usage of block encryption.
func EncryptBlockExample(key []byte, plainText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText block.
	cipherBlock, err := cipher.EncryptBlock(plainText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return cipherBlock
}

// This is an example usage of block decryption.
func DecryptBlockExample(key []byte, cipherText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText block.
	plainBlock, err := cipher.DecryptBlock(cipherText)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Decryption error: %v\n", err)
	}

	return plainBlock
}
