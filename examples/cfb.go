package examples

import (
	"log"

	"github.com/wedkarz02/aes256go"
)

// This is an example usage of CBC mode encryption.
func EncryptCFBExample(key []byte, plainText []byte, segment int) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText using CFB mode.
	cipherText, err := cipher.EncryptCFB(plainText, segment)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return cipherText
}

// This is an example usage of CBC mode decryption.
func DecryptCFBExample(key []byte, cipherText []byte, segment int) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText using CFB mode.
	// Make sure that the segment is the same for encryption and decryption.
	plainText, err := cipher.DecryptCFB(cipherText, segment)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return plainText
}
