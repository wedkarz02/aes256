package examples

import (
	"log"

	"github.com/wedkarz02/aes256go"
	"github.com/wedkarz02/aes256go/src/padding"
)

// This is an example usage of CBC mode encryption.
func EncryptCBCExample(key []byte, plainText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Encrypting the plainText using CBC mode.
	// Padding can either be ZeroPadding or PKCS7Padding.
	cipherText, err := cipher.EncryptCBC(plainText, padding.PKCS7Padding)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Encryption error: %v\n", err)
	}

	return cipherText
}

// This is an example usage of CBC mode decryption.
func DecryptCBCExample(key []byte, cipherText []byte) []byte {

	// Cipher object initialization.
	cipher, err := aes256go.NewAES256(key)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Cipher init error: %v\n", err)
	}

	// Decrypting the cipherText using CBC mode.
	// Padding can either be ZeroPadding or PKCS7Padding.
	// Make sure that the padding is the same for encryption and decryption.
	plainText, err := cipher.DecryptCBC(cipherText, padding.PKCS7Unpadding)

	// Make sure to check for any errors.
	if err != nil {
		log.Fatalf("Decryption error: %v\n", err)
	}

	return plainText
}
