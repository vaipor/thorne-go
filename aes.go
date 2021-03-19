package thorne

import (

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log"

)

func GeneratePass() []byte {

	pass := make([]byte, 32)
	if _, e := io.ReadFull(rand.Reader, pass); e != nil {
		log.Printf("Failed to read from crypto/rand: %s", e)
		return nil
	}

	hash := sha256.Sum256(pass)
	return hash[:]
}

func Crypt(pass []byte, plaintext []byte) ([]byte, []byte, error) {

	//hash := sha256.Sum256(pass)
	block, e := aes.NewCipher(pass)
	if e != nil {
		log.Printf("Failed to create AES Cipher: %s", e)
		return nil, nil, e
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
		log.Printf("Failed to read from crypto/rand: %s", e)
		return nil, nil, e
	}

	aesgcm, e := cipher.NewGCM(block)
	if e != nil {
		log.Printf("Failed to create GCM Cipher: %s", e)
		return nil, nil, e
	}

	cipherBuf := aesgcm.Seal(nil, nonce, plaintext, nil)
	return cipherBuf, nonce, nil
}

func Decrypt(pass []byte, ciphertext []byte) ([]byte, error) {

	//hash := sha256.Sum256(pass)
	block, e := aes.NewCipher(pass)
	if e != nil {
		log.Printf("Failed to create AES Cipher: %s", e)
		return nil, e
	}

	aesgcm, e := cipher.NewGCM(block)
	if e != nil {
		log.Printf("Failed to create GCM Cipher: %s", e)
		return nil, e
	}

	plaintext, e := aesgcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if e != nil {
		log.Printf("Failed to open sealed text: %s", e)
		return nil, e
	}

	return plaintext, nil
}