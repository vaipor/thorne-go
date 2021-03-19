package thorne

import (

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

)

func rsaGenerateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func rsaGetPublicKey(key *rsa.PrivateKey) *rsa.PublicKey {
	return key.Public().(*rsa.PublicKey)
}

func rsaParsePublicKey(publicKeyString string) (*rsa.PublicKey, error) {

	pubKeyBytes, e := base64.StdEncoding.DecodeString(publicKeyString)
	if e != nil {
		return nil, e
	}

	var parsedKey interface{}
	if parsedKey, e = x509.ParsePKCS1PublicKey(pubKeyBytes); e != nil {
		fmt.Printf("Not PKCS1 PublicKey: %s", e)
		// note this returns type `interface{}`
		if parsedKey, e = x509.ParsePKIXPublicKey(pubKeyBytes); e != nil {
			return nil, e
		}
	}

	var ok bool
	var publicKey *rsa.PublicKey
	publicKey, ok = parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Unable to parse RSA public key")
	}

	return publicKey, nil
}

func rsaDecrypt(key *rsa.PrivateKey, cipherString string) (string, error) {

	cipher, e := base64.StdEncoding.DecodeString(cipherString)
	if e != nil {
		return "", e
	}

	b, e := rsa.DecryptPKCS1v15(nil, key, cipher)
	if e != nil {
		return "", e
	}

	return string(b), nil
}

func rsaEncypt(key *rsa.PublicKey, plaintext string) (string, error) {

	b, e := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(plaintext))
	if e != nil {
		return "", e
	}

	return base64.StdEncoding.EncodeToString(b), nil
}