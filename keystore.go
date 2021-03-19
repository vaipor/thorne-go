package thorne

import (

	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"

)

var DEFAULT_KEYSTORE_LOCATION = ""

const (

	SK_STATUS_PENDING				= iota
	SK_STATUS_READY

)

type Connection struct {

	Background 							string
	Direct 									bool
	Email 									string
	Headline 								string
	Image 									string
	Name 										string
	Phone 									string
	UUID 										string

}

type ProfileStore struct {

	Profile
	Image 									string
	Background 							string

}

type SharedKey struct {

	Status 									int
	EphemeralPrivateKey			[]byte
	PublicKey 							[]byte
	SharedSecret 						[]byte
	Message 								string

}

type KeyStore struct {

	UUID 										string
	PublicUUID 							string
	PrivateKey 							*ecdsa.PrivateKey
	PublicUserKey 					*ecdsa.PrivateKey
	RSAKey 									*rsa.PrivateKey
	PendingConnections 			map[string]SharedKey
	LedgerKeys 							map[string]SharedKey
	Ledgers 								[]NewLedger
	Connections 						[]Connection
	Metadata 								map[string]string{}

}

type KeyStoreDisk struct {

	UUID 										string
	PublicUUID 							string
	PrivateKey							[]byte
	PublicUserKey 					[]byte
	RSAKey 									[]byte
	PendingConnections 			map[string]SharedKey
	LedgerKeys 							map[string]SharedKey
	Ledgers 								[]NewLedger
	Connections 						[]Connection
	Metadata 								map[string]interface{}
	
}

func ReadKeyStore(pass []byte, filename string) (*KeyStore, error) {

	_, e := os.Stat(filename)
	if e != nil {
		// we don't have an account so generate one now
		if os.IsNotExist(e) {

			rsaKey, e := rsaGenerateKey()
			if e != nil {
				log.Fatalf("failed to create rsa key: %s", e)
			}

			ks := &KeyStore{PrivateKey: GenerateKey(), PublicUserKey: GenerateKey(), RSAKey: rsaKey, Connections: []Connection{}, LedgerKeys: map[string]SharedKey{}, Ledgers: []NewLedger{}, PendingConnections: map[string]SharedKey{}, Metadata: map[string]interface{}{} }
			if e := Signup(ks); e != nil {
				log.Fatalf("Could not create new user account: %s", e)
			}
			return ks, nil
		} else {
			log.Printf("Failed to read keystore: %s", e)
			return nil, e
		}
	}

	b, e := ioutil.ReadFile(filename)
	if e != nil {
		return nil, e
	}

	hash := sha256.Sum256(pass)
	plaintext, e := Decrypt(hash[:], b)
	if e != nil {
		log.Printf("Failed to Decrypt: %s", e)
		return nil, e
	}

	ksd := KeyStoreDisk{}
	if e := json.Unmarshal(plaintext, &ksd); e != nil {
		log.Printf("Failed to Unmarshal KeyStore from Disk: %s", e)
		return nil, e
	}

	ks := &KeyStore{LedgerKeys: ksd.LedgerKeys, UUID: ksd.UUID, PublicUUID: ksd.PublicUUID, PublicUserKey: DecodeKey(ksd.PublicUserKey), PrivateKey: DecodeKey(ksd.PrivateKey), RSAKey: DecodeRSAKey(ksd.RSAKey), Ledgers: ksd.Ledgers, PendingConnections: ksd.PendingConnections, Metadata: ksd.Metadata}

	if ks.PendingConnections == nil {
		ks.PendingConnections = map[string]SharedKey{}
	}

	return ks, nil
}

func WriteKeyStore(pass []byte, filename string, ks *KeyStore) error {

	ksd := KeyStoreDisk{Ledgers: ks.Ledgers, LedgerKeys: ks.LedgerKeys, PrivateKey: EncodeKey(ks.PrivateKey), PublicUserKey: EncodeKey(ks.PublicUserKey), RSAKey: EncodeRSAKey(ks.RSAKey), UUID: ks.UUID, PublicUUID: ks.PublicUUID, PendingConnections: ks.PendingConnections, Metadata: ks.Metadata}
	buf, e := json.Marshal(ksd)
	if e != nil {
		log.Fatalf("Failed to marshal keystore for storage: %s", e)
	}

	hash := sha256.Sum256(pass)
	cipherBuf, nonce, e := Crypt(hash[:], buf)
	if e != nil {
		log.Printf("Failed to AES Encrypt: %s", e)
		return e
	}

	f, e := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		log.Printf("Failed to create keystore file: %s", e)
		return e
	}

	if _, e := f.Write(nonce); e != nil {
		log.Printf("Failed to write nonce to keystore file: %s", e)
		return e
	}

	if _, e := f.Write(cipherBuf); e != nil {
		log.Printf("Failed to write ciphertext to keystore file: %s", e)
		return e
	}

	if e := f.Close(); e != nil {
		log.Printf("Failed to Close KeyStore File: %s", e)
		return e
	}

	return e
}

func EncodeKey(privateKey *ecdsa.PrivateKey) []byte {
    x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
    return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
}

func DecodeKey(pemEncoded []byte) *ecdsa.PrivateKey {

    block, _ := pem.Decode(pemEncoded)
    x509Encoded := block.Bytes
    privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

    return privateKey
}

func EncodeRSAKey(privateKey *rsa.PrivateKey) []byte {
	x509Encoded := x509.MarshalPKCS1PrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
}

func DecodeRSAKey(pemEncoded []byte) *rsa.PrivateKey {

    block, _ := pem.Decode(pemEncoded)
    x509Encoded := block.Bytes
    privateKey, _ := x509.ParsePKCS1PrivateKey(x509Encoded)

    return privateKey
}
