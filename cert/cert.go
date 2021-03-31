package cert

import (

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/hkdf"
	//"github.com/aead/ecdh"

)

func GenerateKey() *ecdsa.PrivateKey {

	k, e := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if e != nil {
		log.Fatalf("GenerateKey Failed: %s", e)
	}

	return k
}

func GenerateSignature(k *ecdsa.PrivateKey, data []byte) []byte {

	hash := sha256.Sum256(data)
	signature, e := ecdsa.SignASN1(rand.Reader, k, hash[:])
	if e != nil {
		log.Fatalf("Sign Failed: %s", e)
	}

	return signature
}

func GenerateSymetricKey(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {

	if privateKey == nil {
		return nil, fmt.Errorf("Private Key is NIL")
	}

  eciesPublicKey := ecies.ImportECDSAPublic(publicKey)
	eciesPrivateKey := ecies.ImportECDSA(privateKey)
	skLen := ecies.MaxSharedKeyLength(&eciesPrivateKey.PublicKey) / 2

	buf, e := eciesPrivateKey.GenerateShared(eciesPublicKey, skLen, skLen)
	if e != nil {
		log.Printf("Failed to Generate Shared Key: %s", e)
		return nil, e
	}

  hash := sha256.New
  kdf := hkdf.New(hash, buf, nil, nil)

  k := make([]byte, 32)
  if _, err := io.ReadFull(kdf, k); err != nil {
      log.Printf("Failed to read from HKDF: %s", e)
      return nil, e
  }

  return k, nil
}

func MarshalPrivateKey(k *ecdsa.PrivateKey) []byte {

	byteLen := (elliptic.P521().Params().BitSize + 7) / 8

	ret := make([]byte, 1+3*byteLen)
	ret[0] = 4 // uncompressed point

	k.PublicKey.X.FillBytes(ret[1 : 1+byteLen])
	k.PublicKey.Y.FillBytes(ret[1+byteLen : 1+2*byteLen])
	k.D.FillBytes(ret[1+2*byteLen : 1+3*byteLen])

	return ret
}

func UnmarshalPrivateKey(data []byte) *ecdsa.PrivateKey {

	curve := elliptic.P521()

	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+3*byteLen {
		log.Printf("UnmarshalPrivateKey: key (%d) is not expected size (%d)", len(data), 1+3*byteLen)
		return nil
	}

	if data[0] != 4 { // uncompressed form
		log.Printf("UnmarshalPrivateKey: Is compressed")
		return nil
	}

	p := curve.Params().P
	x := new(big.Int).SetBytes(data[1 : 1+byteLen])
	y := new(big.Int).SetBytes(data[1+byteLen : 1+2*byteLen])
	d := new(big.Int).SetBytes(data[1+2*byteLen : 1+3*byteLen])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		log.Printf("UnmarshalPrivateKey: X,Y is less than or equal to prime")
		return nil
	}

	if !curve.IsOnCurve(x, y) {
		log.Printf("UnmarshalPrivateKey: X,Y Not on Curve")
		return nil
	}

	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
}