package thorne

import (

	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

)

func Signup(ks *KeyStore) error {

	c := &http.Client{}
	r, e := http.NewRequest("GET", "https://us-central1-vaipor.cloudfunctions.net/CreateUser", nil)
	if e != nil {
		log.Printf("Failed to create request: %s", e)
		return e
	}

	x, e := c.Do(r)
	if e != nil {
		log.Printf("Create User API Failed: %s", e)
		return e
	}

	buf, e := ioutil.ReadAll(x.Body)
	if e != nil {
		log.Printf("Failed to Read Response Body: %s", e)
		return e
	}

	defer x.Body.Close()

	nu := &NewUser{}
	if e := json.Unmarshal(buf, nu); e != nil {
		log.Printf("Failed to Unmarshal Create User Response: %s", e)
		return e
	}

	ks.UUID = nu.UUID
	ks.PublicUUID = nu.AliasUUID

	//
	// save the public key
	bKey := elliptic.Marshal(elliptic.P521(), ks.PrivateKey.PublicKey.X, ks.PrivateKey.PublicKey.Y)
	sKey := base64.StdEncoding.EncodeToString(bKey)

	r, e = http.NewRequest("PUT", nu.PublicKeyURL, bytes.NewBufferString(sKey))
	if e != nil {
		log.Printf("Failed to create request for public key: %s", e)
		return e
	}

	r.Header.Add("Content-Type", "application/octet-stream")

	x, e = c.Do(r)
	if e != nil {
		log.Printf("Put Public Key Failed: %s", e)
		return e
	}

	fmt.Printf("Public Key Response: %s\n", x.Status)

	//
	// save the public user public key
	bKey = elliptic.Marshal(elliptic.P521(), ks.PublicUserKey.PublicKey.X, ks.PublicUserKey.PublicKey.Y)
	sKey = base64.StdEncoding.EncodeToString(bKey)

	r, e = http.NewRequest("PUT", nu.PublicUserKeyURL, bytes.NewBufferString(sKey))
	if e != nil {
		log.Printf("Failed to create request for public user public key: %s", e)
		return e
	}

	r.Header.Add("Content-Type", "application/octet-stream")

	x, e = c.Do(r)
	if e != nil {
		log.Printf("Put Public User Public Key Failed: %s", e)
		return e
	}

	fmt.Printf("Public User Public Key Response: %s\n", x.Status)

	//
	// save the rsa key
	bKey = x509.MarshalPKCS1PublicKey(rsaGetPublicKey(ks.RSAKey))
	sKey = base64.StdEncoding.EncodeToString(bKey)

	r, e = http.NewRequest("PUT", nu.RSAKeyURL, bytes.NewBufferString(sKey))
	if e != nil {
		log.Printf("Failed to create request for rsa key: %s", e)
		return e
	}

	r.Header.Add("Content-Type", "application/octet-stream")

	x, e = c.Do(r)
	if e != nil {
		log.Printf("Put RSA Key Failed: %s", e)
		return e
	}

	fmt.Printf("RSA Key Response: %s\n", x.Status)


	//
	// now create our ledgers

	// add the requests ledger
	SaveLedger(ks, "ul" + nu.UUID, LEDGER_TYPE_REQUESTS, []byte{}, []string{})

	// create our public ledger
	if _, e = CreateLedger(ks, LEDGER_TYPE_PUBLIC, []byte{}, []string{}); e != nil {
		log.Printf("Failed to create Public Ledger: %s", e)
		return e
	}

	// create our private ledger
	if _, e = CreateLedger(ks, LEDGER_TYPE_PRIVATE, GeneratePass(), []string{}); e != nil {
		log.Printf("Failed to create Private Ledger: %s", e)
		return e
	}

	return nil
}