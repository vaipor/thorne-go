package thorne

import (

	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

)

// ******************************************************
// Key Exchange
// Allow devices can negotiate a mutual 32bit key
// ******************************************************
const KeyExchangeInitType = "ke0"
type KeyExchangeInit struct {

	EphemerealPublicKey string  			// public key of the initiator
	UUID 								string 				// UUID of the initiator
	Message 						string 				// Intro Message

}

// begin a connection request
func DoKeyExchangeInit(ks *KeyStore, uuid string, message string) error {

	log.Printf("DoKeyExchangeInit: %s", uuid)

	// grab the rsa key for this user
	pubKey, e := RsaGetPublicKey(uuid)
	if e != nil {
		log.Printf("Failed to retrieve Public Key for %s", uuid)
		return e
	}

	// create a new key to negotiate the shared key
	priv := GenerateKey()
	
	// setup our pending connections struct
	ks.PendingConnections[uuid] = SharedKey{Status: 0, EphemeralPrivateKey: MarshalPrivateKey(priv)}

	// marshal the public key to send
	bKey := elliptic.Marshal(elliptic.P521(), priv.PublicKey.X, priv.PublicKey.Y)

	// use the rsa key for the other user to encrypt our uuid
	cipherUUID, e := rsaEncypt(pubKey, ks.UUID)
	if e != nil {
		log.Printf("failed to encrypt uuid: %s", e)
		return e
	}

	// use their rsa key to encrypt our hello message
	cipherMsg, e := rsaEncypt(pubKey, message)
	if e != nil {
		log.Printf("failed to encrypt uuid: %s", e)
		return e
	}

	// setup our response
	ker := KeyExchangeInit{EphemerealPublicKey: base64.StdEncoding.EncodeToString(bKey), UUID: cipherUUID, Message: cipherMsg}
	buf, e := json.Marshal(ker)
	if e != nil {
		log.Printf("Failed to Marshal KeyExchangeInit: %s", e)
		return e
	}

	log.Printf("Sending %s", buf)

	return WriteBlock(ks, "ul" + uuid, KeyExchangeInitType, string(buf))
}

func UnmarshalKeyExchangeInit(buf []byte) (*KeyExchangeInit, error) {
	kei := &KeyExchangeInit{}
	e := json.Unmarshal(buf, kei)
	return kei, e
}

// connection request received so handle it
func HandleKeyExchangeInit(ks *KeyStore, ke *KeyExchangeInit) error {

	log.Printf("HandleKeyExchangeInit: %s %#v", ke.UUID, ke)

	// create a new key to  negotiate the shared key
	priv := GenerateKey()
	
	// setup our pending connections struct
	pubKey, e := base64.StdEncoding.DecodeString(ke.EphemerealPublicKey)
	if e != nil {
		log.Printf("HandleKeyExchangeInit: Failed to Decode EphemerealPublicKey (%s) %s", ke.EphemerealPublicKey, e)
		return e
	}

	// use our rsa key to decrypt their uuid and the message
	ke.UUID, e = rsaDecrypt(ks.RSAKey, ke.UUID)
	if e != nil {
		log.Printf("HandleKeyExchangeInit: Failed to RSA Decrypt UUID (%s) %s", ke.UUID, e)
		return e
	}

	ke.Message, e = rsaDecrypt(ks.RSAKey, ke.Message)
	if e != nil {
		log.Printf("HandleKeyExchangeInit: Failed to RSA Decrypt Message (%s) %s", ke.Message, e)
		return e
	}

	ks.PendingConnections[ke.UUID] = SharedKey{Status: 1, PublicKey: pubKey, EphemeralPrivateKey: MarshalPrivateKey(priv), Message: ke.Message }

	log.Printf("Received Connection Request from %s with message: %s", ke.UUID, ke.Message)

	// marshal the public key to send
	bKey := elliptic.Marshal(elliptic.P521(), priv.PublicKey.X, priv.PublicKey.Y)


	// grab the rsa key for this user
	rsapubKey, e := RsaGetPublicKey(ke.UUID)
	if e != nil {
		log.Printf("Failed to retrieve Public Key for %s", ke.UUID)
		return e
	}

	cipherUUID, e := rsaEncypt(rsapubKey, ks.UUID)
	if e != nil {
		log.Printf("failed to encrypt uuid: %s", e)
		return e
	}

	// setup our response
	ker := KeyExchangeResponse{EphemerealPublicKey: base64.StdEncoding.EncodeToString(bKey), UUID: cipherUUID}

	buf, e := json.Marshal(ker)
	if e != nil {
		log.Printf("Failed to Marshal KeyExchangeResponse: %s", e)
		return e
	}

	return WriteBlock(ks, "ul" + ke.UUID, KeyExchangeResponseType, string(buf))
}

const KeyExchangeResponseType = "ke1"
type KeyExchangeResponse struct {

	EphemerealPublicKey string 				// public key of the responder
	UUID 								string 				// UUID of the responder
	//Salt 								string 				// salt for entropy

}

func UnmarshalKeyExchangeResponse(buf []byte) (*KeyExchangeResponse, error) {
	kei := &KeyExchangeResponse{}
	e := json.Unmarshal(buf, kei)
	return kei, e
}

// connection request response received so handle it
func HandleKeyExchangeResponse(ks *KeyStore, ke *KeyExchangeResponse) error {

	var e error

	// use our rsa key to decrypt their uuid and the message
	ke.UUID, e = rsaDecrypt(ks.RSAKey, ke.UUID)
	if e != nil {
		log.Printf("HandleKeyExchangeInit: Failed to RSA Decrypt UUID (%s) %s", ke.UUID, e)
		return e
	}

	log.Printf("HandleKeyExchangeResponse: %s", ke.UUID)

	log.Printf("PublicKey: %#v", ke.EphemerealPublicKey)

	if len(ke.EphemerealPublicKey) == 0 {
		return fmt.Errorf("Empty EphemerealPublicKey")
	}

	// create a new key to  negotiate the shared key
	pubKey, e := base64.StdEncoding.DecodeString(ke.EphemerealPublicKey)
	if e != nil {
		log.Printf("Failed to decode public key: %s", e)
	}
	x, y := elliptic.Unmarshal(elliptic.P521(), pubKey)
  bKey := &ecdsa.PublicKey{elliptic.P521(), x, y}
	
	// grab the previous key negotiation information
	priv := UnmarshalPrivateKey(ks.PendingConnections[ke.UUID].EphemeralPrivateKey)

	log.Printf("Priv %#v Pub %#v", priv, bKey)

	sKey, e := GenerateSymetricKey(priv, bKey)
	if e != nil {
		log.Printf("Failed to GenerateSymetricKey: %s", e)
		return e
	}

	//log.Printf("Generated Symmetric Key %s", base64.StdEncoding.EncodeToString(sKey))

	ledgerUUID, e := CreateLedger(ks, LEDGER_TYPE_ONEONONE, sKey, []string{ke.UUID})
	if e != nil {
		log.Printf("Failed to Create Ledger: %s", e)
		return e
	}

	delete(ks.PendingConnections, ke.UUID)

	// setup our response ack
	ker := KeyExchangeAck{UUID: ks.UUID, LedgerUUID: ledgerUUID, Test: "All Set"}
	buf, e := json.Marshal(ker)
	if e != nil {
		log.Printf("Failed to Marshal KeyExchangeResponse: %s", e)
		return e
	}

	cipher, nonce, e := Crypt(sKey, buf)
	if e != nil {
		log.Printf("Failed to Encrypt Content: %s", e)
		return e
	}
	body := []byte{}
	body = append(body, nonce...)
	body = append(body, cipher...)

	return WriteBlock(ks, "ul" + ke.UUID, KeyExchangeAckType, base64.StdEncoding.EncodeToString(body))
}

const KeyExchangeAckType = "ke2"
type KeyExchangeAck struct {

	UUID 								string 				// UUID of the initiator
	Test 								string 				// encrypted message to Test results
	LedgerUUID 					string

}

func UnmarshalKeyExchangeAck(buf []byte) (*KeyExchangeAck, error) {
	kei := &KeyExchangeAck{}
	e := json.Unmarshal(buf, kei)
	return kei, e
}

// connection request ack received so handle it
func HandleKeyExchangeAck(ks *KeyStore, ke *KeyExchangeAck) error {

	log.Printf("HandleKeyExchangeAck: %s", ke.UUID)

	// create a new key to  negotiate the shared key
	x, y := elliptic.Unmarshal(elliptic.P521(), ks.PendingConnections[ke.UUID].PublicKey)
  bKey := &ecdsa.PublicKey{elliptic.P521(), x, y}
	
	// grab the previous key negotiation information
	priv := UnmarshalPrivateKey(ks.PendingConnections[ke.UUID].EphemeralPrivateKey)

	sKey, e := GenerateSymetricKey(priv, bKey)
	if e != nil {
		log.Printf("Failed to GenerateSymetricKey: %s", e)
		return e
	}

	// save a ledger that was given to us
	SaveLedger(ks, ke.LedgerUUID, LEDGER_TYPE_ONEONONE, sKey, []string{ke.UUID})
	delete(ks.PendingConnections, ke.UUID)
	return nil
}

const KeyRotationType = "kr"
type KeyRotation struct {

	UUID 								string 				// UUID of the initiator
	Test 								string 				// encrypted message to Test results
	LedgerUUID 					string
	PublicKey 					string

}

func UnmarshalKeyRotation(buf []byte) (*KeyRotation, error) {
	kei := &KeyRotation{}
	e := json.Unmarshal(buf, kei)
	return kei, e
}

// connection requested key rotation so start it
/*
func StartKeyRotation(ks *KeyStore, ke *KeyRotation) error {

	log.Printf("HandleKeyRotation: %s", ke.UUID)

	// create a new key to  negotiate the shared key
	x, y := elliptic.Unmarshal(elliptic.P521(), ks.PendingConnections[ke.UUID].PublicKey)
  bKey := &ecdsa.PublicKey{elliptic.P521(), x, y}
	
	// grab the previous key negotiation information
	priv := UnmarshalPrivateKey(ks.PendingConnections[ke.UUID].EphemeralPrivateKey)

	sKey, e := GenerateSymetricKey(priv, bKey)
	if e != nil {
		log.Printf("Failed to GenerateSymetricKey: %s", e)
		return e
	}

	// save a ledger that was given to us
	delete(ks.PendingConnections, ke.UUID)
	return nil
}

// connection requested key rotation so start it
func HandleKeyRotation(ks *KeyStore, ke *KeyRotation) error {

	log.Printf("HandleKeyRotation: %s", ke.UUID)

	// create a new key to  negotiate the shared key
	x, y := elliptic.Unmarshal(elliptic.P521(), ks.PendingConnections[ke.UUID].PublicKey)
  bKey := &ecdsa.PublicKey{elliptic.P521(), x, y}
	
	// grab the previous key negotiation information
	priv := UnmarshalPrivateKey(ks.PendingConnections[ke.UUID].EphemeralPrivateKey)

	sKey, e := GenerateSymetricKey(priv, bKey)
	if e != nil {
		log.Printf("Failed to GenerateSymetricKey: %s", e)
		return e
	}

	// save a ledger that was given to us
	delete(ks.PendingConnections, ke.UUID)
	return nil
}
*/
// ******************************************************
// Social
// Exchanging short messages
// ******************************************************
const MessageType = "msg"
type Message struct {

	Author 							string
	Message 						string

}

// ******************************************************
// Article
// This allows for presenting structured information
// ******************************************************
const ArticleType = "article"
type Article struct {

	Elements 						[]Element 		// orderd array of items to be presented

}

func UnmarshalArticle(buf []byte) (*Article, error) {
	kei := &Article{}
	e := json.Unmarshal(buf, kei)
	return kei, e
}

type Element struct {

	ContentType 				string 				// string representing the content type so it can be rendered properly
	Data 								string 				// base64 encoded information
	Padding 						[]int 				// padding to be used when presentedss
	Margin 							[]int 				// margin to be used when presented
	BackgroundColor 		[4]int 				// RGBA Background Color
	TextColor 					[4]int 				// RGBA Text Color
	MaxWidth 						int 				 	// Max Width in Pixels
	MaxHeight 					int 					// Max Height in Pixels

}

// ******************************************************
// HTML
// This allows for presenting HTML Encoded data
// ******************************************************
const HTMLType = "html"
type HTML struct {

	Body 								string 				// string of HTML
	CSS 								string 				// string of CSS

}

func UnmarshalHTML(buf []byte) (*HTML, error) {
	kei := &HTML{}
	e := json.Unmarshal(buf, kei)
	return kei, e
}


const ProfileType = "profile"
type Profile struct {

	Author 							string
	Name 								string
	Description 				string
	Phone 							string
	Email 							string

}

const JSONType = "json"

const HealthType = "health"
type Health struct {

	Author 							string
	Date 								string
	Data 								interface{}

}

const NotificateNewLedgerType = "not-newledger"
type NotificateNewLedger struct {

	Name 								string
	From 								string
	UUID 								string
	Key 								string
	User 								[]string
	LedgerType 					int

}

