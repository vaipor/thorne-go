package thorne

import (

	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

)

var ErrNotFound 				= errors.New("Ledger Not Found")

func SendMessage(ks *KeyStore, ledger string, content string) error {

	msg := Message{ Author: ks.UUID, Message: content }

	b, e := json.Marshal(msg)
	if e != nil {
		log.Printf("Failed to json.Marshal Message: %s", e)
		return e
	}

	return WriteBlock(ks, ledger, MessageType, string(b))
}

func WriteBlock(ks *KeyStore, ledgerUUID string, blockType string, content string) error {

	ledger, _ := GetLedger(ks, ledgerUUID)
	body := []byte{}

	if ledger == nil || ledger.LedgerType == LEDGER_TYPE_PUBLIC || ledger.LedgerType == LEDGER_TYPE_REQUESTS {
		body = []byte(content)
	} else if key, ok := ks.LedgerKeys[ledgerUUID]; ok {
		cipher, nonce, e := Crypt(key.SharedSecret, []byte(content))
		if e != nil {
			log.Printf("Failed to Encrypt Content: %s", e)
			return e
		}
		body = append(body, nonce...)
		body = append(body, cipher...)
	} else {
		return fmt.Errorf("No Ledger Key for UUID: %s", ledgerUUID)
	}

	bodyBase64 := ""
	// key exchange acks are encrypted and base64 encoded already so just pass them thru
	if blockType == KeyExchangeAckType {
		bodyBase64 = content
	} else {
		bodyBase64 = base64.StdEncoding.EncodeToString(body)
	}
	
	date := time.Now().UTC().Format(time.RFC3339)
	b := NewBlock{UUID: ks.UUID, Ledger: ledgerUUID, Date: date, Contents: bodyBase64, BlockType: blockType}

	br := BlockRequest{Block: b, Signature: base64.StdEncoding.EncodeToString(GenerateSignature(ks.PrivateKey, []byte(ks.UUID + ledgerUUID + bodyBase64 + date + blockType)))}
	buf, e := json.Marshal(br)
	if e != nil {
		log.Printf("Failed to Marshal Block: %s", e)
		return e
	}

	c := &http.Client{}
	r, e := http.NewRequest("PUT", "https://thorne.app/api/write", bytes.NewBuffer(buf))
	if e != nil {
		log.Printf("Failed to create request: %s", e)
		return e
	}

	x, e := c.Do(r)
	if e != nil {
		log.Printf("Write Block API Failed: %s", e)
		return e
	}

	if x.StatusCode != 200 {
		return fmt.Errorf("Failed to write block: %d", x.StatusCode)
	}

	return nil
}

func GetLedger(ks *KeyStore, ledgerUUID string) (*NewLedger, error) {

	for _, v := range ks.Ledgers {
		if v.UUID == ledgerUUID {
			return &v, nil
		}
	}

	return nil, ErrNotFound
}