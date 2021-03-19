package thorne

import (

	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

)

func CreateLedger(ks *KeyStore, ledgerType int, key []byte, addtlUsers []string) (string, error) {

	b := LedgerBlock{UUID: ks.UUID, Date: time.Now().Format(time.RFC3339), LedgerType: ledgerType, AdditionalUsers: addtlUsers}
	sigB, e := json.Marshal(b)
	if e != nil {
		log.Printf("Failed to Marshal Block Body: %s", e)
		return "", e
	}

	br := LedgerRequest{LedgerBlock: b, Signature: base64.StdEncoding.EncodeToString(GenerateSignature(ks.PrivateKey, sigB))}
	buf, e := json.Marshal(br)
	if e != nil {
		log.Printf("Failed to Marshal Block: %s", e)
		return "", e
	}

	c := &http.Client{}
	r, e := http.NewRequest("PUT", "https://us-central1-vaipor.cloudfunctions.net/CreateLedger", bytes.NewBuffer(buf))
	if e != nil {
		log.Printf("Failed to create request: %s", e)
		return "", e
	}

	x, e := c.Do(r)
	if e != nil {
		log.Printf("Create Ledger API Failed: %s", e)
		return "", e
	}

	if x.StatusCode != 200 {
		return "", fmt.Errorf("Failed to write block: %d", x.StatusCode)
	}

	if buf, e = ioutil.ReadAll(x.Body); e != nil {
		log.Printf("Failed to read response body: %s", e)
		return "", e
	}

	nl := NewLedger{}
	if e := json.Unmarshal(buf, &nl); e != nil {
		log.Printf("Failed to unmarshal ledger response: %s", e)
		return "", e
	}

	ks.Ledgers = append(ks.Ledgers, nl)
	ks.LedgerKeys[nl.UUID] = SharedKey{Status: SK_STATUS_READY, SharedSecret: key}
	return nl.UUID, nil
}

func SaveLedger(ks *KeyStore, ledgerUUID string, ledgerType int, key []byte, addtlUsers []string) {
	ks.Ledgers = append(ks.Ledgers, NewLedger{UUID: ledgerUUID, LedgerType: ledgerType, Users: addtlUsers, LastBlock: "-"})
	ks.LedgerKeys[ledgerUUID] = SharedKey{Status: SK_STATUS_READY, SharedSecret: key}
}