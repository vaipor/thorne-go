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

func CreateLedger(ks *KeyStore, name string, description string, site string, hasIcon bool, ledgerType int, key []byte, addtlUsers []string) (string, error) {

	b := LedgerBlock{Name: name, Description: description, Site: site, HasIcon: hasIcon, UUID: ks.UUID, Date: time.Now().UTC().Format(TIME_FORMAT), LedgerType: ledgerType, AdditionalUsers: addtlUsers}

	br := LedgerRequest{LedgerBlock: b, Signature: base64.StdEncoding.EncodeToString(GenerateSignature(ks.PrivateKey, []byte(b.UUID + fmt.Sprintf("%d", b.LedgerType) + b.Date)))}
	buf, e := json.Marshal(br)
	if e != nil {
		log.Printf("Failed to Marshal Block: %s", e)
		return "", e
	}

	c := &http.Client{}
	r, e := http.NewRequest("PUT", "https://thorne.app/api/createledger", bytes.NewBuffer(buf))
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
		return "", fmt.Errorf("Failed to create ledger: %d", x.StatusCode)
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