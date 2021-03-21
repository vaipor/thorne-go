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

func CheckLedger(ks *KeyStore, ledger *NewLedger, ledgerNum int) error {

	// if we don't find a matching ledger than bail
	if ledger == nil {
		return fmt.Errorf("Failed to Locate Matching Ledger: %s", ledger.UUID)
	}

	llb := LedgerLastBlock{UUID: ks.UUID, Date: time.Now().UTC().Format(time.RFC3339), LedgerUUID: ledger.UUID}
	lbr := LedgerBlockRequest{LedgerLastBlock: llb, Signature: base64.StdEncoding.EncodeToString(GenerateSignature(ks.PrivateKey, []byte(llb.UUID + llb.Date + llb.LedgerUUID)))}
	buf, e := json.Marshal(lbr)
	if e != nil {
		log.Printf("Failed to Marshal LedgerBlockRequest: %s", e)
		return e
	}

	c := &http.Client{}
	r, e := http.NewRequest("PUT", "https://us-central1-vaipor.cloudfunctions.net/GetLedger", bytes.NewBuffer(buf))
	if e != nil {
		log.Printf("Failed to create request: %s", e)
		return e
	}

	x, e := c.Do(r)
	if e != nil {
		log.Printf("Get Ledger API Failed: %s", e)
		return e
	}

	if x.StatusCode != 200 {
		return fmt.Errorf("Failed to fetch ledger: %d", x.StatusCode)
	}

	if buf, e = ioutil.ReadAll(x.Body); e != nil {
		log.Printf("Failed to read response body: %s", e)
		return e
	}

	nl := NewLedger{}
	if e := json.Unmarshal(buf, &nl); e != nil {
		log.Printf("Failed to unmarshal ledger response: %s", e)
		return e
	}

	// the block id's match so nothing has changed
	if ledger.LastBlock == nl.LastBlock {
		log.Printf("Last Blocks Match so nothing to grab")
		return nil
	}

	defer func() {
		ledger.LastBlock = nl.LastBlock
	}()

	// so we have a new block id so run down the blocks until we find the one we last downloaded
	// or we cannot download anymore blocks
	var block *BlockRequest
	blockURL := nl.LastBlock
	for {

		if blockURL == "-" {
			break
		}

		log.Printf("Fetching Block %s\n", blockURL)
		block = GetBlock(ks, blockURL, ledger)
		log.Printf("Retrieved Block %s\n", block)

		if block == nil {
			break
		}

		str := ""
		contents, _ := base64.StdEncoding.DecodeString(block.Block.Contents)
		if ledger.LedgerType == LEDGER_TYPE_PUBLIC || ledger.LedgerType == LEDGER_TYPE_REQUESTS {
			str = string(contents)
		} else {
			b, e := Decrypt(ks.LedgerKeys[ledger.UUID].SharedSecret, contents)
			if e != nil {
				log.Printf("Failed to Decrypt Contents: %s", e)
			}

			str = string(b)
		}

		// based on the block type we received handle the scenario i.e. Key Exchange, Decode HTML Block, etc...
		body := ""
		switch block.Block.BlockType {
		case MessageType:
			body = str
		case KeyExchangeInitType:
			body = str
			msg, e := UnmarshalKeyExchangeInit([]byte(str))
			if e != nil {
				return e
			}
			HandleKeyExchangeInit(ks, msg)

			log.Printf("HandleKeyExchangeInit: %s %#v", msg.UUID, ks.PendingConnections[msg.UUID])
		case KeyExchangeResponseType:
			body = str
			msg, e := UnmarshalKeyExchangeResponse([]byte(str))
			if e != nil {
				return e
			}
			HandleKeyExchangeResponse(ks, msg)
		case KeyExchangeAckType:
			body = str
			msg, e := UnmarshalKeyExchangeAck([]byte(str))
			if e != nil {
				return e
			}
			HandleKeyExchangeAck(ks, msg)
		case ArticleType:
			body = str
			msg, e := UnmarshalArticle([]byte(str))
			if e != nil {
				return e
			}
			log.Printf("Article Message: %#v", msg)
		case HTMLType:
			body = str
			msg, e := UnmarshalHTML([]byte(str))
			if e != nil {
				return e
			}
			log.Printf("HTML Message: %#v", msg)
		}


		log.Printf("Block Contents %s\n", body)

		if block == nil {
			log.Printf("Recieved nil block")
			break
		}

		if block.ParentBlock == "-" || len(block.ParentBlock) <= 1 {
			break
		}

		// when we hit the last block we recorded then we can quit
		blockURL = block.ParentBlock

		if blockURL == ledger.LastBlock {
			break
		}
	}

	// set the last block to one we got back from the API
	ks.Ledgers[ledgerNum].LastBlock = nl.LastBlock
	return nil
}

func GetBlock(ks *KeyStore, blockURL string, ledger *NewLedger) *BlockRequest {

	x, e := http.Get(blockURL)
	if e != nil {
		log.Printf("Failed to Fetch Block: %s", e)
		return nil
	}

	buf, e := ioutil.ReadAll(x.Body)
	if e != nil {
		log.Printf("Failed to Read Body: %s", e)
		return nil
	}

	br := &BlockRequest{}
	if e := json.Unmarshal(buf, br); e != nil {
		log.Printf("Failed to Unmarshal Block: %s", e)
		return nil
	}

  publicKey := GetPublicKey(br.Block.UUID)
  if !VerifySignature(publicKey, br.Signature, []byte(br.Block.UUID + br.Block.Ledger + br.Block.Contents + br.Block.Date + br.Block.BlockType)) {
    log.Printf("Failed to verify signature with publicKey: %s", br.Block.UUID)
    //return nil
  }

	return br
}