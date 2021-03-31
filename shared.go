package thorne

import (

  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rsa"
  "crypto/sha256"
  "crypto/x509"
  "encoding/asn1"
  "encoding/base64"
  "errors"
  "io/ioutil"
  "log"
  "math/big"
  "net/http"
  "os"
  "strings"
  "time"

  "cloud.google.com/go/storage"
  "github.com/google/uuid"

)

// This Google Document leads me to believe a single bucket is a scalable solution
// https://cloud.google.com/storage/quotas

const MIN_RETRIES = 5
const TIME_FORMAT = "2006-01-02T15:04:05.999999999Z"

var bucketName = "vaipor_bucket_0"
var userBucketName = "vaipor_users_0"
var publicUserBucketName = "vaipor_public_users_0"
var rootURL = "https://storage.googleapis.com/" + bucketName

// Represents the two mathematical components of an ECDSA signature once decomposed.
type ECDSASignature struct {
    R, S *big.Int
}

func GetPublicKey(uuid string) *ecdsa.PublicKey {

  bucket := userBucketName
  if strings.HasPrefix(uuid, "p") {
    bucket = publicUserBucketName
  }

  url := "https://users.thorne.app/" + uuid + "/public.key"
  r, e := http.Get(url)
  if e != nil {
    log.Fatalf("Failed to get public key (%s): %s", url, e)
  }

  buf, e := ioutil.ReadAll(r.Body)
  if e != nil {
    log.Fatalf("Failed to Read Storage Handler: %s", e)
  }
  defer r.Body.Close()

  log.Printf("Read PublicKey (%s): %s", uuid, buf)

  key, e := base64.StdEncoding.DecodeString(string(buf))
  if e != nil {
    log.Fatalf("base64 error: %s", e)
  }

  x, y := elliptic.Unmarshal(elliptic.P521(), []byte(key))
  return &ecdsa.PublicKey{elliptic.P521(), x, y}
}

func RsaGetPublicKey(uuid string) (*rsa.PublicKey, error) {

  bucket := userBucketName
  if strings.HasPrefix(uuid, "p") {
    bucket = publicUserBucketName
  }

  url := "https://publicusers.thorne.app/" + uuid + "/rsa.key"
  r, e := http.Get(url)
  if e != nil {
    log.Fatalf("Failed to get rsa public key (%s): %s", url, e)
  }

  buf, e := ioutil.ReadAll(r.Body)
  if e != nil {
    log.Fatalf("Failed to Read Storage Handler: %s", e)
  }
  defer r.Body.Close()

  log.Printf("Read PublicKey (%s): %s", uuid, buf)

  key, e := base64.StdEncoding.DecodeString(string(buf))
  if e != nil {
    log.Fatalf("base64 error: %s", e)
  }

  var parsedKey interface{}
  if parsedKey, e = x509.ParsePKCS1PublicKey(key); e != nil {
    log.Printf("Not PKCS1 PublicKey: %s", e)
    if parsedKey, e = x509.ParsePKIXPublicKey(key); e != nil {
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

func VerifySignature(publicKey *ecdsa.PublicKey, signature string, data []byte) bool {

  der, e := base64.StdEncoding.DecodeString(signature)
  if e != nil {
      log.Fatalf("Error: %s", e)
  }

  // unmarshal the R and S components of the ASN.1-encoded signature into our
  // signature data structure
  sig := &ECDSASignature{}
  if _, e = asn1.Unmarshal(der, sig); e != nil {
    log.Fatalf("ASN1 Unmarshal Error: %s", e)
  }

  hash := sha256.Sum256(data)
  return ecdsa.Verify(publicKey, hash[:], sig.R, sig.S)
}