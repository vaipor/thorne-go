package thorne

const (

  LEDGER_TYPE_PRIVATE     = iota
  LEDGER_TYPE_PUBLIC
  LEDGER_TYPE_REQUESTS
  LEDGER_TYPE_ONEONONE
  LEDGER_TYPE_CIRCLE
  LEDGER_TYPE_PHOTOS
  LEDGER_TYPE_HEALTH

)

type NewUser struct {

	UUID					          string
  AliasUUID               string
  PublicKeyURL            string
  PublicUserKeyURL        string
  RSAKeyURL               string
  Platform                string
  Bucket                  string
  PushTokens              []string
  TransactionID           string

}

type NewPublicUser struct {

  UUID                    string
  AliasUUID               string

}

type UserUpdate struct {

  UUID                    string
  Token                   string
  TransactionID           string
  Signature               string

}

type PublicProfileRequest struct {

  UUID                    string
  Name                    string
  Description             string
  Phone                   string
  Email                   string
  MakeSearchable          bool
  Signature               string

}

type PublicProfileResponse struct {

  ProfileImage            string
  BackgroundImage         string

}

type LedgerBlockRequest struct {

  Signature               string
  LedgerLastBlock         LedgerLastBlock

}

type LedgerLastBlock struct {

  UUID                    string        // UUID of the user creating the ledger
  Date                    string        // timestamp to increase entropy
  LedgerUUID              string

}

type LedgerRequest struct {

  Signature               string
  LedgerBlock             LedgerBlock

}

// this must be in alphabetical order for the signatures to match
type LedgerBlock struct {

  AdditionalUsers         []string
  Date                    string        // timestamp to increase entropy
  LedgerType              int
  UUID                    string        // UUID of the user creating the ledger
  Name                    string
  Site                    string
  Description             string
  HasIcon                 bool

}

type NewLedger struct {

	UUID					          string
  LedgerType              int
  Moderators              []string
  Users                   []string
  RootURL                 string
  LastBlock               string
  AllowReplies            bool
  Connections             []Connection

}

type Attachment struct {

  UUID                  string            // UUID for the attachment (generated by vaipor)
  Name                  string
  SHA256                string            // hash of the file's contents
  Size                  int               // file size
  ContentType           string            // Content Type for the file
  URL                   string            // user provided URL if the file is stored outside vaipor

}

type BlockAttachment struct {

  Signature             string            // the user's signature for the block
  Attachment            Attachment        // the attachment

}

type NewBlock struct {

  UUID                  string            // the UUID of the user adding the block
  Ledger                string            // UUID of the ledger to be used
  Contents              string            // the apps contents (base64 encoded)
  Date                  string            // the date the block was created (provided by app)
  Attachments           []BlockAttachment // any block attachments like files
  BlockType             string

}

type BlockRequest struct {

  ParentBlock           string            // The Next Block UUID in line
  UID                   string            // UUID for the Block (generated by vaipor)
  Block                 NewBlock          // The Block Contents Submitted by the user
  Signature             string            // The User's Signature for the Block
  OrgSignatures         []OrganizationalSignatures

}

// Signatures that provide additional verification of authority on top of the author's
type OrganizationalSignatures struct {

  UUID                  string
  Signature             string

}

type BlockResponse struct {

  Success               bool              // guess
  Error                 string            // an error during the process
  UUID                  string            // the UUID given to the new block
  AttachmentURLs        []string          // the signed URLs for attachment uploads

}