package address

import (
	"github.com/kartikaysaxena/substrateinterface/signature"
)

type CordEncryptionKeypair struct {
	SecretKey []byte
	PublicKey []byte
	Type      string
}

type CordKeyringPair struct {
	KeyringPair signature.KeyringPair
	Address     string
}

type VerifyResult struct {
	Crypto    string
	IsValid   bool
	IsWrapped bool
	PublicKey int
}

type CordAddress = string
