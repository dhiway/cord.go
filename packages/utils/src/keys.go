package utils

import (
	"github.com/kartikaysaxena/substrateinterface/signature"
)

type DidKeypair struct {
	Authentication *signature.KeyringPair
	Assertion      *signature.KeyringPair
	Delegation     *signature.KeyringPair
	KeyAgreement   *signature.KeyringPair
}

func GenerateKeypairs(uri string) (DidKeypair, error) {
	if uri == "" {
		uri = GenerateMnemonic()
	}

	authentication, err := KeyPairFromURI(uri + "//did//authentication//0")
	if err != nil {
		panic(err)
	}

	assertion, err := KeyPairFromURI(uri + "//did//assertion//0")
	if err != nil {
		panic(err)
	}

	capabilityDelegation, err := KeyPairFromURI(uri + "//did//delegation//0")
	if err != nil {
		panic(err)
	}

	keyAgreement, err := KeyPairFromURI(uri + "//did//keyAgreement//0")
	if err != nil {
		panic(err)
	}

	return DidKeypair{
		Authentication: authentication,
		Assertion:      assertion,
		Delegation:     capabilityDelegation,
		KeyAgreement:   keyAgreement,
	}, nil

}
