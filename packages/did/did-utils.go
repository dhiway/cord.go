package did

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	utils "github.com/dhiway/cord.go/packages/utils/src"
	"github.com/kartikaysaxena/substrateinterface/signature"
)

// Constants
const DID_LATEST_VERSION = 1

var (
	ss58Format            = 42
	CORD_DID_REGEX        = regexp.MustCompile(`^did:cord:(?P<address>3[1-9a-km-zA-HJ-NP-Z]{47})(?P<fragment>#[^#\n]+)?$`)
	InvalidDidFormatError = fmt.Errorf("Invalid DID format")
	DidError              = fmt.Errorf("DID Error")
)

// Types
type DidUri string
type DidResourceUri string
type UriFragment string

type DidVerificationKey struct {
	PublicKey []byte
	Type      string
}

// Functions

func Parse(didUri string) (map[string]interface{}, error) {
	matches := CORD_DID_REGEX.FindStringSubmatch(didUri)
	if matches == nil {
		return nil, InvalidDidFormatError
	}

	result := make(map[string]string)
	for i, name := range CORD_DID_REGEX.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = matches[i]
		}
	}

	versionString := result["version"]
	fragment := result["fragment"]
	address := result["address"]
	version := DID_LATEST_VERSION
	if versionString != "" {
		version, _ = strconv.Atoi(versionString)
	}

	parsedResult := map[string]interface{}{
		"did":      DidUri(didUri),
		"version":  version,
		"type":     "full",
		"address":  utils.CordAddress(address),
		"fragment": UriFragment(fragment),
	}

	if fragment == "#" {
		parsedResult["fragment"] = nil
	}

	return parsedResult, nil
}

func IsSameSubject(didA, didB DidUri) (bool, error) {
	parsedA, err := Parse(string(didA))
	if err != nil {
		return false, err
	}
	parsedB, err := Parse(string(didB))
	if err != nil {
		return false, err
	}
	return parsedA["address"] == parsedB["address"], nil
}

func ValidateUri(input interface{}, expectType ...string) error {
	inputStr, ok := input.(string)
	if !ok {
		return fmt.Errorf("DID string expected, got %T", input)
	}
	parsed, err := Parse(inputStr)
	if err != nil {
		return err
	}

	address := parsed["address"].(utils.CordAddress)
	fragment, _ := parsed["fragment"].(UriFragment)

	if fragment != "" && (len(expectType) > 0 && expectType[0] == "Did" || (len(expectType) > 0 && expectType[0] == "ResourceUri")) {
		return DidError
	}

	if fragment == "" && len(expectType) > 0 && expectType[0] == "ResourceUri" {
		return DidError
	}

	if !utils.IsCordAddress(string(address)) {
		return errors.New("Invalid cord address")
	} else {
		return nil
	}
}

func GetAddressByKey(key signature.KeyringPair) utils.CordAddress {
	return utils.EncodeAddress(key.PublicKey, utils.Ss58Format)
}

func GetDidUri(didOrAddress string) (DidUri, error) {
	if utils.IsCordAddress(didOrAddress) {
		return DidUri(fmt.Sprintf("did:cord:%s", didOrAddress)), nil
	}
	parsed, err := Parse(didOrAddress)
	if err != nil {
		return "", err
	}
	return DidUri(fmt.Sprintf("did:cord:%s", parsed["address"])), nil
}

func GetDidUriFromKey(key signature.KeyringPair) (DidUri, error) {
	address := GetAddressByKey(key)
	return GetDidUri(string(address))
}
