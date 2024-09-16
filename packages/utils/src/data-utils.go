package utils

import (
	"time"

	"golang.org/x/crypto/blake2b"

	"fmt"
	"regexp"

	"github.com/btcsuite/btcutil/base58"
)

// Constants
const DID_LATEST_VERSION = 1

var (
	CORD_DID_REGEX        = regexp.MustCompile(`^did:cord:(?P<address>3[1-9a-km-zA-HJ-NP-Z]{47})(?P<fragment>#[^#\n]+)?$`)
	InvalidDidFormatError = fmt.Errorf("Invalid DID format")
	DidError              = fmt.Errorf("DID Error")
)

type DidUri string
type DidResourceUri string
type CordAddress string
type UriFragment string

type DidVerificationKey struct {
	PublicKey []byte
	Type      string
}

type IDidParsingResult struct {
	Did                 DidUri
	Version             int
	Type                string
	Address             CordAddress
	Fragment            *UriFragment
	AuthKeyTypeEncoding *string
	EncodedDetails      *string
}

// Functions
func Parse(didUri string) (IDidParsingResult, error) {
	matches := CORD_DID_REGEX.FindStringSubmatch(didUri)
	if matches == nil {
		return IDidParsingResult{}, InvalidDidFormatError
	}

	result := make(map[string]string)
	for i, name := range CORD_DID_REGEX.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = matches[i]
		}
	}

	address := result["address"]
	fragment := result["fragment"]
	version := DID_LATEST_VERSION

	return IDidParsingResult{
		Did:      DidUri(didUri),
		Version:  version,
		Type:     "full",
		Address:  CordAddress(address),
		Fragment: (*UriFragment)(&fragment),
	}, nil
}

func IsSameSubject(didA, didB DidUri) (bool, error) {
	ParsedA, err := Parse(string(didA))
	if err != nil {
		return false, err
	}
	ParsedB, err := Parse(string(didB))
	if err != nil {
		return false, err
	}
	return ParsedA.Address == ParsedB.Address, nil
}

type EncodedVerificationKey struct {
	Sr25519 []byte
	Ed25519 []byte
	Ecdsa   []byte
}

type EncodedEncryptionKey struct {
	X25519 []byte
}

type EncodedKey struct {
	EncodedVerificationKey
	EncodedEncryptionKey
}

type EncodedSignature struct {
	EncodedVerificationKey
}

func ValidateUri(input interface{}, expectType ...string) error {
	inputStr, ok := input.(string)
	if !ok {
		return fmt.Errorf("DID string expected, got %T", input)
	}
	Parsed, err := Parse(inputStr)
	if err != nil {
		return err
	}

	fragment := Parsed.Fragment
	if fragment != nil && (len(expectType) > 0 && expectType[0] == "Did" || (len(expectType) > 0 && expectType[0] == "ResourceUri")) {
		return DidError
	}

	if fragment == nil && len(expectType) > 0 && expectType[0] == "ResourceUri" {
		return DidError
	}

	if !IsCordAddress(string(Parsed.Address)) {
		return fmt.Errorf("invalid cord address")
	}
	return nil
}

func GetAddressByKey(input DidVerificationKey) (CordAddress, error) {
	if input.Type == "ed25519" || input.Type == "sr25519" {
		return EncodeAddress(input.PublicKey, Ss58Format), nil

	}

	var address []byte
	if len(input.PublicKey) > 32 {
		hash := blake2b.Sum256(input.PublicKey)
		address = hash[:]
	} else {
		address = input.PublicKey
	}
	return EncodeAddress(address, Ss58Format), nil
}

func GetDidUri(didOrAddress string) (DidUri, error) {
	if IsCordAddress(didOrAddress) {
		return DidUri(fmt.Sprintf("did:cord:%s", didOrAddress)), nil
	}
	Parsed, err := Parse(didOrAddress)
	if err != nil {
		return "", err
	}
	return DidUri(fmt.Sprintf("did:cord:%s", Parsed.Address)), nil
}

func GetDidUriFromKey(key DidVerificationKey) (DidUri, error) {
	address, err := GetAddressByKey(key)
	if err != nil {
		return "", err
	}
	return GetDidUri(string(address))
}

func IsCordAddress(address string) bool {
	decodedAddress := base58.Decode(address)
	if decodedAddress != nil {
		return true
	} else {
		return false
	}
}


func ConvertUnixTimeToDateTime(unixTime float64, timeZone string) string {
	location, err := time.LoadLocation(timeZone)
	if err != nil {
		panic(err)
	}

	date := time.Unix(int64(unixTime), 0).In(location)

	formattedDate := date.Format("2006-January-02 15:04:05 MST")

	return formattedDate
}

func ConvertDateTimeToUnixTime(dateTimeStr string) int64 {
	layout := "2006-January-02 15:04:05 MST"
	date, err := time.Parse(layout, dateTimeStr)
	if err != nil {
		panic(err)
	}

	unixTime := date.Unix()

	return unixTime
}
