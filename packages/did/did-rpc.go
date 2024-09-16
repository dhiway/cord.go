package did

import (
	"encoding/hex"
	"strings"

	"github.com/kartikaysaxena/substrateinterface/signature"
	utils "github.com/dhiway/cord.go/packages/utils/src"
)

func FromChain(encoded []byte) string {
	address := utils.EncodeAddress(encoded, utils.Ss58Format)
	didUri, err := GetDidUri(string(address))
	if err != nil {
		panic(err)
	}
	return string(didUri)
}

func DidPublicKeyDetailsFromChain(keyDetails map[string]interface{}) map[string]interface{} {
	key := keyDetails["key"].(map[string]interface{})
	keyValue := key["asPublicVerificationKey"]
	if key["isPublicEncryptionKey"].(bool) {
		keyValue = key["asPublicEncryptionKey"]
	}

	keyID := keyDetails["id"].([]byte)

	return map[string]interface{}{
		"sr25519": "0x" + hex.EncodeToString(keyDetails.PublicKey),
	}
}

func ResourceIdToChain(id string) string {
	return strings.ReplaceAll(id, "#", "")
}

func DocumentFromChain(encoded map[string]interface{}) map[string]interface{} {
	publicKeys := encoded["publicKeys"].(map[string]interface{})
	authenticationKey := encoded["authenticationKey"].([]byte)
	assertionKey := encoded["assertionKey"].(map[string]interface{})
	delegationKey := encoded["delegationKey"].(map[string]interface{})
	keyAgreementKeys := encoded["keyAgreementKeys"].([]interface{})
	lastTxCounter := encoded["lastTxCounter"]

	keys := make(map[string]interface{})
	for keyID, keyDetails := range publicKeys {
		keys[ResourceIdToChain(keyID)] = DidPublicKeyDetailsFromChain(keyDetails.(map[string]interface{}))
	}

	authKeyID := hex.EncodeToString(authenticationKey)
	authentication := keys[authKeyID]

	didRecord := map[string]interface{}{
		"authentication": []interface{}{authentication},
		"lastTxCounter":  lastTxCounter,
	}

	if assertionKey["isSome"].(bool) {
		key := keys[hex.EncodeToString(assertionKey["value"].([]byte))]
		didRecord["assertionMethod"] = []interface{}{key}
	}
	if delegationKey["isSome"].(bool) {
		key := keys[hex.EncodeToString(delegationKey["value"].([]byte))]
		didRecord["capabilityDelegation"] = []interface{}{key}
	}

	keyAgreementKeyIDs := []string{}
	for _, keyID := range keyAgreementKeys {
		keyAgreementKeyIDs = append(keyAgreementKeyIDs, hex.EncodeToString(keyID.([]byte)))
	}
	if len(keyAgreementKeyIDs) > 0 {
		keyAgreements := []interface{}{}
		for _, id := range keyAgreementKeyIDs {
			keyAgreements = append(keyAgreements, keys[id])
		}
		didRecord["keyAgreement"] = keyAgreements
	}

	return didRecord
}

func ServiceFromChain(encoded map[string]interface{}) map[string]interface{} {
	id := encoded["id"].(string)
	serviceTypes := encoded["service_types"].([]interface{})
	urls := encoded["urls"].([]interface{})

	return map[string]interface{}{
		"id":              "#" + id,
		"type":            serviceTypes,

		"serviceEndpoint": urls,
	}
}

func ServicesFromChain(encoded []interface{}) []interface{} {
	services := []interface{}{}
	for _, encodedValue := range encoded {
		services = append(services, ServiceFromChain(encodedValue.(map[string]interface{})))
	}
	return services
}

func LinkedInfoFromChain(encoded map[string]interface{}) map[string]interface{} {
	data := encoded["value"].(map[string]interface{})
	identifier := data["identifier"].([]byte)
	account := data["account"].(map[string]interface{})
	name := data["name"]
	serviceEndpoints := data["service_endpoints"].([]interface{})
	details := data["details"].(map[string]interface{})

	didRec := DocumentFromChain(details)

	did := map[string]interface{}{
		"uri":                  FromChain(identifier),
		"authentication":       didRec["authentication"],
		"assertionMethod":      didRec["assertionMethod"],
		"capabilityDelegation": didRec["capabilityDelegation"],
		"keyAgreement":         didRec["keyAgreement"],
	}

	services := ServicesFromChain(serviceEndpoints)
	if len(services) > 0 {
		did["service"] = services
	}

	var didName interface{}
	if name != nil {
		didName = name.(map[string]interface{})["value"]
	}

	didAccount := account["value"]

	return map[string]interface{}{
		"document": did,
		"account":  didAccount,
		"didName":  didName,
	}
}
