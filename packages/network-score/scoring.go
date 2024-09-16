package network_score

import (
	"errors"
	"regexp"

	"github.com/dhiway/cord.go/packages/did"
	identifier "github.com/dhiway/cord.go/packages/identifier/src"
	utils "github.com/dhiway/cord.go/packages/utils/src"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
)

var RatingTypeOf = struct {
	Overall  string
	Delivery string
}{
	Overall:  "Overall",
	Delivery: "Delivery",
}

func ValidateRequiredFields(fields []string) error {
	for _, field := range fields {
		if field == "" {
			return errors.New("required fields cannot be empty")
		}
	}
	return nil
}

func ValidateHexString(entryDigest string) error {
	hexPattern := regexp.MustCompile(`^0x[0-9a-fA-F]+$`)
	if !hexPattern.MatchString(entryDigest) {
		return errors.New("invalid HexString for entryDigest")
	}
	return nil
}

func GetUriForRatingEntry(api *gsrpc.SubstrateAPI, entryDigest []byte, entityID, entryMsgID, chainSpace, providerURI string) (string, error) {
	scaleEncodedRatingEntryDigest := types.NewH256(entryDigest)

	scaleEncodedEntityUID := types.NewBytes([]byte(entityID))

	scaleEncodedMessageID := types.NewBytes([]byte(entryMsgID))

	chainSpaceIdentifier, err := identifier.UriToIdentifier(chainSpace)
	if err != nil {
		return "", err
	}
	scaleEncodedChainSpace := types.NewBytes(utils.InterfaceToBytes(codec.Encode(chainSpaceIdentifier)))
	providerIdentifier := did.ToChain(did.DidUri(providerURI))

	scaleEncodedProvider := types.NewBytes(utils.InterfaceToBytes(codec.Encode(providerIdentifier)))

	combinedEncoded := append(
		utils.InterfaceToBytes(codec.Encode(scaleEncodedRatingEntryDigest)),
		append(
			utils.InterfaceToBytes(codec.Encode(scaleEncodedEntityUID)),
			append(
				utils.InterfaceToBytes(codec.Encode(scaleEncodedMessageID)),
				append(
					utils.InterfaceToBytes(codec.Encode(scaleEncodedChainSpace)),
					utils.InterfaceToBytes(codec.Encode(scaleEncodedProvider))...,
				)...,
			)...,
		)...,
	)

	digest := utils.Blake2AsHex(combinedEncoded, 32)
	ratingURI := identifier.HashToURI(digest, utils.RATING_IDENT, utils.RATING_PREFIX)
	if err != nil {
		return "", err
	}

	return ratingURI, nil
}

// CreateRatingObject creates a rating object with a unique URI and common details
func CreateRatingObject(api *gsrpc.SubstrateAPI, entryDigest []byte, entityID, messageID, chainSpace, providerURI, authorURI string) (map[string]interface{}, error) {
	ratingURI, err := GetUriForRatingEntry(api, entryDigest, entityID, messageID, chainSpace, providerURI)
	if err != nil {
		return nil, err
	}

	details := map[string]interface{}{
		"entry_uri":    ratingURI,
		"chain_space":  chainSpace,
		"message_id":   messageID,
		"entry_digest": entryDigest,
		"author_uri":   authorURI,
	}

	return map[string]interface{}{
		"uri":     ratingURI,
		"details": details,
	}, nil
}

func BuildFromRatingProperties(api *gsrpc.SubstrateAPI, rating map[string]interface{}, chainSpace, authorURI string) (map[string]interface{}, error) {
	err := ValidateRequiredFields([]string{
		chainSpace,
		authorURI,
		rating["message_id"].(string),
		rating["entry_digest"].(string),
		rating["entry"].(map[string]interface{})["entity_id"].(string),
		rating["entry"].(map[string]interface{})["provider_did"].(string),
	})
	if err != nil {
		return nil, err
	}

	err = ValidateHexString(rating["entry_digest"].(string))
	if err != nil {
		return nil, err
	}

	uri, err := did.GetDidUri(rating["entry"].(map[string]interface{})["provider_did"].(string))
	if err != nil {
		panic(err)
	}

	result, err := CreateRatingObject(
		api,
		rating["entry_digest"].([]byte),
		rating["entry"].(map[string]interface{})["entity_id"].(string),
		rating["message_id"].(string),
		chainSpace,
		string(uri),
		authorURI,
	)
	if err != nil {
		return nil, err
	}

	details := result["details"].(map[string]interface{})
	details["entry"] = rating["entry"]
	return result, nil
}

func BuildFromRevokeRatingProperties(api *gsrpc.SubstrateAPI, rating map[string]interface{}, chainSpace, authorURI string) (map[string]interface{}, error) {
	err := ValidateRequiredFields([]string{
		chainSpace,
		authorURI,
		rating["entry"].(map[string]interface{})["message_id"].(string),
		rating["entry"].(map[string]interface{})["entry_digest"].(string),
	})
	if err != nil {
		return nil, err
	}

	err = ValidateHexString(rating["entry"].(map[string]interface{})["entry_digest"].(string))
	if err != nil {
		return nil, err
	}

	result, err := CreateRatingObject(
		api,
		rating["entry"].(map[string]interface{})["entry_digest"].([]byte),
		rating["entity_id"].(string),
		rating["entry"].(map[string]interface{})["message_id"].(string),
		chainSpace,
		rating["provider_did"].(string),
		authorURI,
	)
	if err != nil {
		return nil, err
	}

	details := result["details"].(map[string]interface{})
	details["entry"] = rating["entry"]
	return result, nil
}

func BuildFromReviseRatingProperties(api *gsrpc.SubstrateAPI, rating map[string]interface{}, chainSpace, authorURI string) (map[string]interface{}, error) {
	err := ValidateRequiredFields([]string{
		chainSpace,
		authorURI,
		rating["entry"].(map[string]interface{})["entity_id"].(string),
		rating["entry"].(map[string]interface{})["provider_did"].(string),
		rating["reference_id"].(string),
		rating["entry"].(map[string]interface{})["count_of_txn"].(string),
		rating["entry"].(map[string]interface{})["total_encoded_rating"].(string),
	})
	if err != nil {
		return nil, err
	}

	err = ValidateHexString(rating["entry_digest"].(string))
	if err != nil {
		return nil, err
	}

	didUri, err := did.GetDidUri(rating["entry"].(map[string]interface{})["provider_did"].(string))
	if err != nil {
		panic(err)
	}

	result, err := CreateRatingObject(
		api,
		rating["entry_digest"].([]byte),
		rating["entry"].(map[string]interface{})["entity_id"].(string),
		rating["message_id"].(string),
		chainSpace,
		string(didUri),
		authorURI,
	)
	if err != nil {
		return nil, err
	}

	details := result["details"].(map[string]interface{})
	details["entry"] = rating["entry"]
	return result, nil
}
