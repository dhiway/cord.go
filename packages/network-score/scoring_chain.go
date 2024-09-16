package network_score

import (
	"github.com/dhiway/cord.go/packages/did"
	identifier "github.com/dhiway/cord.go/packages/identifier/src"
	utils "github.com/dhiway/cord.go/packages/utils/src"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/signature"
	"github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
	"github.com/kartikaysaxena/substrateinterface/types/extrinsic"
)

func isRatingStored(ratingURI string, api *gsrpc.SubstrateAPI) (bool, error) {

	id, err := identifier.UriToIdentifier(ratingURI)
	if err != nil {
		panic(err)
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	var encoded types.Bytes

	key, err := types.CreateStorageKey(meta, "NetworkScore", "RatingEntries", utils.InterfaceToBytes(codec.Encode(id)))
	if err != nil {
		panic(err)
	}

	_, err = api.RPC.State.GetStorageLatest(key, encoded)
	if err != nil || len(encoded) == 0 {
		return false, nil
	}
	return true, nil
}

func dispatchRatingToChain(api *gsrpc.SubstrateAPI, ratingEntry map[string]string, authorAccount signature.KeyringPair, authorizationURI string, signCallback func()) (string, error) {

	authorizationID, err := identifier.UriToIdentifier(authorizationURI)
	if err != nil {
		panic(err)
	}

	exists, err := isRatingStored(ratingEntry["entry_uri"], api)
	if err != nil {
		return "", err
	}

	if exists {
		return ratingEntry["entry_uri"], nil
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	tx, err := types.NewCall(meta, "NetworkScore", "register_rating", map[string]interface{}{
		"entry":         ratingEntry["entry"],
		"digest":        ratingEntry["entry_digest"],
		"message_id":    ratingEntry["message_id"],
		"authorization": authorizationID,
	})

	dynamicExt := extrinsic.NewDynamicExtrinsic(&tx)

	if err != nil {
		panic(err)
	}

	ext, err := did.AuthorizeTx(api, ratingEntry["entry_uri"], dynamicExt, signCallback, authorAccount.Address, nil)
	if err != nil {
		panic(err)
	}

	err = ext.Sign(authorAccount, meta)
	if err != nil {
		panic(err)
	}

	sub, err := api.RPC.Author.SubmitAndWatchDynamicExtrinsic(ext)
	if err != nil {
		panic(err)
	}

	defer sub.Unsubscribe()

	return ratingEntry["entry_uri"], nil
}

func dispatchRevokeRatingToChain(api *gsrpc.SubstrateAPI, ratingEntry map[string]interface{}, authorAccount signature.KeyringPair, authorizationURI string, signCallback func()) (string, error) {

	authorizationID, err := identifier.UriToIdentifier(authorizationURI)
	if err != nil {
		panic(err)
	}

	exists, err := isRatingStored(ratingEntry["entry"].(map[string]string)["reference_id"], api)
	if err != nil {
		panic(err)
	}

	if !exists {
		panic("Rating Entry not found on chain")
	}

	ratingEntryID, err := identifier.UriToIdentifier(ratingEntry["entry_uri"].(string))

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}
	tx, err := types.NewCall(meta, "NetworkScore", "revoke_rating", map[string]interface{}{
		"entry_identifier": ratingEntryID,
		"message_id":       ratingEntry["message_id"],
		"digest":           ratingEntry["entry_digest"],
		"authorization":    authorizationID,
	})

	if err != nil {
		panic("Error creating revoke transaction: " + err.Error())
	}

	extrinsic, err := did.AuthorizeTx(api, ratingEntry["entry_uri"].(string), extrinsic.NewDynamicExtrinsic(&tx), signCallback, authorAccount.Address, nil)
	if err != nil {
		panic("Error authorizing transaction: " + err.Error())
	}

	err = extrinsic.Sign(authorAccount, meta)
	if err != nil {
		panic("Error signing transaction: " + err.Error())
	}

	sub, err := api.RPC.Author.SubmitAndWatchDynamicExtrinsic(extrinsic)
	if err != nil {
		panic("Error submitting extrinsic: " + err.Error())
	}

	defer sub.Unsubscribe()

	return ratingEntry["entry_uri"].(string), nil
}

func dispatchReviseRatingToChain(api *gsrpc.SubstrateAPI, ratingEntry map[string]interface{}, authorAccount signature.KeyringPair, authorizationURI string, signCallback func()) (string, error) {

	authorizationID, err := identifier.UriToIdentifier(authorizationURI)
	if err != nil {
		panic(err)
	}

	exists, err := isRatingStored(ratingEntry["entry_uri"].(string), api)
	if err != nil {
		panic(err)
	}

	if exists {
		return ratingEntry["entry_uri"].(string), nil
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	refEntryID, err := identifier.UriToIdentifier(ratingEntry["entry"].(map[string]string)["reference_id"])
	if err != nil {
		panic(err)
	}

	tx, err := types.NewCall(meta, "NetworkScore", "revise_rating", map[string]interface{}{
		"entry":         ratingEntry["entry"].(map[string]string)["entry"],
		"digest":        ratingEntry["entry_digest"],
		"message_id":    ratingEntry["message_id"],
		"debit_ref_id":  refEntryID,
		"authorization": authorizationID,
	})
	if err != nil {
		panic("Error creating revise transaction: " + err.Error())
	}

	extrinsic, err := did.AuthorizeTx(api, ratingEntry["entry_uri"].(string), extrinsic.NewDynamicExtrinsic(&tx), signCallback, authorAccount.Address, nil)
	if err != nil {
		panic("Error authorizing transaction: " + err.Error())
	}

	err = extrinsic.Sign(authorAccount, meta)
	if err != nil {
		panic("Error signing transaction: " + err.Error())
	}

	sub, err := api.RPC.Author.SubmitAndWatchDynamicExtrinsic(extrinsic)
	if err != nil {
		panic("Error submitting extrinsic: " + err.Error())
	}

	defer sub.Unsubscribe()

	return ratingEntry["entry_uri"].(string), nil
}

func decodeRatingValue(encodedRating int64, mod int64) int64 {
	if mod == 0 {
		mod = 10
	}
	return encodedRating / mod
}

func decodeEntryDetailsFromChain(encoded types.Bytes, stmtURI, timeZone string) map[string]interface{} {

	if timeZone == "" {
		timeZone = "GMT"
	}

	var encodedValue map[string]interface{}

	err := codec.Decode(encoded, &encodedValue)
	if err != nil {
		panic(err)
	}

	encodedEntry := encodedValue["entry"].(map[string]interface{})

	decodedEntry := map[string]interface{}{
		"entity_id":    encodedEntry["entity_id"],
		"provider_id":  encodedEntry["provider_id"],
		"rating_type":  encodedEntry["rating_type"],
		"count_of_txn": encodedEntry["count_of_txn"],
		"total_rating": decodeRatingValue(encodedEntry["total_rating"].(int64), 10),
	}

	var reference_id string

	if encodedEntry["reference_id"] != nil {
		reference_id, err = identifier.IdentifierToUri(encodedEntry["reference_id"].(string))
		if err != nil {
			panic(err)
		}
	}

	spaceId, err := identifier.IdentifierToUri(encodedEntry["space"].(string))
	if err != nil {
		panic(err)
	}

	entry_uri, err := identifier.IdentifierToUri(stmtURI)
	if err != nil {
		panic(err)
	}

	decodedDetails := map[string]interface{}{
		"entry_uri":    entry_uri,
		"entry":        decodedEntry,
		"digest":       encodedEntry["digest"],
		"message_id":   encodedEntry["message_id"],
		"space":        spaceId,
		"creator_uri":  did.FromChain(encodedEntry["creator_id"].([]byte)),
		"entry_type":   encodedEntry["entry_type"],
		"reference_id": reference_id,
		"created_at":   utils.ConvertUnixTimeToDateTime(float64(encodedEntry["created_at"].(int64))/1000.0, timeZone),
	}

	return decodedDetails
}

func fetchRatingDetailsFromChain(api *gsrpc.SubstrateAPI, ratingURI, timeZone string) (map[string]interface{}, error) {

	id, err := identifier.UriToIdentifier(ratingURI)
	if err != nil {
		panic(err)
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	var encoded types.Bytes

	key, err := types.CreateStorageKey(meta, "NetworkScore", "RatingEntries", utils.InterfaceToBytes(codec.Encode(id)))
	if err != nil {
		panic(err)
	}

	_, err = api.RPC.State.GetStorageLatest(key, encoded)
	if err != nil {
		panic(err)
	}

	entryDetails := decodeEntryDetailsFromChain(encoded, ratingURI, timeZone)
	return entryDetails, nil
}

func fetchEntityAggregateScoreFromChain(api *gsrpc.SubstrateAPI, entity string, ratingType *string) []map[string]interface{} {

	decodedEntries := []map[string]interface{}{}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	if ratingType != nil {

		ratingTypeBytes, err := codec.Encode(*ratingType)
		if err != nil {
			panic(err)
		}

		key, err := types.CreateStorageKey(meta, "NetworkScore", "AggregateScores", []byte(entity), ratingTypeBytes)
		if err != nil {
			panic(err)
		}

		var specificItem types.Bytes
		_, err = api.RPC.State.GetStorageLatest(key, &specificItem)
		if err != nil || len(specificItem) == 0 {
			return nil
		}

		var value map[string]interface{}
		err = codec.Decode(specificItem, &value)
		if err != nil {
			panic(err)
		}

		decodedEntries = append(decodedEntries, map[string]interface{}{
			"entity_id":    entity,
			"rating_type":  *ratingType,
			"count_of_txn": value["count_of_txn"].(int64),
			"total_rating": decodeRatingValue(value["total_encoded_rating"].(int64), 10),
		})
	} else {
		key, err := types.CreateStorageKey(meta, "NetworkScore", "AggregateScores", []byte(entity))
		if err != nil {
			panic(err)
		}

		var entries map[string]types.Bytes
		_, err = api.RPC.State.GetStorageLatest(key, &entries)
		if err != nil {
			panic(err)
		}

		for ratingTypeKey, encodedValue := range entries {
			var value map[string]interface{}
			err := codec.Decode(encodedValue, &value)
			if err != nil {
				panic(err)
			}

			decodedEntries = append(decodedEntries, map[string]interface{}{
				"entity_id":    entity,
				"rating_type":  ratingTypeKey,
				"count_of_txn": value["count_of_txn"].(int64),
				"total_rating": decodeRatingValue(value["total_encoded_rating"].(int64), 10),
			})
		}
	}

	if len(decodedEntries) == 0 {
		panic("No entries found")
	}

	return decodedEntries
}
