package chainspace

import (
	utils "github.com/dhiway/cord.go/packages/utils/src"
	"github.com/google/uuid"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
)

func BuildFromProperties(api *gsrpc.SubstrateAPI, uri string, params ...map[string]interface{}) map[string]interface{} {

	var chainSpaceDesc uuid.UUID

	if params[0]["chainSpaceDesc"] == nil {
		uuid, err := uuid.NewUUID()
		if err != nil {
			panic(err)
		}

		chainSpaceDesc = uuid

	} else {
		chainSpaceDesc = params[0]["chainSpaceDesc"].(uuid.UUID)
	}

	chainSpaceHash := "0x" + utils.Blake2AsHex(utils.InterfaceToBytes(codec.Encode(chainSpaceDesc)), 32)
	uriInfo := GetURIForSpace(chainSpaceHash, uri, *api)

	return map[string]interface{}{
		"uri":              uriInfo["uri"],
		"desc":             chainSpaceDesc,
		"digest":           chainSpaceHash,
		"authorizationURI": uriInfo["authorizationURI"],
	}
}

func BuildFromAuthorizationProperties(spaceURI string, delegateURI string, permission string, creatorURI string) map[string]string {

	authorizationURI := GetURIForAuthorization(spaceURI, delegateURI, creatorURI)

	return map[string]string{
		"uri":              spaceURI,
		"delegate_uri":     delegateURI,
		"permission":       permission,
		"authorizationURI": authorizationURI,
		"delegator_uri":    creatorURI,
	}
}
