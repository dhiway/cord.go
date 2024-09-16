package chainspace

import (
	"strings"

	did "github.com/dhiway/cord.go/packages/did"
	identifier "github.com/dhiway/cord.go/packages/identifier/src"
	utils "github.com/dhiway/cord.go/packages/utils/src"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/rpc/author"
	"github.com/kartikaysaxena/substrateinterface/signature"
	types "github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
	"github.com/kartikaysaxena/substrateinterface/types/extrinsic"
)

func GetURIForSpace(spaceDigest string, creatorURI string, api gsrpc.SubstrateAPI) map[string]string {

	bytes, err := codec.Encode(spaceDigest)
	if err != nil {
		panic(err)
	}
	scaleEncodedSpaceDigest, err := codec.Encode(types.NewH256(bytes))

	encodedCreator, err := codec.Encode(did.ToChain(did.DidUri(creatorURI)))
	scaleEncodedCreatorAccountID, err := types.NewAccountID(encodedCreator)
	if err != nil {
		panic(err)
	}

	scaleEncodedCreator, err := codec.Encode(scaleEncodedCreatorAccountID)

	digest := utils.Blake2AsHex(append(scaleEncodedSpaceDigest, scaleEncodedCreator[0]), 256)

	chainSpaceURI := identifier.HashToURI(digest, utils.SPACE_IDENT, utils.SPACE_PREFIX)

	identifierToUri, err := identifier.UriToIdentifier(chainSpaceURI)
	if err != nil {
		panic(err)
	}
	scaleAuthDigest := utils.InterfaceToBytes(codec.Encode(identifierToUri))

	scaleEncodedAuthDigest := types.NewBytes(scaleAuthDigest)

	scaleEncodedAuthDelegate, err := types.NewAccountID(utils.InterfaceToBytes(codec.Encode(did.ToChain(did.DidUri(creatorURI)))))

	authDigest := utils.Blake2AsHex(append(scaleEncodedAuthDigest, scaleEncodedAuthDelegate[0]), 256)

	authorizationURI := identifier.HashToURI(authDigest, utils.AUTH_IDENT, utils.AUTH_PREFIX)

	return map[string]string{
		"uri":              chainSpaceURI,
		"authorizationURI": authorizationURI,
	}
}

func GetURIForAuthorization(spaceURI string, delegateURI string, creatorURI string) string {

	ident, err := identifier.UriToIdentifier(spaceURI)
	if err != nil {
		panic(err)
	}

	scaleEncodedSpaceId, err := codec.Encode(types.NewBytes(utils.InterfaceToBytes(codec.Encode(ident)))) //

	scaleEncodedAuthDelegateID, err := types.NewAccountID(utils.InterfaceToBytes(codec.Encode(did.ToChain(did.DidUri(delegateURI)))))
	if err != nil {
		panic(err)
	}

	scaleEncodedAuthDelegate, err := codec.Encode(scaleEncodedAuthDelegateID) //
	if err != nil {
		panic(err)
	}

	scaleEncodedAuthCreatorID, err := types.NewAccountID(utils.InterfaceToBytes(codec.Encode(did.ToChain(did.DidUri(creatorURI)))))
	if err != nil {
		panic(err)
	}

	scaleEncodedAuthCreator, err := codec.Encode(scaleEncodedAuthCreatorID) //
	if err != nil {
		panic(err)
	}

	var totalBytes []byte

	totalBytes = append(append(append(totalBytes, scaleEncodedSpaceId...), scaleEncodedAuthDelegate...), scaleEncodedAuthCreator...)

	authDigest := utils.Blake2AsHex(totalBytes, 256)
	auth_uri := identifier.HashToURI(authDigest, utils.AUTH_IDENT, utils.AUTH_PREFIX)

	return auth_uri
}

func SudoApproveChainSpace(authority *signature.KeyringPair, spaceURI string, capacity int, api *gsrpc.SubstrateAPI) (*author.ExtrinsicStatusSubscription, error) {

	spaceID, err := identifier.UriToIdentifier(spaceURI)
	if err != nil {
		return nil, err
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}

	callTx, err := types.NewCall(meta, "ChainSpace.approve", map[string]interface{}{
		"space_id":     spaceID,
		"txn_capacity": capacity,
	})
	if err != nil {
		return nil, err
	}

	sudoTx, err := types.NewCall(meta, "Sudo.sudo", map[string]interface{}{
		"call": callTx,
	})
	if err != nil {
		return nil, err
	}

	ext := extrinsic.NewExtrinsic(sudoTx)
	if err != nil {
		return nil, err
	}

	return api.RPC.Author.SubmitAndWatchExtrinsic(ext)
}

func PrepareCreateSpaceExtrinsic(chainSpace map[string]string, creatorURI string, signCallback func(), authorAccount *signature.KeyringPair, api *gsrpc.SubstrateAPI) (*extrinsic.Extrinsic, error) {

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}

	tx, err := types.NewCall(meta, "ChainSpace.create", map[string]interface{}{
		"space_code": chainSpace["digest"],
	})
	if err != nil {
		return nil, err
	}

	ext := extrinsic.NewExtrinsic(tx)

	extrinsic, err := did.AuthorizeTx(api, creatorURI, ext, signCallback, authorAccount.Address, nil)
	if err != nil {
		return nil, err
	}

	return &extrinsic, nil
}

func DispatchToChain(chainSpace map[string]string, creatorURI string, authorAccount *signature.KeyringPair, signCallback func(), api *gsrpc.SubstrateAPI) (map[string]string, error) {
	ext, err := PrepareCreateSpaceExtrinsic(chainSpace, creatorURI, signCallback, authorAccount, api)
	if err != nil {
		return nil, err
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	rv, err := api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		panic(err)
	}

	genesisHash, err := api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		panic(err)
	}

	accountStorageKey, err := types.CreateStorageKey(meta, "System", "Account", authorAccount.PublicKey)

	var accountInfo types.AccountInfo
	_, err = api.RPC.State.GetStorageLatest(accountStorageKey, &accountInfo)
	if err != nil {
		panic(err)
	}

	err = ext.Sign(
		*authorAccount,
		meta,
		extrinsic.WithEra(types.ExtrinsicEra{IsImmortalEra: true}, genesisHash),
		extrinsic.WithNonce(types.NewUCompactFromUInt(uint64(accountInfo.Nonce))),
		extrinsic.WithTip(types.NewUCompactFromUInt(0)),
		extrinsic.WithSpecVersion(rv.SpecVersion),
		extrinsic.WithTransactionVersion(rv.TransactionVersion),
		extrinsic.WithGenesisHash(genesisHash),
	)
	// extrinsic, err = api.CreateSignedExtrinsic(extrinsic, authorAccount)
	if err != nil {
		return nil, err
	}

	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(*ext)
	if err != nil {
		return nil, err
	}

	defer sub.Unsubscribe()

	return map[string]string{
		"uri":           chainSpace["uri"],
		"authorization": chainSpace["authorization_uri"],
	}, nil
}

func DispatchSubspaceCreateToChain(api *gsrpc.SubstrateAPI, chainSpace map[string]string, creatorURI string, authorAccount *signature.KeyringPair, count int, parent string, signCallback func()) (map[string]string, error) {

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}
	newStr := strings.Replace(parent, "space:cord:", "", -1)

	tx, err := types.NewCall(meta, "ChainSpace", "subspace_create", map[string]interface{}{
		"space_code": chainSpace["digest"],
		"count":      count,
		"space_id":   newStr,
	})
	if err != nil {
		return nil, err
	}

	ext := extrinsic.NewExtrinsic(&tx)

	extrinsicAuthorized, err := did.AuthorizeTx(api, creatorURI, ext, signCallback, authorAccount.Address)
	if err != nil {
		return nil, err
	}

	err = extrinsicAuthorized.Sign(*authorAccount, meta)
	if err != nil {
		return nil, err
	}

	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(extrinsicAuthorized)
	if err != nil {
		return nil, err
	}

	defer sub.Unsubscribe()

	return map[string]string{
		"uri":           chainSpace["uri"],
		"authorization": chainSpace["authorization_uri"],
	}, nil
}

func DispatchUpdateTxCapacityToChain(space string, creatorURI string, authorAccount *signature.KeyringPair, newCapacity int, signCallback func(), api *gsrpc.SubstrateAPI) (map[string]string, error) {

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	newStr := strings.Replace(space, "space:cord:", "", -1)

	tx, err := types.NewCall(meta, "ChainSpace.update_transaction_capacity_sub", map[string]interface{}{
		"space_id":         newStr,
		"new_txn_capacity": newCapacity,
	})
	if err != nil {
		return nil, err
	}

	ext := extrinsic.NewExtrinsic(&tx)

	extrinsicAuthorized, err := did.AuthorizeTx(api, creatorURI, ext, signCallback, authorAccount.Address)
	if err != nil {
		return nil, err
	}

	err = extrinsicAuthorized.Sign(*authorAccount, meta)
	if err != nil {
		return nil, err
	}

	sub, err := api.RPC.Author.SubmitAndWatchExtrinsic(extrinsicAuthorized)
	if err != nil {
		return nil, err
	}

	defer sub.Unsubscribe()

	return map[string]string{
		"uri": space,
	}, nil
}
