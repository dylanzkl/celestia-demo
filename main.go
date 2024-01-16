package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/celestiaorg/celestia-app/x/qgb/types"
	"github.com/cosmos/cosmos-sdk/server"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"
	"github.com/tendermint/tendermint/crypto/merkle"
	"math/big"
	"os"

	wrapper "github.com/celestiaorg/blobstream-contracts/v3/wrappers/Blobstream.sol"
	"github.com/celestiaorg/celestia-app/app"
	"github.com/celestiaorg/celestia-app/app/encoding"
	"github.com/celestiaorg/celestia-app/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/pkg/namespace"
	"github.com/celestiaorg/celestia-app/pkg/square"
	"github.com/celestiaorg/celestia-app/pkg/user"
	blobtypes "github.com/celestiaorg/celestia-app/x/blob/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/std"
	sdk "github.com/cosmos/cosmos-sdk/types"
	ethcmn "github.com/ethereum/go-ethereum/common"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	"github.com/tendermint/tendermint/rpc/client/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultKeyringDir  = "/Users/kyrie/.celestia-light/keys/"
	defaultAppName     = "celestia-app"
	defaultAccountName = "my_celes_key"
	// Blob index (only the first is supported currently)
	blobIndex = 0
	txHash    = "C9CB7B3212F362AF7003E6DE8DF6911BA029D8776678EE6BDA19461764C545F2"
	celesGRPC = "consensus.lunaroasis.net:9090"
	// Celestia RPC endpoint
	rpcEndpoint = "tcp://consensus.lunaroasis.net:26657"
	// BlobstreamX contract address
	contractAddr = "0x046120E6c6C48C05627FB369756F5f44858950a5"
	// EVM chain RPC endpoint. Goerli in this case
	evmRPC                   = "https://eth-goerli.public.blastapi.io"
	dataCommitmentStartBlock = 529001
	dataCommitmentEndBlock   = 530001
)

func createKeyRing() (keyring.Keyring, error) {
	dir := "/Users/kyrie/.celestia-test"
	//useInput := strings.NewReader("")
	cdc := getCodec()

	kr, err := keyring.New("celestia-app", keyring.BackendTest, dir, os.Stdin, cdc)
	if err != nil {
		return nil, err
	}

	return kr, nil
}

func generateNewKey(ring keyring.Keyring) (*keyring.Record, string, error) {
	return ring.NewMnemonic(defaultAccountName, keyring.English, sdk.GetConfig().GetFullBIP44Path(), keyring.DefaultBIP39Passphrase, hd.Secp256k1)
}

func getCodec() codec.Codec {
	amino := codec.NewLegacyAmino()
	registry := codectypes.NewInterfaceRegistry()

	std.RegisterLegacyAminoCodec(amino)
	cryptocodec.RegisterInterfaces(registry)

	return codec.NewProtoCodec(registry)
}

//func main() {
//	kr, err := createKeyRing()
//	if err != nil {
//		fmt.Printf("New keyring failed: %v", err)
//		os.Exit(1)
//	}
//	keys, err := kr.List()
//	if err != nil {
//		fmt.Printf("keyring list failed: %v", err)
//		os.Exit(1)
//	}
//	fmt.Printf("keys num: %d, keys: %v", len(keys), keys)
//	if len(keys) == 0 {
//		fmt.Println("No key found in store, generate new key")
//		keyInfo, mn, err := generateNewKey(kr)
//		if err != nil {
//			os.Exit(1)
//		}
//		fmt.Println("new key generated")
//		addr, err := keyInfo.GetAddress()
//		if err != nil {
//			os.Exit(1)
//		}
//		fmt.Printf("\nName: %s\nAddress: %s\nMnemonic: \n%s\n\n", keyInfo.Name, addr.String(), mn)
//		keys, _ = kr.List()
//		fmt.Printf("keys num: %d, keys: %v", len(keys), keys)
//	}
//	rec, err := kr.Key("dylan")
//	if err != nil {
//		fmt.Printf("Account not found: %v", err)
//	}
//	addr, err := rec.GetAddress()
//	if err != nil {
//		fmt.Printf("get addr failed: %v", err)
//	}
//	fmt.Printf("addr: %s", addr.String())
//}

//func main() {
//
//	dir := "/Users/kyrie/.celestia-light/keys/"
//	cdc := getCodec()
//	kr, err := keyring.New("celestia-app", keyring.BackendTest, dir, os.Stdin, cdc)
//	if err != nil {
//		panic(err)
//	}
//	rec, err := kr.Key(defaultAccountName)
//	if err != nil {
//		panic(err)
//	}
//	addr, err := rec.GetAddress()
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println(rec.Name)
//	fmt.Println(addr)
//
//	ecfg := encoding.MakeConfig(app.ModuleEncodingRegisters...)
//	conn, err := grpc.Dial(celesGRPC, grpc.WithTransportCredentials(insecure.NewCredentials()))
//	if err != nil {
//		panic(err)
//	}
//	defer conn.Close()
//	signer, err := user.SetupSigner(context.TODO(), kr, conn, addr, ecfg)
//	if err != nil {
//		panic(err)
//	}
//	ns := namespace.MustNewV0([]byte("1234567890"))
//	fmt.Println("namespace", len(ns.Bytes()))
//
//	blob, err := blobtypes.NewBlob(ns, []byte("hello world"), appconsts.ShareVersionZero)
//	if err != nil {
//		panic(err)
//	}
//
//	gasLimit := blobtypes.DefaultEstimateGas([]uint32{uint32(len(blob.Data))})
//	fmt.Println()
//	//fee := float64(appconsts.DefaultMinGasPrice * float64(gasLimit))
//
//	options := []user.TxOption{
//		user.SetGasLimitAndFee(gasLimit, 0.003),
//	}
//
//	resp, err := signer.SubmitPayForBlob(context.TODO(), []*tmproto.Blob{blob}, options...)
//	if err != nil {
//		panic(err)
//	}
//	if resp.Code != 0 {
//		fmt.Println(resp.Code, resp.Codespace, resp.RawLog)
//	}
//
//}

func main() {
	err := verify(txHash)
	if err != nil {
		fmt.Printf("verify failed: %s", err.Error())
		os.Exit(1)
	}
	fmt.Println("proofs from shares to data root are valid")
}

func loadKeyring() (keyring.Keyring, error) {
	cdc := getCodec()
	kr, err := keyring.New(defaultAppName, keyring.BackendTest, defaultKeyringDir, os.Stdin, cdc)
	if err != nil {
		return nil, err
	}
	return kr, nil
}

func submitDataDemo(grpcAddr string, kr keyring.Keyring) {
	rec, err := kr.Key(defaultAccountName)
	if err != nil {
		panic(err)
	}
	addr, err := rec.GetAddress()
	if err != nil {
		panic(err)
	}
	ecfg := encoding.MakeConfig(app.ModuleEncodingRegisters...)
	conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	signer, err := user.SetupSigner(context.TODO(), kr, conn, addr, ecfg)
	if err != nil {
		panic(err)
	}
	ns := namespace.MustNewV0([]byte("1234567890"))
	fmt.Println("namespace", len(ns.Bytes()))

	blob, err := blobtypes.NewBlob(ns, []byte("hello world"), appconsts.ShareVersionZero)
	if err != nil {
		panic(err)
	}

	gasLimit := blobtypes.DefaultEstimateGas([]uint32{uint32(len(blob.Data))})
	fmt.Println()
	//fee := float64(appconsts.DefaultMinGasPrice * float64(gasLimit))

	options := []user.TxOption{
		user.SetGasLimitAndFee(gasLimit, 0.003),
	}

	resp, err := signer.SubmitPayForBlob(context.TODO(), []*tmproto.Blob{blob}, options...)
	if err != nil {
		panic(err)
	}
	if resp.Code != 0 {
		fmt.Println(resp.Code, resp.Codespace, resp.RawLog)
	}
}

func verify(txHash string) error {
	txHashBz, err := hex.DecodeString(txHash)
	if err != nil {
		return fmt.Errorf("decode txHash faild: %s", err.Error())
	}

	logger := server.ZeroLogWrapper{
		Logger: zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger(),
	}

	trpc, err := http.New(rpcEndpoint, "/websocket")
	if err != nil {
		return fmt.Errorf("dial rpc failed: %s", err.Error())
	}
	//err = trpc.Start()
	//if err != nil {
	//	return fmt.Errorf("start rpc failed: %s", err.Error())
	//}
	//defer func(trpc *http.HTTP) {
	//	err := trpc.Stop()
	//	if err != nil {
	//		fmt.Printf("error closing connection: %s", err.Error())
	//	}
	//}(trpc)

	ctx := context.Background()

	tx, err := trpc.Tx(ctx, txHashBz, true)
	if err != nil {
		return err
	}
	// Log the start of the verification process
	logger.Info("verifying that the blob was committed to by Blobstream", "tx_hash", txHash, "height", tx.Height)

	blockRes, err := trpc.Block(ctx, &tx.Height)
	if err != nil {
		return err
	}

	blobShareRange, err := square.BlobShareRange(blockRes.Block.Txs.ToSliceOfBytes(), int(tx.Index), blobIndex, blockRes.Block.Header.Version.App)
	if err != nil {
		return err
	}

	// Log the start of the proof generation process
	logger.Info(
		"proving shares inclusion to data root",
		"height",
		tx.Height,
		"start_share",
		blobShareRange.Start,
		"end_share",
		blobShareRange.End,
	)

	logger.Debug("getting shares proof from tendermint node")
	sharesProofs, err := trpc.ProveShares(ctx, uint64(tx.Height), uint64(blobShareRange.Start), uint64(blobShareRange.End))
	if err != nil {
		return err
	}

	logger.Debug("verifying shares proofs")
	if !sharesProofs.VerifyProof() {
		logger.Info("proofs from shares to data root are invalid")
		return err
	}

	logger.Info("proofs from shares to data root are valid")

	bsGrpc, err := grpc.Dial(celesGRPC, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer func(bsGrpc *grpc.ClientConn) {
		err := bsGrpc.Close()
		if err != nil {
			logger.Debug("error closing connection", "err", err.Error())
		}
	}(bsGrpc)

	queryClient := types.NewQueryClient(bsGrpc)
	resp, err := queryClient.DataCommitmentRangeForHeight(ctx, &types.QueryDataCommitmentRangeForHeightRequest{
		Height: uint64(tx.Height),
	})
	if err != nil {
		return err
	}

	logger.Info(
		"proving that the data root was committed to in the Blobstream contract",
		"contract_address",
		contractAddr,
		"first_block",
		resp.DataCommitment.BeginBlock,
		"last_block",
		resp.DataCommitment.EndBlock,
		"nonce",
		resp.DataCommitment.Nonce,
	)

	dcProof, err := trpc.DataRootInclusionProof(ctx, uint64(tx.Height), resp.DataCommitment.BeginBlock, resp.DataCommitment.EndBlock)
	if err != nil {
		return err
	}

	contractAddress := ethcmn.HexToAddress(contractAddr)

	ethClient, err := ethclient.Dial(evmRPC)
	if err != nil {
		return err
	}
	defer ethClient.Close()

	bsWrapper, err := wrapper.NewWrappers(contractAddress, ethClient)
	if err != nil {
		return err
	}

	logger.Info("verifying that the data root was committed to in the Blobstream contract")
	isCommittedTo, err := VerifyDataRootInclusion(
		ctx,
		bsWrapper,
		resp.DataCommitment.Nonce,
		uint64(tx.Height),
		blockRes.Block.DataHash,
		dcProof.Proof,
	)

	if isCommittedTo {
		logger.Info("the Blobstream contract has committed to the provided shares")
	} else {
		logger.Info("the Blobstream contract didn't commit to the provided shares")
	}

	return nil
}

func VerifyDataRootInclusion(
	_ context.Context,
	bsWrapper *wrapper.Wrappers,
	nonce uint64,
	height uint64,
	dataRoot []byte,
	proof merkle.Proof,
) (bool, error) {
	tuple := wrapper.DataRootTuple{
		Height:   big.NewInt(int64(height)),
		DataRoot: *(*[32]byte)(dataRoot),
	}

	sideNodes := make([][32]byte, len(proof.Aunts))
	for i, aunt := range proof.Aunts {
		sideNodes[i] = *(*[32]byte)(aunt)
	}
	wrappedProof := wrapper.BinaryMerkleProof{
		SideNodes: sideNodes,
		Key:       big.NewInt(proof.Index),
		NumLeaves: big.NewInt(proof.Total),
	}

	valid, err := bsWrapper.VerifyAttestation(
		&bind.CallOpts{},
		big.NewInt(int64(nonce)),
		tuple,
		wrappedProof,
	)
	if err != nil {
		return false, err
	}
	return valid, nil
}
