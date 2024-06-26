package eth

import (
	"bytes"
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/filters"
	"github.com/ethereum/go-ethereum/rlp"
	ethrpc "github.com/ethereum/go-ethereum/rpc"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/callformat"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/config"
	sdkSignature "github.com/oasisprotocol/oasis-sdk/client-sdk/go/crypto/signature"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/crypto/signature/secp256k1"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/helpers"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/accounts"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/core"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/evm"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"

	"github.com/oasisprotocol/oasis-web3-gateway/archive"
	"github.com/oasisprotocol/oasis-web3-gateway/conf"
	"github.com/oasisprotocol/oasis-web3-gateway/gas"
	"github.com/oasisprotocol/oasis-web3-gateway/indexer"
	"github.com/oasisprotocol/oasis-web3-gateway/rpc/utils"
)

func estimateGasDummySigSpec() types.SignatureAddressSpec {
	pk := sha512.Sum512_256([]byte("estimateGas: dummy sigspec"))
	signer := secp256k1.NewSigner(pk[:])
	return types.NewSignatureAddressSpecSecp256k1Eth(signer.Public().(secp256k1.PublicKey))
}

var (
	ErrInternalError        = errors.New("internal error")
	ErrIndexOutOfRange      = errors.New("index out of range")
	ErrMalformedTransaction = errors.New("malformed transaction")
	ErrMalformedBlockNumber = errors.New("malformed blocknumber")
	ErrInvalidRequest       = errors.New("invalid request")

	// estimateGasSigSpec is a dummy signature spec used by the estimate gas method, as
	// otherwise transactions without signature would be underestimated.
	estimateGasSigSpec = estimateGasDummySigSpec()
)

const (
	revertErrorPrefix = "reverted: "
)

// API is the eth_ prefixed set of APIs in the Web3 JSON-RPC spec.
type API interface {
	// GetBlockByNumber returns the block identified by number.
	GetBlockByNumber(ctx context.Context, blockNum ethrpc.BlockNumber, fullTx bool) (map[string]interface{}, error)
	// GetBlockTransactionCountByNumber returns the number of transactions in the block.
	GetBlockTransactionCountByNumber(ctx context.Context, blockNum ethrpc.BlockNumber) (hexutil.Uint, error)
	// GetStorageAt returns the storage value at the provided position.
	GetStorageAt(ctx context.Context, address common.Address, position hexutil.Big, blockNrOrHash ethrpc.BlockNumberOrHash) (hexutil.Big, error)
	// GetBalance returns the provided account's balance up to the provided block number.
	GetBalance(ctx context.Context, address common.Address, blockNrOrHash ethrpc.BlockNumberOrHash) (*hexutil.Big, error)
	// ChainId return the EIP-155 chain id for the current network.
	ChainId() (*hexutil.Big, error)
	// GasPrice returns a suggestion for a gas price for legacy transactions.
	GasPrice(ctx context.Context) (*hexutil.Big, error)
	FeeHistory(ctx context.Context, blockCount hexutil.Uint, unresolvedLastBlock ethrpc.BlockNumber, rewardPercentiles []float64) (map[string]interface{}, error)
	// GetBlockTransactionCountByHash returns the number of transactions in the block identified by hash.
	GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) (hexutil.Uint, error)
	// GetTransactionCount returns the number of transactions the given address has sent for the given block number.
	GetTransactionCount(ctx context.Context, ethAddr common.Address, blockNrOrHash ethrpc.BlockNumberOrHash) (*hexutil.Uint64, error)
	// GetCode returns the contract code at the given address and block number.
	GetCode(ctx context.Context, address common.Address, blockNrOrHash ethrpc.BlockNumberOrHash) (hexutil.Bytes, error)
	// Call executes the given transaction on the state for the given block number.
	Call(ctx context.Context, args utils.TransactionArgs, blockNrOrHash ethrpc.BlockNumberOrHash, _ *utils.StateOverride) (hexutil.Bytes, error)
	// SendRawTransaction send a raw Ethereum transaction.
	SendRawTransaction(ctx context.Context, data hexutil.Bytes) (common.Hash, error)
	// EstimateGas returns an estimate of gas usage for the given transaction.
	EstimateGas(ctx context.Context, args utils.TransactionArgs, blockNum *ethrpc.BlockNumber) (hexutil.Uint64, error)
	// GetBlockByHash returns the block identified by hash.
	GetBlockByHash(ctx context.Context, blockHash common.Hash, fullTx bool) (map[string]interface{}, error)
	// GetTransactionByHash returns the transaction identified by hash.
	GetTransactionByHash(ctx context.Context, hash common.Hash) (*utils.RPCTransaction, error)
	// GetTransactionByBlockHashAndIndex returns the transaction for the given block hash and index.
	GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (*utils.RPCTransaction, error)
	// GetTransactionByBlockNumberAndIndex returns the transaction identified by number and index.
	GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNum ethrpc.BlockNumber, index hexutil.Uint) (*utils.RPCTransaction, error)
	// GetTransactionReceipt returns the transaction receipt by hash.
	GetTransactionReceipt(ctx context.Context, txHash common.Hash) (map[string]interface{}, error)
	// GetLogs returns the ethereum logs.
	GetLogs(ctx context.Context, filter filters.FilterCriteria) ([]*ethtypes.Log, error)
	// GetBlockHash returns the block hash by the given number.
	GetBlockHash(ctx context.Context, blockNum ethrpc.BlockNumber, _ bool) (common.Hash, error)
	// BlockNumber returns the latest block number.
	BlockNumber(ctx context.Context) (hexutil.Uint64, error)
	// Accounts returns the list of accounts available to this node.
	Accounts() ([]common.Address, error)
	// Mining returns whether or not this node is currently mining.
	Mining() bool
	// Hashrate returns the current node's hashrate.
	Hashrate() hexutil.Uint64
	// Syncing returns false in case the node is currently not syncing with the network, otherwise
	// returns syncing information.
	Syncing(ctx context.Context) (interface{}, error)

	// showproposal [ID], Show proposal information with proposal ID, latest proposal is output by default
	ManagestShowProposal(ctx context.Context, proposalID hexutil.Uint) (map[string]interface{}, error)
	// showroles [role]", Show accounts of specific roles, including Admin, MintProposer, MintVoter etc.
	ManagestShowRoles(ctx context.Context, roleStr string) (map[string]interface{}, error)
	// showquorums [action], Show quorums of different actions, including Mint, Burn, SetRoles, Config, etc.
	ManagestShowQuorums(ctx context.Context, actionStr string) (map[string]interface{}, error)

	// Initialize addresses with roles, Init owners by chain_initiator only one time, roles are [Admin, MintProposer, MintVoter, ...].
	// managestInitOwners

	// propose <proposal.json>, Propose a new proposal with content from a JSON file
	ManagestProposalPreparing(ctx context.Context, address common.Address, data hexutil.Bytes) (map[string]interface{}, error)
	// vote <proposalID> <option>, Vote the proposal with options of YES, NO and ABSTAIN.
	ManagestVotePreparing(ctx context.Context, address common.Address, proposalID hexutil.Uint, optionStr string) (map[string]interface{}, error)
	// send a signed runtime transaction
	ManagestSendTransaction(ctx context.Context, optionStr string) (map[string]interface{}, error)
}

type publicAPI struct {
	client         client.RuntimeClient
	archiveClient  *archive.Client
	backend        indexer.Backend
	gasPriceOracle gas.Backend
	chainID        uint32
	Logger         *logging.Logger
	methodLimits   *conf.MethodLimits
}

// NewPublicAPI creates an instance of the public ETH Web3 API.
func NewPublicAPI(
	client client.RuntimeClient,
	archiveClient *archive.Client,
	logger *logging.Logger,
	chainID uint32,
	backend indexer.Backend,
	gasPriceOracle gas.Backend,
	methodLimits *conf.MethodLimits,
) API {
	return &publicAPI{
		client:         client,
		archiveClient:  archiveClient,
		chainID:        chainID,
		Logger:         logger,
		backend:        backend,
		gasPriceOracle: gasPriceOracle,
		methodLimits:   methodLimits,
	}
}

// handleStorageError handles the internal storage errors.
func handleStorageError(logger *logging.Logger, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		// By web3 spec an empty response should be returned if the queried block, transaction
		// is not existing.
		logger.Debug("no results found", "err", err)
		return nil
	}
	logger.Error("internal storage error", "err", err)
	return ErrInternalError
}

func (api *publicAPI) shouldQueryArchive(n uint64) bool {
	// If there is no archive node configured, return false.
	if api.archiveClient == nil {
		return false
	}

	return n <= api.archiveClient.LatestBlock()
}

// roundParamFromBlockNum converts special BlockNumber values to the corresponding special round numbers.
func (api *publicAPI) roundParamFromBlockNum(ctx context.Context, logger *logging.Logger, blockNum ethrpc.BlockNumber) (uint64, error) {
	switch blockNum {
	case ethrpc.PendingBlockNumber:
		// Oasis does not expose a pending block. Use the latest.
		return client.RoundLatest, nil
	case ethrpc.LatestBlockNumber:
		return client.RoundLatest, nil
	case ethrpc.EarliestBlockNumber:
		var earliest uint64
		clrBlk, err := api.client.GetLastRetainedBlock(ctx)
		if err != nil {
			logger.Error("failed to get last retained block from client", "err", err)
			return 0, ErrInternalError
		}
		ilrRound, err := api.backend.QueryLastRetainedRound(ctx)
		if err != nil {
			logger.Error("failed to get last retained block from indexer", "err", err)
			return 0, ErrInternalError
		}
		if clrBlk.Header.Round < ilrRound {
			earliest = ilrRound
		} else {
			earliest = clrBlk.Header.Round
		}
		return earliest, nil
	default:
		if int64(blockNum) < 0 {
			logger.Debug("malformed block number", "block_number", blockNum)
			return 0, ErrMalformedBlockNumber
		}

		return uint64(blockNum), nil
	}
}

func (api *publicAPI) GetBlockByNumber(ctx context.Context, blockNum ethrpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	logger := api.Logger.With("method", "eth_getBlockByNumber", "block_number", blockNum, "full_tx", fullTx)
	logger.Debug("request")

	round, err := api.roundParamFromBlockNum(ctx, logger, blockNum)
	if err != nil {
		return nil, err
	}

	blk, err := api.backend.GetBlockByRound(ctx, round)
	if err != nil {
		return nil, handleStorageError(logger, err)
	}

	return utils.ConvertToEthBlock(blk, fullTx), nil
}

func (api *publicAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNum ethrpc.BlockNumber) (hexutil.Uint, error) {
	logger := api.Logger.With("method", "eth_getBlockTransactionCountByNumber", "block_number", blockNum)
	logger.Debug("request")

	round, err := api.roundParamFromBlockNum(ctx, logger, blockNum)
	if err != nil {
		return 0, err
	}
	n, err := api.backend.GetBlockTransactionCountByRound(ctx, round)
	if err != nil {
		return 0, handleStorageError(logger, err)
	}

	return hexutil.Uint(n), nil
}

func (api *publicAPI) GetStorageAt(ctx context.Context, address common.Address, position hexutil.Big, blockNrOrHash ethrpc.BlockNumberOrHash) (hexutil.Big, error) {
	logger := api.Logger.With("method", "eth_getStorageAt", "address", address, "position", position, "block_or_hash", blockNrOrHash)
	logger.Debug("request")

	round, err := api.getBlockRound(ctx, logger, blockNrOrHash)
	if err != nil {
		return hexutil.Big{}, err
	}
	if api.shouldQueryArchive(round) {
		return api.archiveClient.GetStorageAt(ctx, address, position, round)
	}

	// EVM module takes index as H256, which needs leading zeros.
	position256 := make([]byte, 32)
	// Unmarshalling to hexutil.Big rejects overlong inputs. Verify in `TestRejectOverlong`.
	position.ToInt().FillBytes(position256)

	ethmod := evm.NewV1(api.client)
	res, err := ethmod.Storage(ctx, round, address[:], position256)
	if err != nil {
		logger.Error("failed to query storage", "err", err)
		return hexutil.Big{}, ErrInternalError
	}
	// Some apps expect no leading zeros, so output as big integer.
	var resultBI big.Int
	resultBI.SetBytes(res)
	return hexutil.Big(resultBI), nil
}

func (api *publicAPI) GetBalance(ctx context.Context, address common.Address, blockNrOrHash ethrpc.BlockNumberOrHash) (*hexutil.Big, error) {
	logger := api.Logger.With("method", "eth_getBalance", "address", address, "block_or_hash", blockNrOrHash)
	logger.Debug("request")

	round, err := api.getBlockRound(ctx, logger, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	if api.shouldQueryArchive(round) {
		return api.archiveClient.GetBalance(ctx, address, round)
	}

	ethmod := evm.NewV1(api.client)
	res, err := ethmod.Balance(ctx, round, address[:])
	if err != nil {
		logger.Error("ethmod.Balance failed", "round", round, "err", err)
		return nil, ErrInternalError
	}

	return (*hexutil.Big)(res.ToBigInt()), nil
}

//nolint:revive,stylecheck
func (api *publicAPI) ChainId() (*hexutil.Big, error) {
	logger := api.Logger.With("method", "eth_chainId")
	logger.Debug("request")
	return (*hexutil.Big)(big.NewInt(int64(api.chainID))), nil
}

func (api *publicAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	logger := api.Logger.With("method", "eth_gasPrice")
	logger.Debug("request")

	return api.gasPriceOracle.GasPrice(), nil
}

func (api *publicAPI) FeeHistory(ctx context.Context, blockCount hexutil.Uint, unresolvedLastBlock ethrpc.BlockNumber, rewardPercentiles []float64) (map[string]interface{}, error) {
	logger := api.Logger.With("method", "eth_feeHistory")
	logger.Debug("request")

	resolvedRound, err := api.roundParamFromBlockNum(ctx, logger, unresolvedLastBlock)
	if err != nil {
		return nil, err
	}

	// GB: keep the same parameter name from ethclient.go/FeeHistory function.
	// rewardPercentiles is ignored, as the returned reward value will be set to 0 by default.
	// our ecosystem doesn't implement reward mechanism.
	indexBackend := api.backend
	return api.gasPriceOracle.FeeHistory(ctx, indexBackend, blockCount, resolvedRound, rewardPercentiles)
}

func (api *publicAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) (hexutil.Uint, error) {
	logger := api.Logger.With("method", "eth_getBlockTransactionCountByHash", "block_hash", blockHash.Hex())
	logger.Debug("request")

	n, err := api.backend.GetBlockTransactionCountByHash(ctx, blockHash)
	if err != nil {
		return 0, handleStorageError(logger, err)
	}

	return hexutil.Uint(n), nil
}

func (api *publicAPI) GetTransactionCount(ctx context.Context, ethAddr common.Address, blockNrOrHash ethrpc.BlockNumberOrHash) (*hexutil.Uint64, error) {
	logger := api.Logger.With("method", "eth_getBlockTransactionCount", "address", ethAddr, "block_or_hash", blockNrOrHash)
	logger.Debug("request")

	round, err := api.getBlockRound(ctx, logger, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	if api.shouldQueryArchive(round) {
		return api.archiveClient.GetTransactionCount(ctx, ethAddr, round)
	}

	accountsMod := accounts.NewV1(api.client)
	accountsAddr := types.NewAddressRaw(types.AddressV0Secp256k1EthContext, ethAddr[:])

	nonce, err := accountsMod.Nonce(ctx, round, accountsAddr)
	if err != nil {
		logger.Error("accounts.Nonce failed", "err", err)
		return nil, ErrInternalError
	}

	return (*hexutil.Uint64)(&nonce), nil
}

func (api *publicAPI) GetCode(ctx context.Context, address common.Address, blockNrOrHash ethrpc.BlockNumberOrHash) (hexutil.Bytes, error) {
	logger := api.Logger.With("method", "eth_getCode", "address", address, "block_or_hash", blockNrOrHash)
	logger.Debug("request")

	round, err := api.getBlockRound(ctx, logger, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	if api.shouldQueryArchive(round) {
		return api.archiveClient.GetCode(ctx, address, round)
	}

	ethmod := evm.NewV1(api.client)
	res, err := ethmod.Code(ctx, round, address[:])
	if err != nil {
		logger.Error("ethmod.Code failed", "err", err)
		return nil, err
	}

	return res, nil
}

type RevertError struct {
	error
	Reason string `json:"reason"`
}

// ErrorData returns the ABI encoded error reason.
func (e *RevertError) ErrorData() interface{} {
	return e.Reason
}

// NewRevertError returns an revert error with ABI encoded revert reason.
func (api *publicAPI) NewRevertError(revertErr error) *RevertError {
	// ABI encoded function.
	abiReason := []byte{0x08, 0xc3, 0x79, 0xa0} // Keccak256("Error(string)")

	// ABI encode the revert Reason string.
	revertReason := strings.TrimPrefix(revertErr.Error(), revertErrorPrefix)
	typ, _ := abi.NewType("string", "", nil)
	unpacked, err := (abi.Arguments{{Type: typ}}).Pack(revertReason)
	if err != nil {
		api.Logger.Error("failed to encode revert error", "revert_reason", revertReason, "err", err)
		return &RevertError{
			error: revertErr,
		}
	}
	abiReason = append(abiReason, unpacked...)

	return &RevertError{
		error:  revertErr,
		Reason: hexutil.Encode(abiReason),
	}
}

func (api *publicAPI) Call(ctx context.Context, args utils.TransactionArgs, blockNrOrHash ethrpc.BlockNumberOrHash, _ *utils.StateOverride) (hexutil.Bytes, error) {
	logger := api.Logger.With("method", "eth_call", "block_or_hash", blockNrOrHash)
	logger.Debug("request", "args", args)

	round, err := api.getBlockRound(ctx, logger, blockNrOrHash)
	if err != nil {
		return nil, err
	}
	if api.shouldQueryArchive(round) {
		return api.archiveClient.Call(ctx, args, round)
	}

	var (
		amount   = []byte{0}
		input    = []byte{}
		sender   = common.Address{1}
		gasPrice = []byte{1}
		// This gas cap should be enough for SimulateCall an ethereum transaction
		gas uint64 = 30_000_000
	)

	if args.To == nil {
		return []byte{}, errors.New("to address not specified")
	}
	if args.GasPrice != nil {
		gasPrice = args.GasPrice.ToInt().Bytes()
	}
	if args.Gas != nil {
		gas = uint64(*args.Gas)
	}
	if args.Value != nil {
		amount = args.Value.ToInt().Bytes()
	}
	if args.Data != nil {
		input = *args.Data
	}
	if args.From != nil {
		sender = *args.From
	}

	res, err := evm.NewV1(api.client).SimulateCall(
		ctx,
		round,
		gasPrice,
		gas,
		sender.Bytes(),
		args.To.Bytes(),
		amount,
		input,
	)
	if err != nil {
		if strings.HasPrefix(err.Error(), revertErrorPrefix) {
			revertErr := api.NewRevertError(err)
			logger.Debug("failed to execute SimulateCall, reverted", "err", err, "reason", revertErr.Reason)
			return nil, revertErr
		}
		logger.Debug("failed to execute SimulateCall", "err", err)
		return nil, err
	}

	logger.Debug("response", "args", args, "resp", res)

	return res, nil
}

func (api *publicAPI) SendRawTransaction(ctx context.Context, data hexutil.Bytes) (common.Hash, error) {
	logger := api.Logger.With("method", "eth_sendRawTransaction")
	logger.Debug("request", "length", len(data))

	// Decode the Ethereum transaction.
	ethTx := &ethtypes.Transaction{}
	if err := rlp.DecodeBytes(data, ethTx); err != nil {
		logger.Debug("failed to decode raw transaction data", "err", err)
		return common.Hash{}, ErrMalformedTransaction
	}

	// Generate an Ethereum transaction that is handled by the EVM module.
	utx := types.UnverifiedTransaction{
		Body: data,
		AuthProofs: []types.AuthProof{
			{Module: "evm.ethereum.v0"},
		},
	}

	err := api.client.SubmitTxNoWait(ctx, &utx)
	if err != nil {
		logger.Debug("failed to submit transaction", "err", err)
		return ethTx.Hash(), err
	}

	return ethTx.Hash(), nil
}

func (api *publicAPI) EstimateGas(ctx context.Context, args utils.TransactionArgs, blockNum *ethrpc.BlockNumber) (hexutil.Uint64, error) {
	logger := api.Logger.With("method", "eth_estimateGas", "block_number", blockNum)
	logger.Debug("request", "args", args)

	if args.From == nil {
		// This may make sense if from not specified
		args.From = &common.Address{}
	}
	if args.Value == nil {
		args.Value = (*hexutil.Big)(big.NewInt(0))
	}
	if args.Data == nil {
		args.Data = (*hexutil.Bytes)(&[]byte{})
	}

	ethTxValue := args.Value.ToInt().Bytes()
	ethTxData := args.Data

	var tx *types.Transaction
	round := client.RoundLatest
	if blockNum != nil {
		var err error
		round, err = api.roundParamFromBlockNum(ctx, logger, *blockNum)
		if err != nil {
			return 0, err
		}
	}
	if args.To == nil {
		// evm.create
		tx = evm.NewV1(api.client).Create(ethTxValue, *ethTxData).AppendAuthSignature(estimateGasSigSpec, 0).GetTransaction()
	} else {
		// evm.call
		tx = evm.NewV1(api.client).Call(args.To.Bytes(), ethTxValue, *ethTxData).AppendAuthSignature(estimateGasSigSpec, 0).GetTransaction()
	}

	var ethAddress [20]byte
	copy(ethAddress[:], args.From[:])
	gas, err := core.NewV1(api.client).EstimateGasForCaller(ctx, round, types.CallerAddress{EthAddress: &ethAddress}, tx, true)
	if err != nil {
		logger.Debug("failed", "err", err)
		return 0, err
	}

	logger.Debug("result", "gas", gas)

	return hexutil.Uint64(gas), nil
}

func (api *publicAPI) GetBlockByHash(ctx context.Context, blockHash common.Hash, fullTx bool) (map[string]interface{}, error) {
	logger := api.Logger.With("method", "eth_getBlockByHash", "block_hash", blockHash, "full_tx", fullTx)
	logger.Debug("request")

	blk, err := api.backend.GetBlockByHash(ctx, blockHash)
	if err != nil {
		return nil, handleStorageError(logger, err)
	}

	return utils.ConvertToEthBlock(blk, fullTx), nil
}

func (api *publicAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) (*utils.RPCTransaction, error) {
	logger := api.Logger.With("method", "eth_getTransactionByHash", "hash", hash)
	logger.Debug("request")

	dbTx, err := api.backend.QueryTransaction(ctx, hash)
	if err != nil {
		return nil, handleStorageError(logger, err)
	}

	return utils.NewRPCTransaction(dbTx), nil
}

func (api *publicAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (*utils.RPCTransaction, error) {
	logger := api.Logger.With("method", "eth_getTransactionByBlockHashAndIndex", "block_hash", blockHash, "index", index)
	logger.Debug("request")

	dbBlock, err := api.backend.GetBlockByHash(ctx, blockHash)
	if err != nil {
		return nil, handleStorageError(logger, err)
	}
	if l := uint(len(dbBlock.Transactions)); l <= uint(index) {
		logger.Debug("invalid block transaction index", "num_txs", l)
		return nil, ErrIndexOutOfRange
	}

	return utils.NewRPCTransaction(dbBlock.Transactions[index]), nil
}

func (api *publicAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNum ethrpc.BlockNumber, index hexutil.Uint) (*utils.RPCTransaction, error) {
	logger := api.Logger.With("method", "eth_getTransactionByNumberAndIndex", "block_number", blockNum, "index", index)
	logger.Debug("request")

	round, err := api.roundParamFromBlockNum(ctx, logger, blockNum)
	if err != nil {
		return nil, err
	}
	blockHash, err := api.backend.QueryBlockHash(ctx, round)
	if err != nil {
		return nil, handleStorageError(logger, err)
	}

	return api.GetTransactionByBlockHashAndIndex(ctx, blockHash, index)
}

func (api *publicAPI) GetTransactionReceipt(ctx context.Context, txHash common.Hash) (map[string]interface{}, error) {
	logger := api.Logger.With("method", "eth_getTransactionReceipt", "hash", txHash)
	logger.Debug("request")

	receipt, err := api.backend.GetTransactionReceipt(ctx, txHash)
	if err != nil {
		return nil, handleStorageError(logger, err)
	}

	return receipt, nil
}

// getStartEndRounds is a helper for fetching start and end rounds parameters.
func (api *publicAPI) getStartEndRounds(ctx context.Context, logger *logging.Logger, filter filters.FilterCriteria) (uint64, uint64, error) {
	if filter.BlockHash != nil {
		round, err := api.backend.QueryBlockRound(ctx, *filter.BlockHash)
		if err != nil {
			return 0, 0, fmt.Errorf("query block round: %w", err)
		}
		return round, round, nil
	}

	start := client.RoundLatest
	end := client.RoundLatest
	if filter.FromBlock != nil {
		round, err := api.roundParamFromBlockNum(ctx, logger, ethrpc.BlockNumber(filter.FromBlock.Int64()))
		if err != nil {
			return 0, 0, err
		}
		start = round
	}
	if filter.ToBlock != nil {
		round, err := api.roundParamFromBlockNum(ctx, logger, ethrpc.BlockNumber(filter.ToBlock.Int64()))
		if err != nil {
			return 0, 0, err
		}
		end = round
	}

	return start, end, nil
}

func (api *publicAPI) GetLogs(ctx context.Context, filter filters.FilterCriteria) ([]*ethtypes.Log, error) {
	logger := api.Logger.With("method", "eth_getLogs")
	logger.Debug("request", "filter", filter)

	startRoundInclusive, endRoundInclusive, err := api.getStartEndRounds(ctx, logger, filter)
	if err != nil {
		return nil, fmt.Errorf("error getting start and end rounds: %w", err)
	}

	if endRoundInclusive < startRoundInclusive {
		return nil, fmt.Errorf("%w: end round greater than start round", ErrInvalidRequest)
	}

	if limit := api.methodLimits.GetLogsMaxRounds; limit != 0 && endRoundInclusive-startRoundInclusive > limit {
		return nil, fmt.Errorf("%w: max allowed of rounds in logs query is: %d", ErrInvalidRequest, limit)
	}

	ethLogs := []*ethtypes.Log{}
	dbLogs, err := api.backend.GetLogs(ctx, startRoundInclusive, endRoundInclusive)
	if err != nil {
		logger.Error("failed to get logs", "err", err)
		return ethLogs, ErrInternalError
	}
	ethLogs = utils.DB2EthLogs(dbLogs)

	// Early return if no further filtering.
	if len(filter.Addresses) == 0 && len(filter.Topics) == 0 {
		logger.Debug("response", "rsp", ethLogs)
		return ethLogs, nil
	}

	filtered := make([]*ethtypes.Log, 0, len(ethLogs))
	for _, log := range ethLogs {
		// Filter by address.
		addressMatch := len(filter.Addresses) == 0
		for _, addr := range filter.Addresses {
			if bytes.Equal(addr[:], log.Address[:]) {
				addressMatch = true
				break
			}
		}
		if !addressMatch {
			continue
		}

		// Filter by topics.
		if !utils.TopicsMatch(log, filter.Topics) {
			continue
		}

		// Log matched all filters.
		filtered = append(filtered, log)
	}

	logger.Debug("response", "rsp", filtered, "all_logs", ethLogs)
	return filtered, nil
}

func (api *publicAPI) GetBlockHash(ctx context.Context, blockNum ethrpc.BlockNumber, _ bool) (common.Hash, error) {
	logger := api.Logger.With("method", "eth_getBlockHash", "block_num", blockNum)
	logger.Debug("request")

	round, err := api.roundParamFromBlockNum(ctx, logger, blockNum)
	if err != nil {
		return [32]byte{}, err
	}
	return api.backend.QueryBlockHash(ctx, round)
}

func (api *publicAPI) BlockNumber(ctx context.Context) (hexutil.Uint64, error) {
	logger := api.Logger.With("method", "eth_getBlockNumber")
	logger.Debug("request")

	blockNumber, err := api.backend.BlockNumber(ctx)
	if err != nil {
		logger.Error("getting latest block number failed", "err", err)
		return 0, ErrInternalError
	}

	logger.Debug("response", "blockNumber", blockNumber)

	return hexutil.Uint64(blockNumber), nil
}

func (api *publicAPI) Accounts() ([]common.Address, error) {
	logger := api.Logger.With("method", "eth_getAccounts")
	logger.Debug("request")

	addresses := make([]common.Address, 0)
	return addresses, nil
}

func (api *publicAPI) Mining() bool {
	logger := api.Logger.With("method", "eth_mining")
	logger.Debug("request")
	return false
}

func (api *publicAPI) Hashrate() hexutil.Uint64 {
	logger := api.Logger.With("method", "eth_hashrate")
	logger.Debug("request")
	return 0
}

func (api *publicAPI) Syncing(ctx context.Context) (interface{}, error) {
	logger := api.Logger.With("method", "eth_syncing")
	logger.Debug("request")

	return false, nil
}

// getBlockRound returns the block round from BlockNumberOrHash.
func (api *publicAPI) getBlockRound(ctx context.Context, logger *logging.Logger, blockNrOrHash ethrpc.BlockNumberOrHash) (uint64, error) {
	switch {
	// case if block number and blockhash is specified are handling by the BlockNumberOrHash type.
	case blockNrOrHash.BlockHash == nil && blockNrOrHash.BlockNumber == nil:
		return 0, fmt.Errorf("types BlockHash and BlockNumber cannot be both nil")
	case blockNrOrHash.BlockHash != nil:
		return api.backend.QueryBlockRound(ctx, *blockNrOrHash.BlockHash)
	case blockNrOrHash.BlockNumber != nil:
		return api.roundParamFromBlockNum(ctx, logger, *blockNrOrHash.BlockNumber)
	default:
		return 0, nil
	}
}

// showproposal [ID], Show proposal information with proposal ID, latest proposal is output by default
func (api *publicAPI) ManagestShowProposal(ctx context.Context, proposalID hexutil.Uint) (map[string]interface{}, error) {

	logger := api.Logger.With("method", "eth_managestShowProposal")
	logger.Debug("request", "Proposal ID", proposalID)

	round := client.RoundLatest
	accountsMod := accounts.NewV1(api.client)
	proID := uint32(proposalID)
	if proID == uint32(0) {
		prodID, err := accountsMod.ProposalIDInfo(ctx, round)
		if err != nil {
			return nil, err
		}
		proID = prodID
	}

	proposal, err := accountsMod.ProposalInfo(ctx, round, proID)
	if err != nil {
		return nil, err
	}

	proposalInfo := make(map[string]interface{})
	info := ""
	if proposal.Content.Action != types.NoAction {
		if proposal.Content.Action != types.NoAction {
			info = fmt.Sprintf("Proposal ID: %d\n", proposal.ID)
			info += fmt.Sprintf("Proposal Submitter: %s\n", proposal.Submitter.String())
			info += fmt.Sprintf("Proposal State: %s\n", proposal.State.String())
			info += fmt.Sprintf("Proposal Content:\n")
			contentStr, err := proposal.Content.String()
			if err != nil {
				return nil, err
			}
			for key, value := range contentStr {
				info += fmt.Sprintf("    %s: %s\n", key, value)
			}

			if len(proposal.Results) > 0 {
				info += fmt.Sprintln("Results:")
				for vote, count := range proposal.Results {
					info += fmt.Sprintf("    Vote: %s, Count: %d\n", vote.String(), count)
				}
			}
		}
	}

	proposalInfo["proposal info"] = info
	return proposalInfo, nil

}

// showroles [role]", Show accounts of specific roles, including Admin, MintProposer, MintVoter etc.
func (api *publicAPI) ManagestShowRoles(ctx context.Context, roleStr string) (map[string]interface{}, error) {
	logger := api.Logger.With("method", "eth_managestShowRoles")
	logger.Debug("request", "Role", roleStr)

	round := client.RoundLatest
	accountsMod := accounts.NewV1(api.client)

	roleAddresses := make(map[string]interface{})
	info := ""
	if roleStr != "" {
		role, err := types.RoleFromString(roleStr)
		if err != nil {
			return nil, err
		}

		addrs, err := accountsMod.RolesTeam(ctx, round, role)
		if len(addrs) > 0 {
			info = fmt.Sprintf("%s: %s\n", roleStr, addrs)
		}
	} else {
		for role := types.Admin; role < types.User; role++ {
			addrs, err := accountsMod.RolesTeam(ctx, round, role)
			if err != nil {
				return nil, err
			}
			if len(addrs) > 0 {
				info += fmt.Sprintf("%s: %s\n", role.String(), addrs)
			}
		}
	}
	roleAddresses["role"] = info
	return roleAddresses, nil
}

// showquorums [action], Show quorums of different actions, including Mint, Burn, SetRoles, Config, etc.
func (api *publicAPI) ManagestShowQuorums(ctx context.Context, actionStr string) (map[string]interface{}, error) {

	logger := api.Logger.With("method", "eth_managestShowQuorums")
	logger.Debug("request", "Action", actionStr)
	round := client.RoundLatest
	accountsMod := accounts.NewV1(api.client)

	quorums := make(map[string]interface{})
	info := ""

	if actionStr != "" {
		action, err := types.ActionFromString(actionStr)
		if err != nil {
			return nil, err
		}

		quorum, err := accountsMod.Quorums(ctx, round, action)
		if quorum != 0 {
			info = fmt.Sprintf("%s: %d%%\n", actionStr, quorum)
		}
	} else {
		for action := types.SetRoles; action <= types.Config; action++ {
			quorum, err := accountsMod.Quorums(ctx, round, action)
			if err != nil {
				return nil, err
			}
			if quorum != 0 {
				info += fmt.Sprintf("%s: %d%%\n", action.String(), quorum)
			}
		}
	}
	quorums["quorum"] = info
	return quorums, nil

}

// propose <proposal.json>, Propose a new proposal with content from a JSON file
func (api *publicAPI) ManagestProposalPreparing(ctx context.Context, ethAddr common.Address, data hexutil.Bytes) (map[string]interface{}, error) {
	logger := api.Logger.With("method", "eth_managestProposalPreparing")
	logger.Debug("response", "Address", ethAddr, "data", data)
	result := make(map[string]interface{})

	accountsMod := accounts.NewV1(api.client)
	accountsAddr := types.NewAddressRaw(types.AddressV0Secp256k1EthContext, ethAddr[:])

	var raw json.RawMessage
	tmp := struct {
		Action string           `json:"action"`
		Data   *json.RawMessage `json:"data"`
	}{Data: &raw}

	err := json.Unmarshal(data, &tmp)

	if err != nil {
		logger.Error("proposal data unMarshall failed", "err", err)
		return nil, err
	}

	logger.Debug("proposal", tmp)
	action, err := types.ActionFromString(tmp.Action)
	if err != nil {
		logger.Error("invalid action for proposal", "err", err)
		return nil, err
	}

	// GB: take the input string to dataStr structure.
	var proposalDataStr *types.ProposalDataStr
	err = json.Unmarshal(raw, &proposalDataStr)
	if err != nil {
		logger.Error("proposalData invalid", "err", err)
		return nil, err
	}

	var proposalData types.ProposalData
	switch action {
	case types.Mint, types.Burn:
		if proposalDataStr.Role != nil ||
			proposalDataStr.MintQuorum != nil || proposalDataStr.BurnQuorum != nil ||
			proposalDataStr.BlacklistQuorum != nil || proposalDataStr.ConfigQuorum != nil {
			logger.Error("invalid input for proposal", "err", err)
		}

		addr, _, err := helpers.ResolveEthOrOasisAddress(*proposalDataStr.Address)
		if err != nil {
			logger.Error("address invalid", "err", err)
			return nil, err
		}

		runtimeID, err := api.client.GetInfo(ctx)
		if err != nil {
			logger.Error("runtimeInfo", "err", err)
			return nil, err
		}
		net := config.Network{
			ParaTimes: config.ParaTimes{
				All: map[string]*config.ParaTime{
					"hela_evm": {
						Description: "hela_evm",
						ID:          runtimeID.ID.String(),
						Denominations: map[string]*config.DenominationInfo{"_": {Decimals: 18,
							Symbol: "HLUSD"}},
					},
				},
			},
		}

		amtBaseUnits, err := helpers.ParseParaTimeDenomination(net.ParaTimes.All["hela_evm"], *proposalDataStr.Amount, types.NativeDenomination)
		if err != nil {
			logger.Error("amount invalid", "err", err)
			return nil, err
		}

		metadata, err := types.StringToMeta(proposalDataStr.Meta)
		if err != nil {
			logger.Error("metadata invalid", "err", err)
			return nil, err
		}

		proposalData = types.ProposalData{
			Address: addr,
			Amount:  amtBaseUnits,
			Meta:    metadata,
		}

	case types.SetRoles:
		if proposalDataStr.Amount != nil ||
			proposalDataStr.MintQuorum != nil || proposalDataStr.BurnQuorum != nil ||
			proposalDataStr.BlacklistQuorum != nil || proposalDataStr.ConfigQuorum != nil {
			logger.Error("invalid input for proposal", "err", err)
		}

		addr, _, err := helpers.ResolveEthOrOasisAddress(*proposalDataStr.Address)
		if err != nil {
			logger.Error("address invalid", "err", err)
			return nil, err
		}
		role, err := types.RoleFromString(*proposalDataStr.Role)
		if err != nil {
			logger.Error("role invalid", "err", err)
			return nil, err
		}

		proposalData = types.ProposalData{
			Address: addr,
			Role:    &role,
		}

	case types.Whitelist, types.Blacklist:
		if proposalDataStr.Role != nil || proposalDataStr.Amount != nil ||
			proposalDataStr.MintQuorum != nil || proposalDataStr.BurnQuorum != nil ||
			proposalDataStr.BlacklistQuorum != nil || proposalDataStr.ConfigQuorum != nil {
			logger.Error("invalid input for proposal", "err", err)
		}

		addr, _, err := helpers.ResolveEthOrOasisAddress(*proposalDataStr.Address)
		if err != nil {
			logger.Error("address invalid", "err", err)
			return nil, err
		}

		proposalData = types.ProposalData{
			Address: addr,
		}

	case types.Config:
		if proposalDataStr.Amount != nil || proposalDataStr.Address != nil {
			logger.Error("invalid input for proposal", "err", err)
		}

		proposalData = types.ProposalData{
			MintQuorum:      proposalDataStr.MintQuorum,
			BurnQuorum:      proposalDataStr.BurnQuorum,
			WhitelistQuorum: proposalDataStr.WhitelistQuorum,
			BlacklistQuorum: proposalDataStr.BlacklistQuorum,
			ConfigQuorum:    proposalDataStr.ConfigQuorum,
		}

	default:
		logger.Error("invalid action for proposal", "err", err)
		return nil, err
	}

	// Prepare transaction.
	proposal := &accounts.ProposalContent{
		Action: action,
		Data:   proposalData,
	}
	tx := accounts.NewProposeTx(nil, proposal)

	nonce, err := accountsMod.Nonce(ctx, client.RoundLatest, accountsAddr)
	if err != nil {
		logger.Error("accounts.Nonce failed", "err", err)
		return nil, ErrInternalError
	}

	tx.AppendAuthSignature(estimateGasDummySigSpec(), nonce)
	tx.AuthInfo.Fee.Gas = 10_1000
	tx.AuthInfo.Fee.Amount = types.NewBaseUnits(*quantity.NewFromUint64(0), types.NativeDenomination)
	cborTx := cbor.Marshal(tx)
	result["cborTx"] = cborTx

	return result, nil
}

// vote <proposalID> <option>, Vote the proposal with options of YES, NO and ABSTAIN.
func (api *publicAPI) ManagestVotePreparing(ctx context.Context, ethAddr common.Address, proposalID hexutil.Uint, optionStr string) (map[string]interface{}, error) {

	logger := api.Logger.With("method", "eth_managestVotePreparing")
	logger.Debug("response", "Address", ethAddr, "Proposal ID", proposalID, "Option", optionStr)
	result := make(map[string]interface{})

	accountsMod := accounts.NewV1(api.client)
	accountsAddr := types.NewAddressRaw(types.AddressV0Secp256k1EthContext, ethAddr[:])

	proID := uint32(proposalID)
	lowercaseOption := strings.ToLower(optionStr)
	voteOp, err := types.StringToVote(lowercaseOption)
	if err != nil {
		return nil, err
	}

	// Prepare transaction.
	tx := accounts.NewVoteSTTx(nil, &accounts.VoteProposal{
		ID:     proID,
		Option: voteOp,
	})

	nonce, err := accountsMod.Nonce(ctx, client.RoundLatest, accountsAddr)
	if err != nil {
		logger.Error("accounts.Nonce failed", "err", err)
		return nil, ErrInternalError
	}

	tx.AppendAuthSignature(estimateGasDummySigSpec(), nonce)
	tx.AuthInfo.Fee.Gas = 10_1000
	tx.AuthInfo.Fee.Amount = types.NewBaseUnits(*quantity.NewFromUint64(0), types.NativeDenomination)
	cborTx := cbor.Marshal(tx)
	result["cborTx"] = cborTx

	return result, nil
}

// send a signed runtime transaction
func (api *publicAPI) ManagestSendTransaction(ctx context.Context, optionStr string) (map[string]interface{}, error) {

	logger := api.Logger.With("method", "eth_managestSendTransaction")
	logger.Debug("Signed Transaction", optionStr)
	result := make(map[string]interface{})

	var utx types.UnverifiedTransaction
	utxStr, _ := base64.StdEncoding.DecodeString(optionStr)

	if err := cbor.Unmarshal([]byte(utxStr), &utx); err != nil {
		logger.Error("failed to unmarshal signed transaction", "err", err)
		return nil, err
	}

	logger.Info("Broadcasting transaction...\n")
	rawMeta, err := api.client.SubmitTxRawMeta(ctx, &utx)
	if err != nil {
		logger.Error("failed to SubmitTxRawMeta signed transaction", "err", err)
		return nil, err
	}
	if rawMeta.CheckTxError != nil {
		logger.Error("Transaction check failed with error: module:  code:  message: ",
			rawMeta.CheckTxError.Module,
			rawMeta.CheckTxError.Code,
			rawMeta.CheckTxError.Message,
		)
		return nil, fmt.Errorf("Transaction check failed with error: %s, %d %s", rawMeta.CheckTxError.Module,
			rawMeta.CheckTxError.Code, rawMeta.CheckTxError.Message)
	}

	logger.Debug("Transaction included in block successfully.\n Round: hash:", rawMeta.Round, utx.Hash().Hex())

	if rawMeta.Result.IsUnknown() {
		logger.Debug("    Transaction result is encrypted.\n")
	}

	decResult, err := callformat.DecodeResult(&rawMeta.Result, nil)
	if err != nil {
		logger.Error("failed to DecodeResult", "err", err)
		return nil, err
	}

	switch {
	case decResult.IsUnknown():
		// This should never happen as the inner result should not be unknown.
		logger.Debug("Execution result unknown: ", decResult.Unknown)
	case decResult.IsSuccess():
		logger.Debug("Execution successful.\n")
	default:
		logger.Debug("Execution failed with error: ", decResult.Failed.Error())
	}

	hash := utx.Hash().Hex()
	result["hash"] = hash

	return result, nil
}

func Secp256k1FromHex(text string) (sdkSignature.Signer, error) {
	text = strings.TrimPrefix(text, "0x")
	data, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}

	if len(data) != 32 {
		return nil, signature.ErrMalformedPrivateKey
	}

	return secp256k1.NewSigner(data), nil
}
