// Package gas implements a gas price oracle.
package gas

import (
	"context"
	"math"
	"math/big"
	"sync"
	"time"
	"fmt"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/modules/core"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/oasisprotocol/oasis-web3-gateway/db/model"
	"github.com/oasisprotocol/oasis-web3-gateway/indexer"
)

var (
	metricNodeMinPrice  = promauto.NewGauge(prometheus.GaugeOpts{Name: "oasis_oasis_web3_gateway_gas_orcale_node_min_price", Help: "Min gas price periodically queried from the node."})
	metricComputedPrice = promauto.NewGauge(prometheus.GaugeOpts{Name: "oasis_oasis_web3_gateway_gas_oracle_computed_price", Help: "Computed recommended gas price based on recent full blocks. -1 if none (no recent full blocks)."})
)

// Backend is the gas price oracle backend.
type Backend interface {
	service.BackgroundService

	// GasPrice returns the currently recommended minimum gas price.
	GasPrice() *hexutil.Big
	FeeHistory(ctx context.Context, indexBackend indexer.Backend, blocks hexutil.Uint, unresolvedRound uint64, rewardPercentiles []float64) (map[string]interface{}, error)
}

const (
	// windowSize is the number of recent blocks to use for calculating min gas price.
	// NOTE: code assumes that this is relatively small.
	windowSize = 12

	// fullBlockThreshold is the percentage of block used gas over which a block should
	// be considered full.
	fullBlockThreshold = 0.8

	// period for querying oasis node for minimum gas price.
	nodeMinGasPriceTimeout = 60 * time.Second

	// GB: max blocks can inquiry at a time
	maxHeaderWindow = 1024
	// maxBlockFetchers is the max number of goroutines to spin up to pull blocks
	// for the fee history calculation (mostly relevant for LES).
	maxBlockFetchers = 4

)

var (
	// minPriceEps is a constant added to the cheapest transaction executed in last windowSize blocks.
	minPriceEps = *quantity.NewFromUint64(1_000_000_000) // 1 "gwei".

	// defaultGasPrice is the default gas price reported if no better estimate can be returned.
	//
	// This is only returned when all calls to oasis-node for min gas price failed and there were no
	// full blocks in last `windowSize` blocks.
	defaultGasPrice = *quantity.NewFromUint64(100_000_000_000) // 100 "gwei".
)

// gasPriceOracle implements the gas price backend by looking at transaction costs in previous blocks.
//
// The gas price oracle does roughly:
// (a) Compute the recommended gas price based on recent blocks:
//   - look at the most recent block(s) (controlled by `windowSize` parameter)
//   - if block gas used is greater than some threshold, consider it "full" (controlled by `fullBlockThresholdParameter`)
//   - set recommended gas price to the lowest-priced transaction from the full blocks + a small constant (controlled by `minPriceEps`)
//
// (b) Query gas price configured on the oasis-node:
//   - periodically query the oasis-node for it's configured gas price
//
// Return the greater of the (a) and (b), default to a `defaultGasPrice `if neither are available.
type gasPriceOracle struct {
	service.BaseBackgroundService

	ctx       context.Context
	cancelCtx context.CancelFunc

	// protects nodeMinGasPrice and computedMinGasPrice.
	priceLock sync.RWMutex
	// nodeMinGasPrice is the minimum gas price as reported by the oasis node.
	// This is queried from the node and updated periodically.
	nodeMinGasPrice *quantity.Quantity
	// computedMinGasPrice is the computed min gas price by observing recent blocks.
	computedMinGasPrice *quantity.Quantity

	// blockPrices is a rolling-array containing minimum transaction prices for
	// last up to `windowSize` blocks.
	blockPrices []*quantity.Quantity
	// tracks the current index of the blockPrices rolling array.:w
	blockPricesCurrentIdx int

	blockWatcher indexer.BlockWatcher
	coreClient   core.V1

	// GB: the max blocks allowed to inquiry for feeHistory, [0, 1024] by default.
	maxHeaderHistory hexutil.Uint
}


// blockFees represents a single block for processing
type blockFees struct {
	// set by the caller
	blockNumber uint64
	header      *model.Header
	block       *model.Block // only set if reward percentiles are requested
	// filled by processBlock
	results processedFees
	err     error
}


type processedFees struct {
	reward               []*hexutil.Big
	baseFee, nextBaseFee *hexutil.Big
	gasUsedRatio         float64
}


func New(ctx context.Context, blockWatcher indexer.BlockWatcher, coreClient core.V1) Backend {
	ctxB, cancelCtx := context.WithCancel(ctx)
	g := &gasPriceOracle{
		BaseBackgroundService: *service.NewBaseBackgroundService("gas-price-oracle"),
		ctx:                   ctxB,
		cancelCtx:             cancelCtx,
		blockPrices:           make([]*quantity.Quantity, 0, windowSize),
		blockWatcher:          blockWatcher,
		coreClient:            coreClient,

		maxHeaderHistory:		maxHeaderWindow,
	}

	return g
}

// Start starts service.
func (g *gasPriceOracle) Start() error {
	go g.nodeMinGasPriceFetcher()
	go g.indexedBlockWatcher()

	return nil
}

// Stop stops service.
func (g *gasPriceOracle) Stop() {
	g.cancelCtx()
}

func (g *gasPriceOracle) GasPrice() *hexutil.Big {
	g.priceLock.RLock()
	defer g.priceLock.RUnlock()

	if g.computedMinGasPrice == nil && g.nodeMinGasPrice == nil {
		// No blocks tracked yet and no min gas price from the node,
		// default to a default value.
		price := hexutil.Big(*defaultGasPrice.ToBigInt())
		return &price
	}

	// Set minPrice to the larger of the `nodeMinGasPrice` and `computedMinGasPrice`.
	minPrice := quantity.NewQuantity()
	if g.nodeMinGasPrice != nil {
		minPrice = g.nodeMinGasPrice.Clone()
	}
	if g.computedMinGasPrice != nil && g.computedMinGasPrice.Cmp(minPrice) > 0 {
		minPrice = g.computedMinGasPrice.Clone()
		// Add small constant to the min price.
		if err := minPrice.Add(&minPriceEps); err != nil {
			g.Logger.Error("failed to add minPriceEps to minPrice", "err", err, "min_price", minPrice, "min_price_eps", minPriceEps)
			minPrice = &defaultGasPrice
		}
	}

	price := hexutil.Big(*minPrice.ToBigInt())
	return &price
}


func (g *gasPriceOracle) resolveBlockRange(ctx context.Context, indexBackend indexer.Backend, reqEndRound uint64, blockCount hexutil.Uint) (uint64, uint64, error) {
	var (
		reqEndBlkNum	uint64
		LatestBlkNum 	uint64
		err             error
	)

	switch reqEndRound {
	case client.RoundLatest:
		reqEndBlkNum, err = indexBackend.BlockNumber(ctx)
		if err != nil {
			g.Logger.Error("no results found", "err", err)
			return 0, 0, err
		}		
	default:
		reqEndBlkNum = reqEndRound
	}

	// Get the chain's current head.
	if LatestBlkNum, err = indexBackend.BlockNumber(ctx); err != nil {
		return 0, 0, err
	}

	// Fail if request block is beyond the chain's current head.
	if LatestBlkNum < reqEndBlkNum {
		return 0, 0, fmt.Errorf("request beyond head block: requested %d, head %d", reqEndBlkNum, LatestBlkNum)
	}

	// Ensure not trying to retrieve before genesis.
	blkcnt := uint64(blockCount)
	if uint64(reqEndBlkNum+1) < uint64(blockCount) {
		blkcnt = uint64(reqEndBlkNum + 1)
	}
	return reqEndBlkNum, blkcnt, nil
}



func stringToBig(str string) (*hexutil.Big) {
	bigInt := new(big.Int)
	_, success := bigInt.SetString(str, 10)
	if !success {
		return nil
	}
	return (*hexutil.Big)(bigInt)
}

// processBlock takes a blockFees structure with the blockNumber, the header and optionally
// the block field filled in, retrieves the block from the backend if not present yet and
// fills in the rest of the fields.
func (g *gasPriceOracle) processBlock(bf *blockFees, percentiles []float64) {
	if bf.results.baseFee = stringToBig(bf.header.BaseFee); bf.results.baseFee == nil {
		bf.results.baseFee = (*hexutil.Big)(new(big.Int))
	}

	// GB: define the nextBaseFee as the GasPrice, which is the minimum value of past 12 blocks.
	bf.results.nextBaseFee = g.GasPrice()

	bf.results.gasUsedRatio = float64(bf.header.GasUsed) / float64(bf.header.GasLimit)
	if len(percentiles) == 0 {
		// rewards were not requested, return null
		return
	}

	// GB: return 0 for all reward enquiried.
    bf.results.reward = make([]*hexutil.Big, len(percentiles))
	for i := range bf.results.reward {
		bf.results.reward[i] = (*hexutil.Big)(new(big.Int))
	}
	return
}


        
func (g *gasPriceOracle) FeeHistory(ctx context.Context, indexBackend indexer.Backend, blockCount hexutil.Uint, resolvedRound uint64, rewardPercentiles []float64) (map[string]interface{}, error) {
	if blockCount < 1 {
		return nil, nil // returning with no data and no error means there are no retrievable blocks
	}
	maxFeeHistory := g.maxHeaderHistory

	if blockCount > maxFeeHistory {
		g.Logger.Warn("Sanitizing fee history length", "requested", blockCount, "truncated", maxFeeHistory)
		blockCount = maxFeeHistory
	}

	lastBlock, blockWindow, err := g.resolveBlockRange(ctx, indexBackend, resolvedRound, blockCount)
	if err != nil || blockWindow == 0 {
		return nil, err
	}
	oldestBlock := lastBlock + 1 - blockWindow

	var next atomic.Uint64
	next.Store(oldestBlock)
	results := make(chan *blockFees, blockWindow)

	for i := 0; i < maxBlockFetchers && i < int(blockWindow); i++ {
		go func() {
			for {
				// Retrieve the next block number to fetch with this goroutine
				blockNumber := next.Add(1) - 1
				if blockNumber > lastBlock {
					return
				}

				fees := &blockFees{blockNumber: blockNumber}
				fees.block, fees.err = indexBackend.GetBlockByRound(ctx, blockNumber)
				fees.header = fees.block.Header
				g.processBlock(fees, rewardPercentiles)
				results <- fees
			}
		}()
	}


	var (
		reward       = make([][]*hexutil.Big, blockWindow)
		baseFee      = make([]*hexutil.Big, blockWindow+1)
		gasUsedRatio = make([]float64, blockWindow)
		firstMissing = blockWindow
	)
	for ; blockWindow > 0; blockWindow-- {
		fees := <-results
		if fees.err != nil {
			return nil, fees.err
		}
		i := fees.blockNumber - oldestBlock
		if fees.results.baseFee != nil {
			reward[i], baseFee[i], baseFee[i+1], gasUsedRatio[i] = fees.results.reward, fees.results.baseFee, fees.results.nextBaseFee, fees.results.gasUsedRatio
		} else {
			// getting no block and no error means we are requesting into the future (might happen because of a reorg)
			if i < firstMissing {
				firstMissing = i
			}
		}
	}
	if firstMissing == 0 {
		return nil, nil
	}
	if len(rewardPercentiles) != 0 {
		reward = reward[:firstMissing]
	} else {
		reward = nil
	}
	baseFee, gasUsedRatio = baseFee[:firstMissing+1], gasUsedRatio[:firstMissing]

	res := make(map[string]interface{})
	res["oldestBlock"] = oldestBlock
	res["reward"] = reward
	res["baseFeePerGas"] = baseFee
	res["gasUsedRatio"] = gasUsedRatio

	return res, nil

}


func (g *gasPriceOracle) nodeMinGasPriceFetcher() {
	for {
		// Fetch and update min gas price from the node.
		g.fetchMinGasPrice(g.ctx)

		select {
		case <-g.ctx.Done():
			return
		case <-time.After(nodeMinGasPriceTimeout):
		}
	}
}

func (g *gasPriceOracle) fetchMinGasPrice(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	mgp, err := g.coreClient.MinGasPrice(ctx)
	if err != nil {
		g.Logger.Error("node min gas price query failed", "err", err)
		return
	}
	// MZ
	// Fetch SUSD as gas fee
	price := mgp[types.NativeDenomination]

	g.priceLock.Lock()
	g.nodeMinGasPrice = &price
	g.priceLock.Unlock()

	metricNodeMinPrice.Set(float64(price.ToBigInt().Int64()))
}

func (g *gasPriceOracle) indexedBlockWatcher() {
	ch, sub, err := g.blockWatcher.WatchBlocks(g.ctx, windowSize)
	if err != nil {
		g.Logger.Error("indexed block watcher failed to watch blocks", "err", err)
		return
	}
	defer sub.Close()

	for {
		select {
		case <-g.ctx.Done():
			return
		case blk := <-ch:
			g.onBlock(blk.Block, blk.LastTransactionPrice)
		}
	}
}

func (g *gasPriceOracle) onBlock(b *model.Block, lastTxPrice *quantity.Quantity) {
	// Consider block full if block gas used is greater than `fullBlockThreshold` of gas limit.
	blockFull := (float64(b.Header.GasLimit) * fullBlockThreshold) <= float64(b.Header.GasUsed)
	if !blockFull {
		// Track 0 for non-full blocks.
		g.trackPrice(quantity.NewFromUint64(0))
		return
	}

	if lastTxPrice == nil {
		g.Logger.Error("no last tx gas price for block", "block", b)
		return
	}
	g.trackPrice(lastTxPrice)
}

func (g *gasPriceOracle) trackPrice(price *quantity.Quantity) {
	// One item always gets added to the prices array.
	// Bump the current index for next iteration.
	defer func() {
		g.blockPricesCurrentIdx = (g.blockPricesCurrentIdx + 1) % windowSize
	}()

	// Recalculate min-price over the block window.
	defer func() {
		minPrice := quantity.NewFromUint64(math.MaxUint64)
		// Find smallest non-zero gas price.
		for _, price := range g.blockPrices {
			if price.IsZero() {
				continue
			}
			if price.Cmp(minPrice) < 0 {
				minPrice = price
			}
		}

		// No full blocks among last `windowSize` blocks.
		if minPrice.Cmp(quantity.NewFromUint64(math.MaxUint64)) == 0 {
			g.priceLock.Lock()
			g.computedMinGasPrice = nil
			g.priceLock.Unlock()
			metricComputedPrice.Set(float64(-1))

			return
		}
		g.priceLock.Lock()
		g.computedMinGasPrice = minPrice
		g.priceLock.Unlock()
		metricComputedPrice.Set(float64(minPrice.ToBigInt().Int64()))
	}()

	if len(g.blockPrices) < windowSize {
		g.blockPrices = append(g.blockPrices, price)
		return
	}
	g.blockPrices[g.blockPricesCurrentIdx] = price
}
