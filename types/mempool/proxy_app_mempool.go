package mempool

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	cmtmempool "github.com/cometbft/cometbft/mempool"
	cmttypes "github.com/cometbft/cometbft/types"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/auth/signing"
)

var (
	_ ExtMempool = (*ProxyAppMempool)(nil)

	ErrSenderTxLimit = errors.New("sender reached max tx limit")
	ErrStaleNonce    = errors.New("tx nonce already executed")
)

const (
	DefaultMaxTxsPerSender = 16
	DefaultMaxTotalTxs     = 500
)

// TxBytesContextKey is used to pass raw tx bytes through context to the mempool.
type TxBytesContextKey struct{}

// EventReceiver is implemented by mempools that can receive CometBFT ProxyMempool event channel.
type EventReceiver interface {
	SetEventCh(ch chan<- cmtmempool.AppMempoolEvent)
}

// QueuePromoter is implemented by mempools that support promoting queued txs
// after a block commit. BaseApp calls this from its PrepareCheckStater hook.
type QueuePromoter interface {
	PromoteQueued(ctx context.Context)
}

// AccountKeeper provides the current account sequence from committed state.
type AccountKeeper interface {
	GetAccount(ctx context.Context, addr sdk.AccAddress) sdk.AccountI
}

// ProxyAppMempoolConfig holds configuration for the ProxyAppMempool.
type ProxyAppMempoolConfig struct {
	MaxTxsPerSender int
	MaxTotalTxs     int
}

// ProxyAppMempool is an application mempool that manages an active pool
// (txs with sequential nonces ready for proposal) and a queued pool (txs with
// future nonces waiting for predecessors). It pushes EventTxInserted /
// EventTxRemoved events to CometBFT ProxyMempool via an event channel.
type ProxyAppMempool struct {
	mu sync.RWMutex

	// active: txs with sequential nonces ready for proposal, keyed by sender
	senderActive map[string]*senderQueue
	activeCount  int

	// queued: txs with future nonces waiting for predecessors, keyed by sender
	senderQueued map[string]*senderQueue
	queuedCount  int

	// per-sender next expected nonce for the active pool
	senderNextNonce map[string]uint64

	// event channel to push to CometBFT ProxyMempool (set after node creation)
	eventCh chan<- cmtmempool.AppMempoolEvent

	ak        AccountKeeper
	txEncoder sdk.TxEncoder

	// Limits
	maxTxsPerSender int
	maxTotalTxs     int
}

// senderQueue holds transactions for a single sender, sorted by nonce ascending.
type senderQueue struct {
	txs []txEntry
}

// txEntry holds a transaction with its decoded metadata.
type txEntry struct {
	tx      sdk.Tx
	txBytes []byte
	nonce   uint64
	sender  string
}

// NewProxyAppMempool creates a new ProxyAppMempool with the given configuration.
func NewProxyAppMempool(
	cfg ProxyAppMempoolConfig,
	ak AccountKeeper,
	txEncoder sdk.TxEncoder,
) *ProxyAppMempool {
	if cfg.MaxTxsPerSender <= 0 {
		cfg.MaxTxsPerSender = DefaultMaxTxsPerSender
	}
	if cfg.MaxTotalTxs <= 0 {
		cfg.MaxTotalTxs = DefaultMaxTotalTxs
	}

	return &ProxyAppMempool{
		senderActive:    make(map[string]*senderQueue),
		senderQueued:    make(map[string]*senderQueue),
		senderNextNonce: make(map[string]uint64),
		ak:              ak,
		txEncoder:       txEncoder,
		maxTxsPerSender: cfg.MaxTxsPerSender,
		maxTotalTxs:     cfg.MaxTotalTxs,
	}
}

// SetAccountKeeper sets the account keeper. This is called
// after the AccountKeeper is created during app construction.
func (m *ProxyAppMempool) SetAccountKeeper(ak AccountKeeper) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ak = ak
}

// SetEventCh sets the event channel used to push events to CometBFT's
// ProxyMempool. Called after the CometBFT node is created.
func (m *ProxyAppMempool) SetEventCh(ch chan<- cmtmempool.AppMempoolEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.eventCh = ch
}

// Insert adds a transaction to the mempool. If the nonce matches the next
// expected for the sender, it goes into the active pool and an EventTxInserted
// is pushed. If the nonce is in the future, it goes into the queued pool.
// Stale nonces are rejected.
func (m *ProxyAppMempool) Insert(ctx context.Context, tx sdk.Tx) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sender, nonce, err := extractSenderNonce(tx)
	if err != nil {
		return err
	}

	// optimistically get raw tx bytes from context, should be set by baseapp
	txBytes, _ := ctx.Value(TxBytesContextKey{}).([]byte)
	if len(txBytes) == 0 && m.txEncoder != nil {
		txBytes, err = m.txEncoder(tx)
		if err != nil {
			return fmt.Errorf("failed to encode tx: %w", err)
		}
	}

	var accountSeq uint64
	if m.ak != nil {
		acc := m.ak.GetAccount(ctx, sdk.AccAddress(sender))
		if acc != nil {
			accountSeq = acc.GetSequence()
		}
	}

	nextExpected := accountSeq
	if active, ok := m.senderActive[sender]; ok && len(active.txs) > 0 {
		highestActiveNonce := active.txs[len(active.txs)-1].nonce
		if highestActiveNonce+1 > nextExpected {
			nextExpected = highestActiveNonce + 1
		}
	}

	// reject stale nonces
	if nonce < accountSeq {
		return ErrStaleNonce
	}

	// check for duplicate or replacement
	if entry, _ := m.findTx(sender, nonce); entry != nil {
		return fmt.Errorf("tx with sender %s and nonce %d already exists", sender, nonce)
	}

	// check per-sender limit
	senderCount := m.senderTxCount(sender)
	if senderCount >= m.maxTxsPerSender {
		// try to evict highest queued nonce if new tx has lower nonce
		if queued, ok := m.senderQueued[sender]; ok && len(queued.txs) > 0 {
			highestQueued := queued.txs[len(queued.txs)-1]
			if nonce < highestQueued.nonce {
				m.removeFromQueued(sender, highestQueued.nonce)
				m.pushEvent(cmtmempool.EventTxRemoved, highestQueued.txBytes)
			} else {
				return ErrSenderTxLimit
			}
		} else {
			return ErrSenderTxLimit
		}
	}

	if m.activeCount+m.queuedCount >= m.maxTotalTxs {
		return ErrMempoolTxMaxCapacity
	}

	entry := txEntry{
		tx:      tx,
		txBytes: txBytes,
		nonce:   nonce,
		sender:  sender,
	}

	if nonce == nextExpected {
		m.insertActive(sender, entry)
		m.senderNextNonce[sender] = nonce + 1
		m.pushEvent(cmtmempool.EventTxInserted, txBytes)

		m.promoteChain(sender, nonce+1)
	} else {
		m.insertQueued(sender, entry)
	}

	return nil
}

// Select returns an iterator over active pool txs.
func (m *ProxyAppMempool) Select(_ context.Context, _ [][]byte) Iterator {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var allTxs []sdk.Tx
	senders := m.sortedActiveSenders()

	cursors := make(map[string]int)
	for s := range m.senderActive {
		cursors[s] = 0
	}

	for {
		added := false
		for _, sender := range senders {
			active := m.senderActive[sender]
			idx := cursors[sender]
			if idx < len(active.txs) {
				allTxs = append(allTxs, active.txs[idx].tx)
				cursors[sender] = idx + 1
				added = true
			}
		}
		if !added {
			break
		}
	}

	if len(allTxs) == 0 {
		return nil
	}

	return &proxyAppMempoolIterator{
		txs: allTxs,
		idx: 0,
	}
}

// SelectBy iterates over active pool txs with a callback, holding the read lock.
func (m *ProxyAppMempool) SelectBy(_ context.Context, _ [][]byte, callback func(sdk.Tx) bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	senders := m.sortedActiveSenders()
	cursors := make(map[string]int)
	for s := range m.senderActive {
		cursors[s] = 0
	}

	for {
		added := false
		for _, sender := range senders {
			active := m.senderActive[sender]
			idx := cursors[sender]
			if idx < len(active.txs) {
				if !callback(active.txs[idx].tx) {
					return
				}
				cursors[sender] = idx + 1
				added = true
			}
		}
		if !added {
			break
		}
	}
}

// CountTx returns the total number of transactions in both active and queued pools.
func (m *ProxyAppMempool) CountTx() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.activeCount + m.queuedCount
}

// Remove removes a transaction from the active or queued pool and fires EventTxRemoved.
func (m *ProxyAppMempool) Remove(tx sdk.Tx) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sender, nonce, err := extractSenderNonce(tx)
	if err != nil {
		return err
	}

	entry, pool := m.findTx(sender, nonce)
	if entry == nil {
		return ErrTxNotFound
	}

	txBytes := entry.txBytes
	switch pool {
	case "active":
		m.removeFromActive(sender, nonce)
	case "queued":
		m.removeFromQueued(sender, nonce)
	}
	m.pushEvent(cmtmempool.EventTxRemoved, txBytes)

	return nil
}

// PromoteQueued evaluates queued and active txs against current account
// sequences. It evicts stale txs (firing EventTxRemoved) and promotes
// sequential queued txs to active (firing EventTxInserted). This should be
// called from PrepareCheckStater after each block commit.
func (m *ProxyAppMempool) PromoteQueued(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	senders := make(map[string]struct{})
	for s := range m.senderActive {
		senders[s] = struct{}{}
	}
	for s := range m.senderQueued {
		senders[s] = struct{}{}
	}

	for sender := range senders {
		var accountSeq uint64
		if m.ak != nil {
			acc := m.ak.GetAccount(ctx, sdk.AccAddress(sender))
			if acc != nil {
				accountSeq = acc.GetSequence()
			}
		}

		// evict stale active txs (nonce < accountSeq)
		if active, ok := m.senderActive[sender]; ok {
			var kept []txEntry
			for _, entry := range active.txs {
				if entry.nonce < accountSeq {
					m.activeCount--
					m.pushEvent(cmtmempool.EventTxRemoved, entry.txBytes)
				} else {
					kept = append(kept, entry)
				}
			}
			if len(kept) == 0 {
				delete(m.senderActive, sender)
			} else {
				active.txs = kept
			}
		}

		// evict stale queued txs (nonce < accountSeq)
		if queued, ok := m.senderQueued[sender]; ok {
			var kept []txEntry
			for _, entry := range queued.txs {
				if entry.nonce < accountSeq {
					m.queuedCount--
					m.pushEvent(cmtmempool.EventTxRemoved, entry.txBytes)
				} else {
					kept = append(kept, entry)
				}
			}
			if len(kept) == 0 {
				delete(m.senderQueued, sender)
			} else {
				queued.txs = kept
			}
		}

		// update nextExpected
		nextExpected := accountSeq
		if active, ok := m.senderActive[sender]; ok && len(active.txs) > 0 {
			highestActiveNonce := active.txs[len(active.txs)-1].nonce
			if highestActiveNonce+1 > nextExpected {
				nextExpected = highestActiveNonce + 1
			}
		}
		m.senderNextNonce[sender] = nextExpected

		m.promoteChain(sender, nextExpected)
	}
}

// extractSenderNonce extracts the sender address and nonce from a transaction's first signature.
func extractSenderNonce(tx sdk.Tx) (sender string, nonce uint64, err error) {
	sigTx, ok := tx.(signing.SigVerifiableTx)
	if !ok {
		return "", 0, fmt.Errorf("tx of type %T does not implement SigVerifiableTx", tx)
	}

	sigs, err := sigTx.GetSignaturesV2()
	if err != nil {
		return "", 0, err
	}
	if len(sigs) == 0 {
		return "", 0, fmt.Errorf("tx must have at least one signature")
	}

	sender = string(sigs[0].PubKey.Address().Bytes())
	nonce = sigs[0].Sequence

	return sender, nonce, nil
}

// pushEvent pushes an event to the CometBFT ProxyMempool event channel.
func (m *ProxyAppMempool) pushEvent(eventType cmtmempool.AppMempoolEventType, txBytes []byte) {
	if m.eventCh == nil {
		return
	}
	cmtTx := cmttypes.Tx(txBytes)
	event := cmtmempool.AppMempoolEvent{
		Type:  eventType,
		TxKey: cmtTx.Key(),
		Tx:    cmtTx,
	}

	select {
	case m.eventCh <- event:
	default:
	}
}

// insertActive inserts a txEntry into the sender's active queue in sorted order.
func (m *ProxyAppMempool) insertActive(sender string, entry txEntry) {
	sq, ok := m.senderActive[sender]
	if !ok {
		sq = &senderQueue{}
		m.senderActive[sender] = sq
	}
	sq.insertSorted(entry)
	m.activeCount++
}

// insertQueued inserts a txEntry into the sender's queued pool in sorted order.
func (m *ProxyAppMempool) insertQueued(sender string, entry txEntry) {
	sq, ok := m.senderQueued[sender]
	if !ok {
		sq = &senderQueue{}
		m.senderQueued[sender] = sq
	}
	sq.insertSorted(entry)
	m.queuedCount++
}

// removeFromActive removes a tx by sender+nonce from the active pool. Returns true if found.
func (m *ProxyAppMempool) removeFromActive(sender string, nonce uint64) bool {
	sq, ok := m.senderActive[sender]
	if !ok {
		return false
	}
	if sq.remove(nonce) {
		m.activeCount--
		if len(sq.txs) == 0 {
			delete(m.senderActive, sender)
		}
		return true
	}
	return false
}

// removeFromQueued removes a tx by sender+nonce from the queued pool. Returns true if found.
func (m *ProxyAppMempool) removeFromQueued(sender string, nonce uint64) bool {
	sq, ok := m.senderQueued[sender]
	if !ok {
		return false
	}
	if sq.remove(nonce) {
		m.queuedCount--
		if len(sq.txs) == 0 {
			delete(m.senderQueued, sender)
		}
		return true
	}
	return false
}

// findTx searches for a tx by sender+nonce in both active and queued pools.
// Returns the entry and pool name ("active" or "queued"), or nil if not found.
func (m *ProxyAppMempool) findTx(sender string, nonce uint64) (*txEntry, string) {
	if sq, ok := m.senderActive[sender]; ok {
		if e := sq.find(nonce); e != nil {
			return e, "active"
		}
	}

	if sq, ok := m.senderQueued[sender]; ok {
		if e := sq.find(nonce); e != nil {
			return e, "queued"
		}
	}

	return nil, ""
}

// senderTxCount returns the total number of txs for a sender across both pools.
func (m *ProxyAppMempool) senderTxCount(sender string) int {
	count := 0

	if sq, ok := m.senderActive[sender]; ok {
		count += len(sq.txs)
	}

	if sq, ok := m.senderQueued[sender]; ok {
		count += len(sq.txs)
	}

	return count
}

// promoteChain promotes sequential txs from the queued pool to the active pool
// starting from the given nonce.
func (m *ProxyAppMempool) promoteChain(sender string, startNonce uint64) {
	queued, ok := m.senderQueued[sender]
	if !ok {
		return
	}

	nextNonce := startNonce
	for {
		entry := queued.find(nextNonce)
		if entry == nil {
			break
		}
		entryCopy := *entry
		queued.remove(nextNonce)
		m.queuedCount--

		if len(queued.txs) == 0 {
			delete(m.senderQueued, sender)
		}

		m.insertActive(sender, entryCopy)
		m.senderNextNonce[sender] = nextNonce + 1
		m.pushEvent(cmtmempool.EventTxInserted, entryCopy.txBytes)

		nextNonce++

		queued, ok = m.senderQueued[sender]
		if !ok {
			break
		}
	}
}

// sortedActiveSenders returns active sender addresses in sorted order for
// deterministic iteration.
func (m *ProxyAppMempool) sortedActiveSenders() []string {
	senders := make([]string, 0, len(m.senderActive))
	for s := range m.senderActive {
		senders = append(senders, s)
	}
	sort.Strings(senders)

	return senders
}

// insertSorted inserts a txEntry into the queue maintaining nonce ascending order.
func (sq *senderQueue) insertSorted(entry txEntry) {
	idx := sort.Search(len(sq.txs), func(i int) bool {
		return sq.txs[i].nonce >= entry.nonce
	})
	sq.txs = append(sq.txs, txEntry{})
	copy(sq.txs[idx+1:], sq.txs[idx:])
	sq.txs[idx] = entry
}

// remove removes a txEntry by nonce. Returns true if found and removed.
func (sq *senderQueue) remove(nonce uint64) bool {
	idx := sort.Search(len(sq.txs), func(i int) bool {
		return sq.txs[i].nonce >= nonce
	})
	if idx < len(sq.txs) && sq.txs[idx].nonce == nonce {
		sq.txs = append(sq.txs[:idx], sq.txs[idx+1:]...)
		return true
	}

	return false
}

// find returns a pointer to the txEntry with the given nonce, or nil if not found.
func (sq *senderQueue) find(nonce uint64) *txEntry {
	idx := sort.Search(len(sq.txs), func(i int) bool {
		return sq.txs[i].nonce >= nonce
	})

	if idx < len(sq.txs) && sq.txs[idx].nonce == nonce {
		return &sq.txs[idx]
	}

	return nil
}

// proxyAppMempoolIterator implements the Iterator interface for ProxyAppMempool.
type proxyAppMempoolIterator struct {
	txs []sdk.Tx
	idx int
}

func (it *proxyAppMempoolIterator) Tx() sdk.Tx {
	return it.txs[it.idx]
}

func (it *proxyAppMempoolIterator) Next() Iterator {
	nextIdx := it.idx + 1
	if nextIdx >= len(it.txs) {
		return nil
	}
	return &proxyAppMempoolIterator{
		txs: it.txs,
		idx: nextIdx,
	}
}
