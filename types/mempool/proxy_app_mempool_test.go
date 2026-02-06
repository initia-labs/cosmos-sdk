package mempool_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	cmtmempool "github.com/cometbft/cometbft/mempool"
	"github.com/stretchr/testify/require"

	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/mempool"
)

// --- Test helpers ---

// mockAccountI is a minimal sdk.AccountI implementation for testing.
type mockAccountI struct {
	seq uint64
}

func (m *mockAccountI) GetAddress() sdk.AccAddress       { return nil }
func (m *mockAccountI) SetAddress(sdk.AccAddress) error  { return nil }
func (m *mockAccountI) GetPubKey() cryptotypes.PubKey    { return nil }
func (m *mockAccountI) SetPubKey(cryptotypes.PubKey) error { return nil }
func (m *mockAccountI) GetAccountNumber() uint64         { return 0 }
func (m *mockAccountI) SetAccountNumber(uint64) error    { return nil }
func (m *mockAccountI) GetSequence() uint64              { return m.seq }
func (m *mockAccountI) SetSequence(uint64) error         { return nil }
func (m *mockAccountI) String() string                   { return "" }
func (m *mockAccountI) ProtoMessage()                    {}
func (m *mockAccountI) Reset()                           {}

// mockAccountSeqGetter maps sender raw-address string → account sequence.
type mockAccountSeqGetter struct {
	seqs map[string]uint64
}

func (g *mockAccountSeqGetter) GetAccount(_ context.Context, addr sdk.AccAddress) sdk.AccountI {
	key := string(addr)
	seq, ok := g.seqs[key]
	if !ok {
		return nil
	}
	return &mockAccountI{seq: seq}
}

// mockTxEncoder returns predictable bytes: []byte("tx-<nonce>").
func mockTxEncoder(tx sdk.Tx) ([]byte, error) {
	sigTx, ok := tx.(interface {
		GetSignaturesV2() ([]interface{ GetSequence() uint64 }, error)
	})
	_ = sigTx
	_ = ok
	// Use a simple encoding based on the testTx nonce
	ttx, ok := tx.(testTx)
	if ok {
		return []byte(fmt.Sprintf("tx-%s-%d", ttx.strAddress, ttx.nonce)), nil
	}
	return []byte("tx-unknown"), nil
}

// newTestProxyMempool creates a ProxyAppMempool with the given config and sequence map.
func newTestProxyMempool(cfg mempool.ProxyAppMempoolConfig, seqs map[string]uint64) *mempool.ProxyAppMempool {
	getter := &mockAccountSeqGetter{seqs: seqs}
	return mempool.NewProxyAppMempool(cfg, getter, mockTxEncoder)
}

// collectEvents drains all available events from a buffered channel into a slice.
func collectEvents(ch <-chan cmtmempool.AppMempoolEvent) []cmtmempool.AppMempoolEvent {
	var events []cmtmempool.AppMempoolEvent
	for {
		select {
		case e := <-ch:
			events = append(events, e)
		default:
			return events
		}
	}
}

// makeTx creates a testTx with the given address bytes and nonce.
func makeTx(addrBytes []byte, nonce uint64) testTx {
	addr := sdk.AccAddress(addrBytes)
	return testTx{
		address:    addr,
		strAddress: addr.String(),
		nonce:      nonce,
	}
}

// senderKey returns the raw-bytes string key used by ProxyAppMempool for a sender address.
func senderKey(addrBytes []byte) string {
	return string(addrBytes)
}

// --- Tests ---

func TestProxyAppMempool_Insert(t *testing.T) {
	senderA := []byte("sender_a____________") // 20 bytes
	senderB := []byte("sender_b____________")

	t.Run("sequential nonce goes to active pool with EventTxInserted", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		tx := makeTx(senderA, 0)
		err := mp.Insert(context.Background(), tx)
		require.NoError(t, err)
		require.Equal(t, 1, mp.CountTx())

		events := collectEvents(eventCh)
		require.Len(t, events, 1)
		require.Equal(t, cmtmempool.EventTxInserted, events[0].Type)
	})

	t.Run("future nonce goes to queued pool with no EventTxInserted", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		tx := makeTx(senderA, 5) // future nonce
		err := mp.Insert(context.Background(), tx)
		require.NoError(t, err)
		require.Equal(t, 1, mp.CountTx())

		events := collectEvents(eventCh)
		require.Len(t, events, 0)
	})

	t.Run("stale nonce rejected", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 5,
		})

		tx := makeTx(senderA, 3) // nonce < accountSeq
		err := mp.Insert(context.Background(), tx)
		require.ErrorIs(t, err, mempool.ErrStaleNonce)
		require.Equal(t, 0, mp.CountTx())
	})

	t.Run("duplicate sender+nonce rejected", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		tx1 := makeTx(senderA, 0)
		require.NoError(t, mp.Insert(context.Background(), tx1))

		tx2 := makeTx(senderA, 0)
		err := mp.Insert(context.Background(), tx2)
		require.Error(t, err)
		require.Contains(t, err.Error(), "already exists")
	})

	t.Run("per-sender limit rejects when no lower-nonce eviction possible", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{
			MaxTxsPerSender: 2,
			MaxTotalTxs:     100,
		}, map[string]uint64{
			senderKey(senderA): 0,
		})

		// Fill 2 slots: nonce 0 (active) + nonce 1 (active via chain promotion)
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 1)))

		// Nonce 2 should be rejected (no queued tx with higher nonce to evict)
		err := mp.Insert(context.Background(), makeTx(senderA, 2))
		require.ErrorIs(t, err, mempool.ErrSenderTxLimit)
	})

	t.Run("per-sender limit evicts highest queued when lower nonce inserted", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{
			MaxTxsPerSender: 2,
			MaxTotalTxs:     100,
		}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		// Fill: nonce 0 (active), nonce 5 (queued)
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 5)))
		collectEvents(eventCh) // drain

		// Insert nonce 3 (lower than highest queued 5) → should evict nonce 5
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 3)))
		require.Equal(t, 2, mp.CountTx())

		events := collectEvents(eventCh)
		// Should have EventTxRemoved for nonce 5
		var removedCount int
		for _, e := range events {
			if e.Type == cmtmempool.EventTxRemoved {
				removedCount++
			}
		}
		require.Equal(t, 1, removedCount)
	})

	t.Run("total limit rejects new tx", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{
			MaxTxsPerSender: 100,
			MaxTotalTxs:     2,
		}, map[string]uint64{
			senderKey(senderA): 0,
			senderKey(senderB): 0,
		})

		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderB, 0)))

		tx := makeTx(senderA, 1)
		err := mp.Insert(context.Background(), tx)
		require.ErrorIs(t, err, mempool.ErrMempoolTxMaxCapacity)
	})

	t.Run("auto-promotes queued chain when sequential nonce arrives", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		// Insert out of order: nonces 2, 1, then 0
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 2)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 1)))
		collectEvents(eventCh) // drain - no inserted events for future nonces

		// Insert nonce 0 → should promote all three
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.Equal(t, 3, mp.CountTx())

		events := collectEvents(eventCh)
		// Should have 3 EventTxInserted (for nonces 0, 1, 2)
		insertedCount := 0
		for _, e := range events {
			if e.Type == cmtmempool.EventTxInserted {
				insertedCount++
			}
		}
		require.Equal(t, 3, insertedCount)
	})

	t.Run("uses TxBytesContextKey from context when present", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		customBytes := []byte("custom-tx-bytes")
		ctx := context.WithValue(context.Background(), mempool.TxBytesContextKey{}, customBytes)

		tx := makeTx(senderA, 0)
		require.NoError(t, mp.Insert(ctx, tx))

		events := collectEvents(eventCh)
		require.Len(t, events, 1)
		require.Equal(t, customBytes, []byte(events[0].Tx))
	})

	t.Run("falls back to txEncoder when no context bytes", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		tx := makeTx(senderA, 0)
		require.NoError(t, mp.Insert(context.Background(), tx))

		events := collectEvents(eventCh)
		require.Len(t, events, 1)
		// The mockTxEncoder encodes as "tx-<address>-<nonce>"
		require.Contains(t, string(events[0].Tx), "tx-")
	})
}

func TestProxyAppMempool_Remove(t *testing.T) {
	senderA := []byte("sender_a____________")

	t.Run("remove from active pool", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		tx := makeTx(senderA, 0)
		require.NoError(t, mp.Insert(context.Background(), tx))
		require.Equal(t, 1, mp.CountTx())

		require.NoError(t, mp.Remove(tx))
		require.Equal(t, 0, mp.CountTx())
	})

	t.Run("remove from queued pool", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		tx := makeTx(senderA, 5) // future nonce → queued
		require.NoError(t, mp.Insert(context.Background(), tx))
		require.Equal(t, 1, mp.CountTx())

		require.NoError(t, mp.Remove(tx))
		require.Equal(t, 0, mp.CountTx())
	})

	t.Run("remove non-existent returns ErrTxNotFound", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		tx := makeTx(senderA, 0)
		err := mp.Remove(tx)
		require.ErrorIs(t, err, mempool.ErrTxNotFound)
	})
}

func TestProxyAppMempool_Select(t *testing.T) {
	senderA := []byte("sender_a____________")
	senderB := []byte("sender_b____________")

	t.Run("empty mempool returns nil iterator", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, nil)
		itr := mp.Select(context.Background(), nil)
		require.Nil(t, itr)
	})

	t.Run("single sender nonce order", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		// Insert nonces 2, 1, 0 → all promoted to active via chain
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 2)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 1)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))

		txs := fetchTxs(mp.Select(context.Background(), nil), 100)
		require.Len(t, txs, 3)

		// Verify nonce ascending order
		for i, tx := range txs {
			ttx := tx.(testTx)
			require.Equal(t, uint64(i), ttx.nonce)
		}
	})

	t.Run("multiple senders round-robin interleaving", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
			senderKey(senderB): 0,
		})

		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 1)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderB, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderB, 1)))

		txs := fetchTxs(mp.Select(context.Background(), nil), 100)
		require.Len(t, txs, 4)

		// With round-robin, we should see alternating senders (sorted by address)
		// Both senders should appear
		senderCounts := make(map[string]int)
		for _, tx := range txs {
			ttx := tx.(testTx)
			senderCounts[ttx.strAddress]++
		}
		require.Len(t, senderCounts, 2)
	})

	t.Run("only active txs returned not queued", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))  // active
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 5)))  // queued (gap at 1-4)
		require.Equal(t, 2, mp.CountTx())

		txs := fetchTxs(mp.Select(context.Background(), nil), 100)
		// Only nonce 0 should be returned (active), not nonce 5 (queued)
		require.Len(t, txs, 1)
		require.Equal(t, uint64(0), txs[0].(testTx).nonce)
	})
}

func TestProxyAppMempool_SelectBy(t *testing.T) {
	senderA := []byte("sender_a____________")

	t.Run("iterates all when callback returns true", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 1)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 2)))

		var collected []sdk.Tx
		mp.SelectBy(context.Background(), nil, func(tx sdk.Tx) bool {
			collected = append(collected, tx)
			return true
		})
		require.Len(t, collected, 3)
	})

	t.Run("stops early when callback returns false", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 1)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 2)))

		var collected []sdk.Tx
		mp.SelectBy(context.Background(), nil, func(tx sdk.Tx) bool {
			collected = append(collected, tx)
			return len(collected) < 2
		})
		require.Len(t, collected, 2)
	})
}

func TestProxyAppMempool_CountTx(t *testing.T) {
	senderA := []byte("sender_a____________")

	t.Run("counts active plus queued", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0))) // active
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 5))) // queued
		require.Equal(t, 2, mp.CountTx())
	})

	t.Run("empty returns zero", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, nil)
		require.Equal(t, 0, mp.CountTx())
	})

	t.Run("decrements after remove", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})

		tx := makeTx(senderA, 0)
		require.NoError(t, mp.Insert(context.Background(), tx))
		require.Equal(t, 1, mp.CountTx())

		require.NoError(t, mp.Remove(tx))
		require.Equal(t, 0, mp.CountTx())
	})
}

func TestProxyAppMempool_PromoteQueued(t *testing.T) {
	senderA := []byte("sender_a____________")

	t.Run("evicts stale active txs", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		seqs := map[string]uint64{senderKey(senderA): 0}
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, seqs)
		mp.SetEventCh(eventCh)

		// Insert nonces 0, 1, 2 as active
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 1)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 2)))
		require.Equal(t, 3, mp.CountTx())
		collectEvents(eventCh) // drain

		// Simulate block commit advancing account sequence to 2
		seqs[senderKey(senderA)] = 2
		mp.PromoteQueued(context.Background())

		// Nonces 0 and 1 should be evicted, leaving nonce 2
		require.Equal(t, 1, mp.CountTx())

		events := collectEvents(eventCh)
		removedCount := 0
		for _, e := range events {
			if e.Type == cmtmempool.EventTxRemoved {
				removedCount++
			}
		}
		require.Equal(t, 2, removedCount)
	})

	t.Run("evicts stale queued txs", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		seqs := map[string]uint64{senderKey(senderA): 0}
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, seqs)
		mp.SetEventCh(eventCh)

		// Insert queued txs with future nonces
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 3)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 5)))
		require.Equal(t, 2, mp.CountTx())
		collectEvents(eventCh) // drain

		// Advance account sequence past nonce 3 but not 5
		seqs[senderKey(senderA)] = 4
		mp.PromoteQueued(context.Background())

		// Nonce 3 evicted, nonce 5 remains queued
		require.Equal(t, 1, mp.CountTx())

		events := collectEvents(eventCh)
		removedCount := 0
		for _, e := range events {
			if e.Type == cmtmempool.EventTxRemoved {
				removedCount++
			}
		}
		require.Equal(t, 1, removedCount)
	})

	t.Run("promotes sequential queued chain after commit", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		seqs := map[string]uint64{senderKey(senderA): 0}
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, seqs)
		mp.SetEventCh(eventCh)

		// Insert queued txs for nonces 3, 4, 5 (account seq is 0, so these are queued)
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 3)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 4)))
		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 5)))
		collectEvents(eventCh) // drain

		// Advance account sequence to 3 → nonces 3,4,5 become sequential
		seqs[senderKey(senderA)] = 3
		mp.PromoteQueued(context.Background())

		events := collectEvents(eventCh)
		insertedCount := 0
		for _, e := range events {
			if e.Type == cmtmempool.EventTxInserted {
				insertedCount++
			}
		}
		require.Equal(t, 3, insertedCount)

		// All should now be active
		txs := fetchTxs(mp.Select(context.Background(), nil), 100)
		require.Len(t, txs, 3)
	})

	t.Run("no-op on empty mempool", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, nil)
		mp.SetEventCh(eventCh)

		mp.PromoteQueued(context.Background())

		events := collectEvents(eventCh)
		require.Len(t, events, 0)
		require.Equal(t, 0, mp.CountTx())
	})
}

func TestProxyAppMempool_Events(t *testing.T) {
	senderA := []byte("sender_a____________")

	t.Run("events pushed when channel set", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 100)
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		require.NoError(t, mp.Insert(context.Background(), makeTx(senderA, 0)))

		events := collectEvents(eventCh)
		require.Len(t, events, 1)
		require.Equal(t, cmtmempool.EventTxInserted, events[0].Type)
	})

	t.Run("no panic when channel nil", func(t *testing.T) {
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{}, map[string]uint64{
			senderKey(senderA): 0,
		})
		// Do NOT call SetEventCh

		require.NotPanics(t, func() {
			_ = mp.Insert(context.Background(), makeTx(senderA, 0))
		})
		require.Equal(t, 1, mp.CountTx())
	})

	t.Run("event dropped no deadlock when channel full", func(t *testing.T) {
		eventCh := make(chan cmtmempool.AppMempoolEvent, 1) // tiny buffer
		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{
			MaxTxsPerSender: 100,
			MaxTotalTxs:     100,
		}, map[string]uint64{
			senderKey(senderA): 0,
		})
		mp.SetEventCh(eventCh)

		// Insert multiple txs to overflow the channel
		for i := 0; i < 10; i++ {
			_ = mp.Insert(context.Background(), makeTx(senderA, uint64(i)))
		}
		// Should not deadlock — if we got here, the test passes
		require.Equal(t, 10, mp.CountTx())
	})
}

func TestProxyAppMempool_Concurrent(t *testing.T) {
	t.Run("concurrent inserts from different senders", func(t *testing.T) {
		numSenders := 20
		txsPerSender := 10
		seqs := make(map[string]uint64)
		senders := make([][]byte, numSenders)

		for i := 0; i < numSenders; i++ {
			addr := []byte(fmt.Sprintf("sender_%02d___________", i)) // 20 bytes
			senders[i] = addr
			seqs[senderKey(addr)] = 0
		}

		mp := newTestProxyMempool(mempool.ProxyAppMempoolConfig{
			MaxTxsPerSender: 100,
			MaxTotalTxs:     5000,
		}, seqs)

		var wg sync.WaitGroup
		for i := 0; i < numSenders; i++ {
			wg.Add(1)
			go func(senderIdx int) {
				defer wg.Done()
				for n := 0; n < txsPerSender; n++ {
					tx := makeTx(senders[senderIdx], uint64(n))
					_ = mp.Insert(context.Background(), tx)
				}
			}(i)
		}
		wg.Wait()

		// All txs should be inserted (sequential nonces from 0, all active)
		require.Equal(t, numSenders*txsPerSender, mp.CountTx())
	})
}
