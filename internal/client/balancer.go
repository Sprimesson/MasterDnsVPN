// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	BalancingRoundRobinDefault = 0
	BalancingRandom            = 1
	BalancingRoundRobin        = 2
	BalancingLeastLoss         = 3
	BalancingLowestLatency     = 4
)

type Balancer struct {
	strategy  int
	rrCounter atomic.Uint64
	rngState  atomic.Uint64

	mu          sync.RWMutex
	connections []*Connection
	valid       []int
	indexByKey  map[string]int
	stats       []connectionStats
}

type connectionStats struct {
	sent         atomic.Uint64
	acked        atomic.Uint64
	rttMicrosSum atomic.Uint64
	rttCount     atomic.Uint64
}

func NewBalancer(strategy int) *Balancer {
	b := &Balancer{
		strategy:   strategy,
		indexByKey: make(map[string]int),
	}
	b.rngState.Store(seedRNG())
	return b
}

func (b *Balancer) SetConnections(connections []*Connection) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.connections = connections
	b.indexByKey = make(map[string]int, len(connections))
	b.valid = make([]int, 0, len(connections))
	b.stats = make([]connectionStats, len(connections))

	for idx, conn := range connections {
		if conn == nil {
			continue
		}
		b.indexByKey[conn.Key] = idx
		if conn.IsValid {
			b.valid = append(b.valid, idx)
		}
	}
}

func (b *Balancer) ValidCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.valid)
}

func (b *Balancer) SetConnectionValidity(key string, valid bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	idx, ok := b.indexByKey[key]
	if !ok {
		return false
	}

	conn := b.connections[idx]
	if conn == nil || conn.IsValid == valid {
		return ok
	}

	conn.IsValid = valid
	b.refreshValidLocked()
	return true
}

func (b *Balancer) RefreshValidConnections() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refreshValidLocked()
}

func (b *Balancer) ReportSend(serverKey string) {
	if stats := b.statsForKey(serverKey); stats != nil {
		stats.sent.Add(1)
	}
}

func (b *Balancer) ReportSuccess(serverKey string, rtt time.Duration) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.acked.Add(1)
	if rtt > 0 {
		stats.rttMicrosSum.Add(uint64(rtt / time.Microsecond))
		stats.rttCount.Add(1)
	}

	sent := stats.sent.Load()
	if sent <= 1000 {
		return
	}

	stats.sent.Store(sent / 2)
	stats.acked.Store(stats.acked.Load() / 2)
	stats.rttMicrosSum.Store(stats.rttMicrosSum.Load() / 2)
	stats.rttCount.Store(stats.rttCount.Load() / 2)
}

func (b *Balancer) ResetServerStats(serverKey string) {
	stats := b.statsForKey(serverKey)
	if stats == nil {
		return
	}

	stats.sent.Store(0)
	stats.acked.Store(0)
	stats.rttMicrosSum.Store(0)
	stats.rttCount.Store(0)
}

func (b *Balancer) GetBestConnection() (Connection, bool) {
	selected := b.GetUniqueConnections(1)
	if len(selected) == 0 {
		return Connection{}, false
	}
	return selected[0], true
}

func (b *Balancer) GetUniqueConnections(requiredCount int) []Connection {
	valid := b.snapshotValid()
	count := normalizeRequiredCount(len(valid), requiredCount, 1)
	if count == 0 {
		return nil
	}

	switch b.strategy {
	case BalancingRandom:
		return b.selectRandom(valid, count)
	case BalancingLeastLoss:
		return b.selectLowestScore(valid, count, b.lossScore)
	case BalancingLowestLatency:
		return b.selectLowestScore(valid, count, b.latencyScore)
	default:
		return b.selectRoundRobin(valid, count)
	}
}

func (b *Balancer) refreshValidLocked() {
	valid := make([]int, 0, len(b.connections))
	for idx, conn := range b.connections {
		if conn != nil && conn.IsValid {
			valid = append(valid, idx)
		}
	}
	b.valid = valid
}

func (b *Balancer) snapshotValid() []int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.valid) == 0 {
		return nil
	}

	snapshot := make([]int, len(b.valid))
	copy(snapshot, b.valid)
	return snapshot
}

func (b *Balancer) statsForKey(serverKey string) *connectionStats {
	b.mu.RLock()
	idx, ok := b.indexByKey[serverKey]
	if !ok || idx < 0 || idx >= len(b.stats) {
		b.mu.RUnlock()
		return nil
	}
	stats := &b.stats[idx]
	b.mu.RUnlock()
	return stats
}

func normalizeRequiredCount(validCount, requiredCount, defaultIfInvalid int) int {
	if validCount <= 0 {
		return 0
	}
	if requiredCount <= 0 {
		requiredCount = defaultIfInvalid
	}
	if requiredCount > validCount {
		return validCount
	}
	return requiredCount
}

func (b *Balancer) selectRoundRobin(valid []int, count int) []Connection {
	start := int(b.rrCounter.Add(uint64(count)) - uint64(count))
	selected := make([]Connection, 0, count)
	for i := 0; i < count; i++ {
		selected = append(selected, b.connectionAt(valid[(start+i)%len(valid)]))
	}
	return selected
}

func (b *Balancer) selectRandom(valid []int, count int) []Connection {
	order := make([]int, len(valid))
	copy(order, valid)

	for i := 0; i < count; i++ {
		j := i + int(b.nextRandom()%uint64(len(order)-i))
		order[i], order[j] = order[j], order[i]
	}

	selected := make([]Connection, 0, count)
	for i := 0; i < count; i++ {
		selected = append(selected, b.connectionAt(order[i]))
	}
	return selected
}

func (b *Balancer) selectLowestScore(valid []int, count int, scorer func(int) float64) []Connection {
	bestIdx := make([]int, 0, count)
	bestScores := make([]float64, 0, count)

	for _, idx := range valid {
		score := scorer(idx)
		insertPos := len(bestScores)

		for i := 0; i < len(bestScores); i++ {
			if score < bestScores[i] {
				insertPos = i
				break
			}
		}

		if len(bestScores) < count {
			bestScores = append(bestScores, 0)
			bestIdx = append(bestIdx, 0)
		} else if insertPos == len(bestScores) {
			continue
		}

		copy(bestScores[insertPos+1:], bestScores[insertPos:])
		copy(bestIdx[insertPos+1:], bestIdx[insertPos:])
		bestScores[insertPos] = score
		bestIdx[insertPos] = idx

		if len(bestScores) > count {
			bestScores = bestScores[:count]
			bestIdx = bestIdx[:count]
		}
	}

	selected := make([]Connection, 0, len(bestIdx))
	for _, idx := range bestIdx {
		selected = append(selected, b.connectionAt(idx))
	}
	return selected
}

func (b *Balancer) connectionAt(idx int) Connection {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if idx < 0 || idx >= len(b.connections) || b.connections[idx] == nil {
		return Connection{}
	}
	return *b.connections[idx]
}

func (b *Balancer) lossScore(idx int) float64 {
	stats := &b.stats[idx]
	sent := stats.sent.Load()
	if sent < 5 {
		return 0.5
	}

	acked := stats.acked.Load()
	loss := 1.0 - (float64(acked) / float64(sent))
	if loss < 0 {
		return 0
	}
	if loss > 1 {
		return 1
	}
	return loss
}

func (b *Balancer) latencyScore(idx int) float64 {
	stats := &b.stats[idx]
	count := stats.rttCount.Load()
	if count < 5 {
		return 999000.0
	}
	return float64(stats.rttMicrosSum.Load()) / float64(count)
}

func (b *Balancer) nextRandom() uint64 {
	for {
		current := b.rngState.Load()
		next := xorshift64(current)
		if b.rngState.CompareAndSwap(current, next) {
			return next
		}
	}
}

func seedRNG() uint64 {
	seed := uint64(time.Now().UnixNano())
	if seed == 0 {
		return 0x9e3779b97f4a7c15
	}
	return seed
}

func xorshift64(v uint64) uint64 {
	if v == 0 {
		v = 0x9e3779b97f4a7c15
	}
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	return v
}
