package vpnproto

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"masterdnsvpn-go/internal/logger"
	"sync"
	"time"
)

type packetSnapshot struct {
	PacketType     uint8
	StreamID       uint16
	SeqNum         uint16
	FragmentID     uint8
	TotalFragments uint8
}

type snapshotEntry struct {
	key       [4]byte
	createdAt time.Time
	packets   []packetSnapshot
}

type AckTracker struct {
	logger      *logger.Logger
	mu          sync.Mutex
	sessionSalt [16]byte
	entries     map[[4]byte]snapshotEntry
}

func NewAckTracker(logger *logger.Logger) *AckTracker {
	return &AckTracker{
		logger:  logger,
		entries: make(map[[4]byte]snapshotEntry),
	}
}

func (t *AckTracker) InitSessionSalt(encKey string, sessionIndex uint) error {
	raw, err := hex.DecodeString(encKey)
	if err != nil {
		return fmt.Errorf("decode enckey: %w", err)
	}

	nonce := make([]byte, 4)
	binary.BigEndian.PutUint32(nonce, uint32(sessionIndex))

	sum := sha1.Sum(append(raw, nonce...))
	t.mu.Lock()
	copy(t.sessionSalt[:], sum[0:16])
	t.mu.Unlock()
	return nil
}

func (t *AckTracker) GetRequestSnapshot(payload []byte, nonce uint) [4]byte {
	t.mu.Lock()
	salt := t.sessionSalt
	t.mu.Unlock()

	nonceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceBytes, uint32(nonce))

	buf := make([]byte, 0, len(salt)+len(nonceBytes)+len(payload))
	buf = append(buf, salt[:]...)
	buf = append(buf, nonceBytes...)
	buf = append(buf, payload...)

	sum := sha1.Sum(buf)

	var k [4]byte
	copy(k[:], sum[len(sum)-4:])
	return k
}

func (t *AckTracker) RecordRequestSnapshot(payload []byte, nonce uint, packets []*Packet) ([4]byte, error) {
	if t == nil {
		return [4]byte{}, errors.New("nil tracker")
	}

	key := t.GetRequestSnapshot(payload, nonce)

	copied := make([]packetSnapshot, 0, len(packets))
	for _, p := range packets {
		if p == nil {
			continue
		}
		cp := packetSnapshot{
			PacketType:     p.PacketType,
			StreamID:       p.StreamID,
			SeqNum:         p.SequenceNum,
			FragmentID:     p.FragmentID,
			TotalFragments: p.TotalFragments,
		}
		copied = append(copied, cp)
	}

	t.mu.Lock()
	t.entries[key] = snapshotEntry{
		key:       key,
		createdAt: time.Now(),
		packets:   copied,
	}
	t.mu.Unlock()

	return key, nil
}

func (t *AckTracker) UponResponse(payload [4]byte) ([]packetSnapshot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[payload]
	if !ok {
		return nil, false
	}

	delete(t.entries, payload)

	return entry.packets, true
}

func (t *AckTracker) StartAsyncGc(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			t.mu.Lock()
			for k, entry := range t.entries {
				if now.Sub(entry.createdAt) <= 60*time.Second {
					continue
				}
				if t.logger != nil {
					t.logger.Warnf("Packet snapshot %x was not ACKed within 60s", k[:])
				}
				delete(t.entries, k)
			}
			t.mu.Unlock()
		}
	}
}
