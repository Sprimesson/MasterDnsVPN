package vpnproto

import (
	"context"
	"sync"
	"testing"
	"time"
)

type testLogger struct {
	mu   sync.Mutex
	logs []string
}

func (l *testLogger) Warnf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logs = append(l.logs, "warn")
}

func TestInitSessionSaltAndGetRequestSnapshotDeterministic(t *testing.T) {
	tr := NewAckTracker(nil)

	if err := tr.InitSessionSalt("00112233445566778899aabbccddeeff", 7); err != nil {
		t.Fatalf("initSessionSalt failed: %v", err)
	}

	k1 := tr.GetRequestSnapshot([]byte{1, 2, 3}, 9)
	k2 := tr.GetRequestSnapshot([]byte{1, 2, 3}, 9)
	k3 := tr.GetRequestSnapshot([]byte{1, 2, 4}, 9)
	if k1 != k2 {
		t.Fatalf("expected deterministic snapshots, got %x != %x", k1, k2)
	}
	if k1 == k3 {
		t.Fatalf("expected different payloads to produce different snapshots")
	}
}

func TestRecordAndUponResponse(t *testing.T) {
	tr := NewAckTracker(nil)

	if err := tr.InitSessionSalt("00112233445566778899aabbccddeeff", 1); err != nil {
		t.Fatalf("initSessionSalt failed: %v", err)
	}

	in := []*Packet{
		{
			PacketType:      3,
			HasStreamID:     true,
			StreamID:        42,
			HasSequenceNum:  true,
			SequenceNum:     99,
			HasFragmentInfo: true,
			FragmentID:      1,
			TotalFragments:  3,
			Payload:         []byte("ignored"),
		},
	}

	key, err := tr.RecordRequestSnapshot([]byte("hello"), 5, in)
	if err != nil {
		t.Fatalf("recordRequestSnapshot failed: %v", err)
	}

	got, ok := tr.UponResponse(key)
	if !ok {
		t.Fatalf("expected response to match recorded snapshot")
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(got))
	}

	if got[0].PacketType != 3 || got[0].StreamID != 42 || got[0].SeqNum != 99 || got[0].FragmentID != 1 || got[0].TotalFragments != 3 {
		t.Fatalf("unexpected copied packet: %+v", got[0])
	}

	if _, ok := tr.UponResponse(key); ok {
		t.Fatalf("expected snapshot to be removed after response")
	}
}

func TestAsyncGcRemovesExpiredEntries(t *testing.T) {
	tr := NewAckTracker(nil)

	if err := tr.InitSessionSalt("00112233445566778899aabbccddeeff", 1); err != nil {
		t.Fatalf("initSessionSalt failed: %v", err)
	}

	key, err := tr.RecordRequestSnapshot([]byte("hello"), 5, []*Packet{
		{PacketType: 1},
	})
	if err != nil {
		t.Fatalf("recordRequestSnapshot failed: %v", err)
	}

	tr.mu.Lock()
	entry := tr.entries[key]
	entry.createdAt = time.Now().Add(-61 * time.Second)
	tr.entries[key] = entry
	tr.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	wg.Add(1)

	go tr.StartAsyncGc(ctx, &wg)
	time.Sleep(1500 * time.Millisecond)

	if _, ok := tr.UponResponse(key); ok {
		t.Fatalf("expected expired entry to be removed by gc")
	}

	cancel()
	wg.Wait()
}
