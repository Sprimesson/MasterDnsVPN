// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"net"
	"testing"
	"time"

	"masterdnsvpn-go/internal/arq"
	"masterdnsvpn-go/internal/config"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func buildTCPTestClient() *Client {
	return buildTestClientWithResolvers(config.ClientConfig{
		ProtocolType:                "TCP",
		StreamQueueInitialCapacity:  32,
		OrphanQueueInitialCapacity:  8,
		ARQWindowSize:               64,
		ARQInitialRTOSeconds:        0.2,
		ARQMaxRTOSeconds:            1.0,
		ARQControlInitialRTOSeconds: 0.2,
		ARQControlMaxRTOSeconds:     1.0,
	}, "resolver-a")
}

func TestHandleTCPConnectQueuesStreamSyn(t *testing.T) {
	c := buildTCPTestClient()
	c.syncedUploadMTU = 64

	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	c.HandleTCPConnect(context.Background(), local)

	if len(c.active_streams) != 1 {
		t.Fatalf("expected one active stream, got %d", len(c.active_streams))
	}

	var stream *Stream_client
	for _, s := range c.active_streams {
		stream = s
	}
	if stream == nil {
		t.Fatal("expected created stream")
	}

	if got := stream.StatusValue(); got != streamStatusConnecting {
		t.Fatalf("expected stream status %q, got %q", streamStatusConnecting, got)
	}

	packet, _, ok := stream.PopNextTXPacket()
	if !ok || packet == nil {
		t.Fatal("expected queued STREAM_SYN packet")
	}
	defer stream.ReleaseTXPacket(packet)

	if packet.PacketType != Enums.PACKET_STREAM_SYN {
		t.Fatalf("expected packet type STREAM_SYN, got %d", packet.PacketType)
	}

	if len(packet.Payload) != 0 {
		t.Fatalf("expected raw STREAM_SYN without payload, got %d payload bytes", len(packet.Payload))
	}
}

func TestHandleStreamPacketConnectedEnablesTCPStreamIO(t *testing.T) {
	c := buildTCPTestClient()
	c.syncedUploadMTU = 64

	local, remote := net.Pipe()
	defer remote.Close()

	stream := c.new_stream(1, local, nil)
	arqObj, ok := stream.Stream.(*arq.ARQ)
	if !ok || arqObj == nil {
		t.Fatal("expected ARQ-backed stream")
	}

	packet := VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_CONNECTED,
		StreamID:    1,
		HasStreamID: true,
	}
	if err := c.HandleStreamPacket(packet); err != nil {
		t.Fatalf("HandleStreamPacket returned error: %v", err)
	}

	if got := stream.StatusValue(); got != streamStatusActive {
		t.Fatalf("expected stream status %q, got %q", streamStatusActive, got)
	}

	arqObj.ReceiveData(0, []byte("ok"))

	_ = remote.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2)
	n, err := remote.Read(buf)
	if err != nil {
		t.Fatalf("expected TCP stream IO to become ready, read failed: %v", err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("unexpected data through stream: %q", string(buf[:n]))
	}
}

func TestHandleStreamPacketConnectFailClosesTCPStream(t *testing.T) {
	c := buildTCPTestClient()
	c.syncedUploadMTU = 64

	local, remote := net.Pipe()
	defer remote.Close()

	stream := c.new_stream(2, local, nil)
	arqObj, ok := stream.Stream.(*arq.ARQ)
	if !ok || arqObj == nil {
		t.Fatal("expected ARQ-backed stream")
	}

	packet := VpnProto.Packet{
		PacketType:  Enums.PACKET_STREAM_CONNECT_FAIL,
		StreamID:    2,
		HasStreamID: true,
	}
	if err := c.HandleStreamPacket(packet); err != nil {
		t.Fatalf("HandleStreamPacket returned error: %v", err)
	}

	if got := stream.StatusValue(); got != streamStatusTimeWait {
		t.Fatalf("expected stream status %q, got %q", streamStatusTimeWait, got)
	}
	if stream.TerminalSince().IsZero() {
		t.Fatal("expected stream to be marked terminal after connect failure")
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for !arqObj.IsClosed() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !arqObj.IsClosed() {
		t.Fatal("expected ARQ stream to be closed after connect failure")
	}
}
