// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package dnsparser

import (
	"bytes"
	"testing"

	"masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/vpnproto"
)

func TestBuildTunnelQuestionNameSplitsLabels(t *testing.T) {
	name, err := BuildTunnelQuestionName("v.example.com", stringsOf('a', 130))
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}
	if len(name) > maxDNSNameLen {
		t.Fatalf("name exceeds max length: %d", len(name))
	}
}

func TestBuildAndExtractVPNResponsePacketSingleAnswer(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", enums.DNSRecordTypeTXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	response, err := BuildVPNResponsePacket(query, "x.v.example.com", vpnproto.Packet{
		SessionID:  9,
		PacketType: enums.PacketMTUUpRes,
		Payload:    []byte("challenge"),
	}, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != enums.PacketMTUUpRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, enums.PacketMTUUpRes)
	}
	if !bytes.Equal(packet.Payload, []byte("challenge")) {
		t.Fatalf("unexpected payload: got=%q", packet.Payload)
	}
}

func TestBuildAndExtractVPNResponsePacketChunked(t *testing.T) {
	query, err := BuildTXTQuestionPacket("x.v.example.com", enums.DNSRecordTypeTXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}

	payload := bytes.Repeat([]byte{0xAB}, 700)
	response, err := BuildVPNResponsePacket(query, "x.v.example.com", vpnproto.Packet{
		SessionID:   7,
		PacketType:  enums.PacketMTUDownRes,
		StreamID:    1,
		SequenceNum: 2,
		Payload:     payload,
	}, false)
	if err != nil {
		t.Fatalf("BuildVPNResponsePacket returned error: %v", err)
	}

	packet, err := ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != enums.PacketMTUDownRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, enums.PacketMTUDownRes)
	}
	if !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("unexpected chunked payload size: got=%d want=%d", len(packet.Payload), len(payload))
	}
}

func stringsOf(ch byte, count int) string {
	buf := make([]byte, count)
	for i := range buf {
		buf[i] = ch
	}
	return string(buf)
}
