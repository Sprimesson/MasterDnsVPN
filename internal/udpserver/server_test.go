// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"bytes"
	"encoding/binary"
	"testing"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/vpnproto"
)

func TestHandlePacketDropsDNSResponses(t *testing.T) {
	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, nil)

	packet := buildServerTestQuery(0x1001, "vpn.a.com", enums.DNSRecordTypeTXT)
	packet[2] |= 0x80

	if response := srv.handlePacket(packet); response != nil {
		t.Fatal("handlePacket should drop DNS response packets")
	}
}

func TestHandlePacketReturnsNoDataForUnauthorizedDomain(t *testing.T) {
	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, nil)

	packet := buildServerTestQuery(0x2002, "evil.com", enums.DNSRecordTypeTXT)
	response := srv.handlePacket(packet)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a DNS response for unauthorized DNS queries")
	}

	if got := binary.BigEndian.Uint16(response[0:2]); got != 0x2002 {
		t.Fatalf("unexpected response id: got=%#x want=%#x", got, 0x2002)
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x000F != enums.DNSRCodeNoError {
		t.Fatalf("unexpected rcode: got=%d want=%d", flags&0x000F, enums.DNSRCodeNoError)
	}
}

func TestHandlePacketRespondsToMTUUpProbe(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	challenge := []byte("12345678")
	payload := append([]byte{0}, challenge...)
	payload = append(payload, bytes.Repeat([]byte{0xAB}, 64)...)
	query := buildTunnelQuery(t, codec, "a.com", enums.PacketMTUUpReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-up response")
	}

	packet, err := dnsparser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != enums.PacketMTUUpRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, enums.PacketMTUUpRes)
	}
	if string(packet.Payload) != string(challenge) {
		t.Fatalf("unexpected echoed challenge: got=%q want=%q", packet.Payload, challenge)
	}
}

func TestHandlePacketRespondsToMTUDownProbe(t *testing.T) {
	codec, err := security.NewCodec(0, "")
	if err != nil {
		t.Fatalf("NewCodec returned error: %v", err)
	}

	srv := New(config.ServerConfig{
		MaxPacketSize:     65535,
		Domain:            []string{"a.com"},
		MinVPNLabelLength: 3,
	}, nil, codec)

	challenge := []byte("12345678")
	payload := make([]byte, 13)
	binary.BigEndian.PutUint32(payload[1:5], 128)
	copy(payload[5:], challenge)
	query := buildTunnelQuery(t, codec, "a.com", enums.PacketMTUDownReq, payload)
	response := srv.handlePacket(query)
	if len(response) == 0 {
		t.Fatal("handlePacket should return a vpn mtu-down response")
	}

	packet, err := dnsparser.ExtractVPNResponse(response, false)
	if err != nil {
		t.Fatalf("ExtractVPNResponse returned error: %v", err)
	}
	if packet.PacketType != enums.PacketMTUDownRes {
		t.Fatalf("unexpected packet type: got=%d want=%d", packet.PacketType, enums.PacketMTUDownRes)
	}
	if len(packet.Payload) != 128 {
		t.Fatalf("unexpected mtu-down payload length: got=%d want=%d", len(packet.Payload), 128)
	}
	if string(packet.Payload[:len(challenge)]) != string(challenge) {
		t.Fatalf("unexpected mtu-down challenge prefix: got=%q want=%q", packet.Payload[:len(challenge)], challenge)
	}
}

func buildServerTestQuery(id uint16, name string, qtype uint16) []byte {
	qname := encodeServerTestName(name)
	packet := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)

	offset := 12
	offset += copy(packet[offset:], qname)
	binary.BigEndian.PutUint16(packet[offset:offset+2], qtype)
	binary.BigEndian.PutUint16(packet[offset+2:offset+4], enums.DNSQClassIN)
	return packet
}

func encodeServerTestName(name string) []byte {
	encoded := make([]byte, 0, len(name)+2)
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i != len(name) && name[i] != '.' {
			continue
		}
		encoded = append(encoded, byte(i-labelStart))
		encoded = append(encoded, name[labelStart:i]...)
		labelStart = i + 1
	}
	return append(encoded, 0)
}

func buildTunnelQuery(t *testing.T, codec *security.Codec, name string, packetType uint8, payload []byte) []byte {
	t.Helper()

	encoded, err := vpnproto.BuildEncoded(vpnproto.BuildOptions{
		SessionID:      255,
		PacketType:     packetType,
		StreamID:       1,
		SequenceNum:    1,
		TotalFragments: 1,
		Payload:        payload,
	}, codec)
	if err != nil {
		t.Fatalf("BuildEncoded returned error: %v", err)
	}

	questionName, err := dnsparser.BuildTunnelQuestionName(name, encoded)
	if err != nil {
		t.Fatalf("BuildTunnelQuestionName returned error: %v", err)
	}

	query, err := dnsparser.BuildTXTQuestionPacket(questionName, enums.DNSRecordTypeTXT, 4096)
	if err != nil {
		t.Fatalf("BuildTXTQuestionPacket returned error: %v", err)
	}
	return query
}
