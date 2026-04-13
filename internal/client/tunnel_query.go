// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (tunnel_query.go) handles the construction of DNS tunnel queries.
// ==============================================================================
package client

import (
	DnsParser "masterdnsvpn-go/internal/dnsparser"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

type preparedTunnelDomain struct {
	normalized string
	qname      []byte
}

func QueryTypeFromQueryTypeStr(tunnelQType string) uint16 {
	qType := uint16(0)
	if tunnelQType == "AAAA" {
		qType = Enums.DNS_RECORD_TYPE_AAAA
	} else {
		qType = Enums.DNS_RECORD_TYPE_TXT
	}
	return qType
}

func buildTunnelQuestionBytesPrepared(tunnelQType string, domain preparedTunnelDomain, encoded []byte) ([]byte, error) {
	qType := QueryTypeFromQueryTypeStr(tunnelQType)
	return DnsParser.BuildTunnelQuestionPacketPrepared(domain.normalized, domain.qname, encoded, qType, EDnsSafeUDPSize)
}

func buildTunnelQuestionBytes(tunnelQType string, domain string, encoded []byte) ([]byte, error) {
	qType := QueryTypeFromQueryTypeStr(tunnelQType)
	return DnsParser.BuildTunnelQuestionPacket(domain, encoded, qType, EDnsSafeUDPSize)
}

func prepareTunnelDomain(domain string) (preparedTunnelDomain, error) {
	normalized, qname, err := DnsParser.PrepareTunnelDomainQname(domain)
	if err != nil {
		return preparedTunnelDomain{}, err
	}

	// fmt.Println("-------- DNS ", name, " --------")

	return preparedTunnelDomain{normalized: normalized, qname: qname}, nil
}

// buildTunnelQueryRaw builds an encoded tunnel query using the provided options and codec.
func (c *Client) buildTunnelQueryRaw(domain string, options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRaw(options)
	if err != nil {
		return nil, err
	}
	encoded, err := c.codec.EncryptAndEncodeBytes(raw)
	if err != nil {
		return nil, err
	}
	return buildTunnelQuestionBytes(c.tunnelQType, domain, encoded)
}

func (c *Client) buildEncodedAutoWithCompressionTrace(options VpnProto.BuildOptions) ([]byte, error) {
	raw, err := VpnProto.BuildRawAuto(options, c.cfg.CompressionMinSize)
	if err != nil {
		return nil, err
	}

	if c.codec == nil {
		return nil, VpnProto.ErrCodecUnavailable
	}
	return c.codec.EncryptAndEncodeBytes(raw)
}
