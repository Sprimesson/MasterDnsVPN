// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/dnsparser"
	"masterdnsvpn-go/internal/domainmatcher"
	"masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
	"masterdnsvpn-go/internal/vpnproto"
)

type Server struct {
	cfg             config.ServerConfig
	log             *logger.Logger
	codec           *security.Codec
	domainMatcher   *domainmatcher.Matcher
	packetPool      sync.Pool
	droppedPackets  atomic.Uint64
	lastDropLogUnix atomic.Int64
}

type request struct {
	buf  []byte
	size int
	addr *net.UDPAddr
}

func New(cfg config.ServerConfig, log *logger.Logger, codec *security.Codec) *Server {
	return &Server{
		cfg:           cfg,
		log:           log,
		codec:         codec,
		domainMatcher: domainmatcher.New(cfg.Domain, cfg.MinVPNLabelLength),
		packetPool: sync.Pool{
			New: func() any {
				return make([]byte, cfg.MaxPacketSize)
			},
		},
	}
}

func (s *Server) Run(ctx context.Context) error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP(s.cfg.UDPHost),
		Port: s.cfg.UDPPort,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetReadBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("[!] <yellow>Failed To Set UDP Read Buffer</yellow>: <cyan>%v</cyan>", err)
	}
	if err := conn.SetWriteBuffer(s.cfg.SocketBufferSize); err != nil {
		s.log.Warnf("[!] <yellow>Failed To Set UDP Write Buffer</yellow>: <cyan>%v</cyan>", err)
	}

	s.log.Infof(
		"[*] <green>UDP Listener Ready</green>  Addr: <cyan>%s</cyan>  |  Readers: <magenta>%d</magenta>  |  Workers: <magenta>%d</magenta>  |  Queue: <magenta>%d</magenta>",
		s.cfg.Address(),
		s.cfg.UDPReaders,
		s.cfg.DNSRequestWorkers,
		s.cfg.MaxConcurrentRequests,
	)

	reqCh := make(chan request, s.cfg.MaxConcurrentRequests)
	var workerWG sync.WaitGroup

	for i := range s.cfg.DNSRequestWorkers {
		workerWG.Add(1)
		go func(workerID int) {
			defer workerWG.Done()
			s.worker(ctx, conn, reqCh, workerID)
		}(i + 1)
	}

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	readErrCh := make(chan error, s.cfg.UDPReaders)
	var readerWG sync.WaitGroup
	for i := range s.cfg.UDPReaders {
		readerWG.Add(1)
		go func(readerID int) {
			defer readerWG.Done()
			if err := s.readLoop(ctx, conn, reqCh, readerID); err != nil {
				select {
				case readErrCh <- err:
				default:
				}
			}
		}(i + 1)
	}

	readerWG.Wait()
	close(reqCh)
	workerWG.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	select {
	case err := <-readErrCh:
		return err
	default:
		return nil
	}
}

func (s *Server) readLoop(ctx context.Context, conn *net.UDPConn, reqCh chan<- request, readerID int) error {
	for {
		buffer := s.packetPool.Get().([]byte)
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			s.packetPool.Put(buffer)
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Debugf(
				"Reader <cyan>%d</cyan> returned a UDP read error: <yellow>%v</yellow>",
				readerID,
				err,
			)
			return err
		}

		select {
		case reqCh <- request{buf: buffer, size: n, addr: addr}:
		case <-ctx.Done():
			s.packetPool.Put(buffer)
			return nil
		default:
			s.packetPool.Put(buffer)
			s.onDrop(addr)
		}
	}
}

func (s *Server) worker(ctx context.Context, conn *net.UDPConn, reqCh <-chan request, workerID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqCh:
			if !ok {
				return
			}

			payload := req.buf[:req.size]
			response := s.handlePacket(payload)
			if len(response) == 0 {
				s.packetPool.Put(req.buf)
				continue
			}

			if _, err := conn.WriteToUDP(response, req.addr); err != nil {
				s.log.Debugf(
					"Worker <cyan>%d</cyan> failed to send a UDP response to <cyan>%s</cyan>: <yellow>%v</yellow>",
					workerID,
					req.addr.String(),
					err,
				)
				s.packetPool.Put(req.buf)
				continue
			}

			s.packetPool.Put(req.buf)
		}
	}
}

func (s *Server) handlePacket(packet []byte) []byte {
	if !dnsparser.LooksLikeDNSRequest(packet) {
		return nil
	}

	parsed, err := dnsparser.ParsePacketLite(packet)
	if err != nil {
		response, responseErr := dnsparser.BuildFormatErrorResponse(packet)
		if responseErr == nil {
			s.log.Debugf(
				"[DNS] <yellow>Malformed DNS Packet Rejected</yellow> id=<cyan>%d</cyan> action=<green>formerr</green>",
				binary.BigEndian.Uint16(packet[:2]),
			)
			return response
		}
		return nil
	}

	if !parsed.HasQuestion {
		response, responseErr := dnsparser.BuildFormatErrorResponse(packet)
		if responseErr == nil {
			s.log.Debugf(
				"[DNS] <yellow>DNS Packet Without Question Rejected</yellow> id=<cyan>%d</cyan> action=<green>formerr</green>",
				parsed.Header.ID,
			)
			return response
		}
		return nil
	}

	s.log.Debugf(
		"[DNS] <green>Parsed Packet</green> id=<cyan>%d</cyan> qr=<cyan>%d</cyan> opcode=<cyan>%d</cyan> qd=<cyan>%d</cyan> an=<cyan>%d</cyan> ns=<cyan>%d</cyan> ar=<cyan>%d</cyan>",
		parsed.Header.ID,
		parsed.Header.QR,
		parsed.Header.OpCode,
		parsed.Header.QDCount,
		parsed.Header.ANCount,
		parsed.Header.NSCount,
		parsed.Header.ARCount,
	)

	decision := s.domainMatcher.Match(parsed)
	switch decision.Action {
	case domainmatcher.ActionProcess:
		s.log.Debugf(
			"[VPN] <green>Accepted DNS Tunnel Candidate</green> id=<cyan>%d</cyan> domain=<yellow>%s</yellow> base=<cyan>%s</cyan> labels=<magenta>%s</magenta>",
			parsed.Header.ID,
			decision.RequestName,
			decision.BaseDomain,
			decision.Labels,
		)
		return s.handleTunnelCandidate(packet, parsed, decision)
	case domainmatcher.ActionFormatError:
		response, responseErr := dnsparser.BuildFormatErrorResponseFromLite(packet, parsed)
		if responseErr == nil {
			s.log.Debugf(
				"[DNS] <yellow>Malformed DNS Question</yellow> id=<cyan>%d</cyan> reason=<magenta>%s</magenta> action=<green>formerr</green>",
				parsed.Header.ID,
				decision.Reason,
			)
			return response
		}
		return nil
	case domainmatcher.ActionNoData:
		response, responseErr := dnsparser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
		if responseErr == nil {
			s.log.Debugf(
				"[DNS] <yellow>Question Skipped</yellow> id=<cyan>%d</cyan> reason=<magenta>%s</magenta> domain=<yellow>%s</yellow> qtype=<magenta>%d</magenta> action=<green>nodata</green>",
				parsed.Header.ID,
				decision.Reason,
				decision.RequestName,
				decision.QuestionType,
			)
			return response
		}
		return nil
	default:
		return nil
	}
}

func (s *Server) handleTunnelCandidate(packet []byte, parsed dnsparser.LitePacket, decision domainmatcher.Decision) []byte {
	vpnPacket, err := vpnproto.ParseFromLabels(decision.Labels, s.codec)
	if err != nil {
		s.log.Debugf(
			"[VPN] <yellow>Failed To Parse VPN Packet</yellow> id=<cyan>%d</cyan> domain=<yellow>%s</yellow> err=<yellow>%v</yellow>",
			parsed.Header.ID,
			decision.RequestName,
			err,
		)
		response, responseErr := dnsparser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}

	s.log.Debugf(
		"[VPN] <green>Parsed VPN Packet</green> id=<cyan>%d</cyan> sid=<magenta>%d</magenta> ptype=<magenta>%d</magenta> stream=<magenta>%d</magenta> seq=<magenta>%d</magenta> frag=<magenta>%d</magenta>/<magenta>%d</magenta> comp=<magenta>%d</magenta> payload_len=<cyan>%d</cyan>",
		parsed.Header.ID,
		vpnPacket.SessionID,
		vpnPacket.PacketType,
		vpnPacket.StreamID,
		vpnPacket.SequenceNum,
		vpnPacket.FragmentID,
		vpnPacket.TotalFragments,
		vpnPacket.CompressionType,
		len(vpnPacket.Payload),
	)

	switch vpnPacket.PacketType {
	case enums.PacketMTUUpReq:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case enums.PacketMTUDownReq:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	default:
		response, responseErr := dnsparser.BuildEmptyNoErrorResponseFromLite(packet, parsed)
		if responseErr != nil {
			return nil
		}
		return response
	}
}

func (s *Server) onDrop(addr *net.UDPAddr) {
	total := s.droppedPackets.Add(1)

	now := logger.NowUnixNano()
	last := s.lastDropLogUnix.Load()
	interval := s.cfg.DropLogInterval().Nanoseconds()
	if interval <= 0 {
		interval = 2_000_000_000
	}
	if now-last < interval {
		return
	}
	if !s.lastDropLogUnix.CompareAndSwap(last, now) {
		return
	}

	s.log.Warnf(
		"[!] <yellow>Request Queue Overloaded</yellow>  |  Total Dropped: <magenta>%d</magenta>  |  Last Remote: <cyan>%s</cyan>",
		total,
		addr.String(),
	)
}

func (s *Server) handleMTUUpRequest(questionPacket []byte, _ dnsparser.LitePacket, decision domainmatcher.Decision, vpnPacket vpnproto.Packet) []byte {
	if len(vpnPacket.Payload) < 1+8 {
		return nil
	}

	baseEncode := vpnPacket.Payload[0] == 1
	probeKey := vpnPacket.Payload[1 : 1+8]
	response, err := dnsparser.BuildVPNResponsePacket(questionPacket, decision.RequestName, vpnproto.Packet{
		SessionID:  vpnPacket.SessionID,
		PacketType: enums.PacketMTUUpRes,
		Payload:    append([]byte(nil), probeKey...),
	}, baseEncode)
	if err != nil {
		return nil
	}
	return response
}

func (s *Server) handleMTUDownRequest(questionPacket []byte, _ dnsparser.LitePacket, decision domainmatcher.Decision, vpnPacket vpnproto.Packet) []byte {
	if len(vpnPacket.Payload) < 1+4+8 {
		return nil
	}

	baseEncode := vpnPacket.Payload[0] == 1
	downloadSize := int(binary.BigEndian.Uint32(vpnPacket.Payload[1:5]))
	if downloadSize < 30 || downloadSize > 4096 {
		return nil
	}

	key := vpnPacket.Payload[5:13]
	payload := make([]byte, downloadSize)
	copy(payload, key)
	if downloadSize > len(key) {
		if _, err := rand.Read(payload[len(key):]); err != nil {
			return nil
		}
	}

	response, err := dnsparser.BuildVPNResponsePacket(questionPacket, decision.RequestName, vpnproto.Packet{
		SessionID:      vpnPacket.SessionID,
		PacketType:     enums.PacketMTUDownRes,
		StreamID:       vpnPacket.StreamID,
		SequenceNum:    vpnPacket.SequenceNum,
		FragmentID:     vpnPacket.FragmentID,
		TotalFragments: vpnPacket.TotalFragments,
		Payload:        payload,
	}, baseEncode)
	if err != nil {
		return nil
	}
	return response
}
