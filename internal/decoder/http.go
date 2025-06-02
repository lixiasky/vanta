package decoder

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"vanta/internal/core"
)

// HTTPDecoder implements PacketDecoder for HTTP traffic
type HTTPDecoder struct{}

// CanDecode checks if the packet contains HTTP traffic
func (d *HTTPDecoder) CanDecode(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.DstPort == 80 || tcp.DstPort == 8080 || tcp.SrcPort == 80 || tcp.SrcPort == 8080
	}
	return false
}

// Decode extracts HTTP information from the packet
func (d *HTTPDecoder) Decode(packet gopacket.Packet) (*core.PacketInfo, error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return nil, fmt.Errorf("missing IP or TCP layer")
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	info := &core.PacketInfo{
		Timestamp: packet.Metadata().Timestamp.Format(time.RFC3339),
		Protocol:  "HTTP",
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
	}

	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return info, nil // No HTTP data
	}

	payload := appLayer.Payload()
	payloadStr := string(payload)

	// Ensure this is really HTTP traffic
	if !(strings.HasPrefix(payloadStr, "GET") ||
		strings.HasPrefix(payloadStr, "POST") ||
		strings.HasPrefix(payloadStr, "HEAD") ||
		strings.HasPrefix(payloadStr, "HTTP")) {
		return nil, fmt.Errorf("not HTTP traffic")
	}

	info.HTTPInfo = &core.HTTPInfo{
		Method:  extractHTTPMethod(payload),
		Path:    extractHTTPPath(payload),
		Headers: parseHTTPHeaders(payload),
	}

	return info, nil
}
