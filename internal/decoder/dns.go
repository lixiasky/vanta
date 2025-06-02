package decoder

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"vanta/internal/core"
)

// DNSDecoder implements PacketDecoder for DNS traffic
type DNSDecoder struct{}

// CanDecode checks if the packet contains DNS traffic (UDP port 53)
func (d *DNSDecoder) CanDecode(packet gopacket.Packet) bool {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return udp.DstPort == 53 || udp.SrcPort == 53
	}
	return false
}

// Decode extracts DNS information from the packet
func (d *DNSDecoder) Decode(packet gopacket.Packet) (*core.PacketInfo, error) {
	// Extract required layers: IP, UDP, and DNS
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	// If any layer is missing, this is not a valid DNS packet
	if ipLayer == nil || udpLayer == nil || dnsLayer == nil {
		return nil, fmt.Errorf("missing required layers for DNS decoding")
	}

	// Safe type assertions
	ip, _ := ipLayer.(*layers.IPv4)
	udp, _ := udpLayer.(*layers.UDP)
	dns, _ := dnsLayer.(*layers.DNS)

	// Initialize basic packet info
	info := &core.PacketInfo{
		Timestamp: packet.Metadata().Timestamp.Format(time.RFC3339),
		Protocol:  "DNS",
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		SrcPort:   uint16(udp.SrcPort),
		DstPort:   uint16(udp.DstPort),
	}

	// Parse DNS question section if available
	if len(dns.Questions) > 0 {
		info.DNSInfo = &core.DNSInfo{
			IsQuery:   !dns.QR,
			QueryName: string(dns.Questions[0].Name),
			QueryType: dns.Questions[0].Type.String(),
		}
	}

	// Parse DNS answer section if IP response is available
	if len(dns.Answers) > 0 && dns.Answers[0].IP != nil {
		// Initialize DNSInfo if not already set by Questions
		if info.DNSInfo == nil {
			info.DNSInfo = &core.DNSInfo{}
		}
		info.DNSInfo.ResponseIP = dns.Answers[0].IP.String()
	}

	return info, nil
}
