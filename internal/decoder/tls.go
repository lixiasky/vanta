package decoder

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"vanta/internal/core"
)

// TLSDecoder implements PacketDecoder for TLS traffic
type TLSDecoder struct{}

// CanDecode checks if the packet contains TLS traffic
func (d *TLSDecoder) CanDecode(packet gopacket.Packet) bool {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.DstPort == 443 || tcp.SrcPort == 443
	}
	return false
}

// Decode extracts TLS record information from the packet
func (d *TLSDecoder) Decode(packet gopacket.Packet) (*core.PacketInfo, error) {
	// Extract necessary layers
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return nil, fmt.Errorf("missing IP or TCP layer")
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	// Initialize packet info structure
	info := &core.PacketInfo{
		Timestamp: packet.Metadata().Timestamp.Format(time.RFC3339),
		Protocol:  "TLS",
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
	}

	// Check for application payload (likely TLS)
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload := appLayer.Payload()

		// TLS record must be at least 5 bytes to decode type/version/length
		if len(payload) >= 5 {
			info.TLSInfo = &core.TLSInfo{
				RecordType:     payload[0],
				RecordTypeName: getTLSRecordType(payload[0]),
				Version:        getTLSVersion(payload[1:3]),
				PayloadLength:  binary.BigEndian.Uint16(payload[3:5]),
			}
		}
	}

	return info, nil
}
