package core

import "github.com/google/gopacket"

// PacketDecoder interface defines methods for protocol-specific decoders
type PacketDecoder interface {
	CanDecode(packet gopacket.Packet) bool
	Decode(packet gopacket.Packet) (*PacketInfo, error)
}
