package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"vanta/internal/core"
	"vanta/internal/decoder"
	"vanta/internal/export"
	"vanta/internal/fuzz"
)

func main() {
	// Parse command line flags
	iface := flag.String("iface", "lo0", "Network interface to capture")
	output := flag.String("output", "", "Output file path (optional)")
	noDNS := flag.Bool("no-dns", false, "Disable DNS decoding")
	noTLS := flag.Bool("no-tls", false, "Disable TLS decoding")
	enableFuzz := flag.Bool("fuzz", false, "Enable fuzzing mode")
	fuzzPayloads := flag.String("fuzz-payloads", "", "Custom fuzzing payloads file")
	fuzzConcurrency := flag.Int("fuzz-concurrency", 10, "Number of concurrent fuzzing requests")
	flag.Parse()

	// Graceful shutdown support
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Setup packet capture
	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening device:", err)
	}
	defer handle.Close()

	// Print startup message
	enabled := []string{"HTTP"}
	if !*noTLS {
		enabled = append(enabled, "TLS")
	}
	if !*noDNS {
		enabled = append(enabled, "DNS")
	}
	if *enableFuzz {
		enabled = append(enabled, "Fuzz")
	}
	log.Printf("[VANTA] Packet capture started on interface %s (enabled decoders: %s)\n", *iface, strings.Join(enabled, ", "))

	// Initialize packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// Initialize decoders
	var decoders []core.PacketDecoder
	decoders = append(decoders, &decoder.HTTPDecoder{})
	if !*noTLS {
		decoders = append(decoders, &decoder.TLSDecoder{})
	}
	if !*noDNS {
		decoders = append(decoders, &decoder.DNSDecoder{})
	}

	// Setup output
	var outputFile *os.File
	if *output != "" {
		outputFile, err = os.Create(*output)
		if err != nil {
			log.Fatal("Error creating output file:", err)
		}
		defer func() { _ = outputFile.Close() }()
	}

	// Initialize fuzzer if enabled
	var fuzzer *fuzz.Fuzzer
	if *enableFuzz {
		fuzzer, err = fuzz.NewFuzzer(*fuzzPayloads)
		if err != nil {
			log.Fatal("Error initializing fuzzer:", err)
		}
	}

	// Process packets with graceful exit
captureLoop:
	for {
		select {
		case <-ctx.Done():
			log.Println("[VANTA] Capture stopped. Bye!")
			break captureLoop
		case packet, ok := <-packetChan:
			if !ok {
				break captureLoop
			}
			for _, dec := range decoders {
				if dec.CanDecode(packet) {
					if info, err := dec.Decode(packet); err == nil {
						if *enableFuzz && info.Protocol == "HTTP" && info.HTTPInfo != nil && fuzzer != nil {
							const scheme = "http"
							target := scheme + "://" + info.DstIP + info.HTTPInfo.Path
							go fuzzer.FuzzURL(target, *fuzzConcurrency)
						}
						export.WritePacket(info, outputFile)
					}
				}
			}
		}
	}

	// Cleanup fuzzer if enabled
	if fuzzer != nil {
		fuzzer.Close()
		for result := range fuzzer.Results() {
			export.WriteFuzzResult(result, outputFile)
		}
	}
}
