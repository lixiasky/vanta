package export

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/lixiasky/vanta/internal/core"
)

// WritePacket prints the packet info to stdout and optionally writes to a file.
func WritePacket(info *core.PacketInfo, outputFile *os.File) {
	jsonData, err := json.Marshal(info)
	if err != nil {
		return
	}

	// Always print to terminal
	fmt.Println(string(jsonData))

	// Optionally write to output file
	if outputFile != nil {
		_, _ = fmt.Fprintln(outputFile, string(jsonData))
	}
}

// WriteFuzzResult prints the fuzzing result to stdout and optionally writes to a file.
func WriteFuzzResult(result core.FuzzingResult, outputFile *os.File) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		return
	}

	// Always print to terminal
	fmt.Println(string(jsonData))

	// Optionally write to output file
	if outputFile != nil {
		_, _ = fmt.Fprintln(outputFile, string(jsonData))
	}
}
