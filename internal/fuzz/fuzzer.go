package fuzz

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/lixiasky/vanta/internal/core"
)

// Fuzzer related structures and functions
type Fuzzer struct {
	payloads []string
	results  chan core.FuzzingResult
	wg       sync.WaitGroup
}

func NewFuzzer(payloadFile string) (*Fuzzer, error) {
	payloads := []string{
		"' OR 1=1 --",
		"../../../../etc/passwd",
		"<script>alert(1)</script>",
		// Add more default payloads here
	}

	if payloadFile != "" {
		// Load custom payloads from file
		data, err := os.ReadFile(payloadFile)
		if err == nil {
			customPayloads := strings.Split(string(data), "\n")
			payloads = append(payloads, customPayloads...)
		}
	}

	return &Fuzzer{
		payloads: payloads,
		results:  make(chan core.FuzzingResult, 100),
	}, nil
}

func (f *Fuzzer) FuzzURL(targetURL string, concurrency int) {
	_, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	semaphore := make(chan struct{}, concurrency)
	for _, payload := range f.payloads {
		f.wg.Add(1)
		semaphore <- struct{}{}
		go func(p string) {
			defer func() {
				<-semaphore
				f.wg.Done()
			}()

			// Create fuzzed URL
			fuzzedURL := strings.Replace(targetURL, "FUZZ", url.QueryEscape(p), -1)
			resp, err := http.Get(fuzzedURL)
			if err != nil {
				return
			}
			defer func() {
				_ = resp.Body.Close()
			}()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Println("read body failed:", err)
			}

			result := core.FuzzingResult{
				Target:  fuzzedURL,
				Payload: p,
			}
			result.Response.StatusCode = resp.StatusCode
			result.Response.Length = len(body)
			result.Response.Anomaly = resp.StatusCode >= 500

			f.results <- result
		}(payload)
	}
}

func (f *Fuzzer) Close() {
	f.wg.Wait()
	close(f.results)
}

// Results exposes the fuzzing result channel for external reading
func (f *Fuzzer) Results() <-chan core.FuzzingResult {
	return f.results
}
