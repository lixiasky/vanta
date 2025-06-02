package decoder

import "strings"

func parseHTTPHeaders(payload []byte) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(string(payload), "\n")
	for _, line := range lines[1:] { // Skip the first line (request/status line)
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func extractHTTPMethod(payload []byte) string {
	parts := strings.SplitN(string(payload), " ", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func extractHTTPPath(payload []byte) string {
	lines := strings.Split(string(payload), "\n")
	if len(lines) == 0 {
		return ""
	}
	parts := strings.Split(lines[0], " ")
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}
