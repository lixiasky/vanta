package core

// PacketInfo represents the decoded packet information
type PacketInfo struct {
	Timestamp string         `json:"timestamp"`
	Protocol  string         `json:"protocol"`
	SrcIP     string         `json:"src_ip"`
	DstIP     string         `json:"dst_ip"`
	SrcPort   uint16         `json:"src_port"`
	DstPort   uint16         `json:"dst_port"`
	HTTPInfo  *HTTPInfo      `json:"http_info,omitempty"`
	TLSInfo   *TLSInfo       `json:"tls_info,omitempty"`
	DNSInfo   *DNSInfo       `json:"dns_info,omitempty"`
	FuzzInfo  *FuzzingResult `json:"fuzz,omitempty"`
}

// HTTPInfo contains decoded HTTP request/response information
type HTTPInfo struct {
	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// TLSInfo contains TLS record information
type TLSInfo struct {
	RecordType     uint8  `json:"record_type"`
	RecordTypeName string `json:"record_type_name"`
	Version        string `json:"version"`
	PayloadLength  uint16 `json:"payload_length"`
}

// DNSInfo contains DNS query/response information
type DNSInfo struct {
	IsQuery    bool   `json:"is_query"`
	QueryName  string `json:"query_name,omitempty"`
	QueryType  string `json:"query_type,omitempty"`
	ResponseIP string `json:"response_ip,omitempty"`
}

// FuzzingResult represents the result of a fuzzing attempt
type FuzzingResult struct {
	Target   string `json:"target"`
	Payload  string `json:"payload"`
	Response struct {
		StatusCode int  `json:"status_code"`
		Length     int  `json:"length"`
		Anomaly    bool `json:"anomaly"`
	} `json:"response"`
}
