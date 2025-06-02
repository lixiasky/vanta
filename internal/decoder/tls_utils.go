package decoder

func getTLSRecordType(recordType byte) string {
	switch recordType {
	case 20:
		return "Change Cipher Spec"
	case 21:
		return "Alert"
	case 22:
		return "Handshake"
	case 23:
		return "Application Data"
	default:
		return "Unknown"
	}
}

func getTLSVersion(version []byte) string {
	if len(version) != 2 {
		return "Unknown"
	}
	major := version[0]
	minor := version[1]

	switch {
	case major == 3 && minor == 1:
		return "TLS 1.0"
	case major == 3 && minor == 2:
		return "TLS 1.1"
	case major == 3 && minor == 3:
		return "TLS 1.2"
	case major == 3 && minor == 4:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
