package netstate

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// winNATName is the name of the WinNAT instance owned by awl on Windows.
// Referenced from cross-platform code only through this file so the JSON
// parsing below stays unit-testable on every OS.
const winNATName = "awl-gateway"

// netNATEntry is one WinNAT instance as reported by
// `Get-NetNat | ConvertTo-Json`.
type netNATEntry struct {
	Name                             string `json:"Name"`
	InternalIPInterfaceAddressPrefix string `json:"InternalIPInterfaceAddressPrefix"`
}

// parseNetNATJSON parses `Get-NetNat | ConvertTo-Json -Compress` output.
// PowerShell emits nothing for an empty result, a single JSON object for one
// instance, and a JSON array for several — all three shapes are handled.
func parseNetNATJSON(data []byte) ([]netNATEntry, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] == '[' {
		var entries []netNATEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("parse Get-NetNat JSON array: %w", err)
		}
		return entries, nil
	}
	var entry netNATEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("parse Get-NetNat JSON object: %w", err)
	}
	return []netNATEntry{entry}, nil
}

// findNetNAT returns the entry with the given name, if present.
func findNetNAT(entries []netNATEntry, name string) (netNATEntry, bool) {
	for _, e := range entries {
		if e.Name == name {
			return e, true
		}
	}
	return netNATEntry{}, false
}
