package routes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// PowerShell's ConvertTo-Json emits three shapes depending on result count:
// nothing at all, a bare object, or an array. parseNetNATJSON must handle all.
func TestParseNetNATJSON(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		for _, input := range []string{"", "   ", "\r\n"} {
			entries, err := parseNetNATJSON([]byte(input))
			require.NoError(t, err)
			require.Empty(t, entries)
		}
	})

	t.Run("single object", func(t *testing.T) {
		input := `{"Name":"awl-gateway","InternalIPInterfaceAddressPrefix":"10.66.0.0/16"}`
		entries, err := parseNetNATJSON([]byte(input))
		require.NoError(t, err)
		require.Equal(t, []netNATEntry{{Name: "awl-gateway", InternalIPInterfaceAddressPrefix: "10.66.0.0/16"}}, entries)
	})

	t.Run("array", func(t *testing.T) {
		input := `[{"Name":"DockerNAT","InternalIPInterfaceAddressPrefix":"172.20.0.0/16"},
			{"Name":"awl-gateway","InternalIPInterfaceAddressPrefix":"10.66.0.0/16"}]`
		entries, err := parseNetNATJSON([]byte(input))
		require.NoError(t, err)
		require.Len(t, entries, 2)

		entry, found := findNetNAT(entries, winNATName)
		require.True(t, found)
		require.Equal(t, "10.66.0.0/16", entry.InternalIPInterfaceAddressPrefix)

		_, found = findNetNAT(entries, "no-such-nat")
		require.False(t, found)
	})

	t.Run("extra fields ignored", func(t *testing.T) {
		input := `{"Name":"awl-gateway","InternalIPInterfaceAddressPrefix":"10.66.0.0/16","Active":true,"Store":"Local"}`
		entries, err := parseNetNATJSON([]byte(input))
		require.NoError(t, err)
		require.Len(t, entries, 1)
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := parseNetNATJSON([]byte(`{"Name":`))
		require.Error(t, err)
		_, err = parseNetNATJSON([]byte(`[{"Name":"x"`))
		require.Error(t, err)
	})
}
