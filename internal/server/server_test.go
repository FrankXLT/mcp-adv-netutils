package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/dispatch"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/FrankXLT/mcp-adv-netutils/internal/server"
	"github.com/FrankXLT/mcp-adv-netutils/internal/transport"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPassphrase = "open sesame"

func newLockedDeadbolt() *security.Deadbolt {
	return security.NewDeadbolt(security.DeadboltConfig{
		PassHash: security.NormalizePhrase(testPassphrase),
		TTL:      10 * time.Minute,
	})
}

func invokeTool(t *testing.T, ctx context.Context, s *mcpserver.MCPServer, name string, args map[string]any) (string, bool) {
	t.Helper()
	st := s.GetTool(name)
	require.NotNilf(t, st, "tool %q must be registered", name)
	res, err := st.Handler(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.Content)
	tc, ok := res.Content[0].(mcp.TextContent)
	require.True(t, ok, "expected TextContent from %s", name)
	return tc.Text, res.IsError
}

func TestSetupServerRegistersAll33ToolsAndDefaults(t *testing.T) {
	t.Parallel()

	s, err := server.SetupTools(nil)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Len(t, s.ListTools(), 33)

	srv, disp, err := server.SetupServerWithDispatcher(nil)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.NotNil(t, disp)
	assert.Equal(t, "2.1.0", disp.Version())

	tools := srv.ListTools()
	canonical := disp.ToolNames()
	require.Len(t, canonical, 33)
	require.Len(t, tools, 33)

	for _, name := range canonical {
		st, ok := tools[name]
		require.Truef(t, ok, "missing registered tool %q", name)

		styleProp, hasStyle := st.Tool.InputSchema.Properties["style"].(map[string]any)
		require.Truef(t, hasStyle, "tool %q missing style property", name)
		assert.Equal(t, "default", styleProp["default"])
		assert.Equal(t, []string{"default", "quick", "rich", "json"}, styleProp["enum"])
	}

	portScan := srv.GetTool("tcp_port_scan")
	require.NotNil(t, portScan)
	portsProp, ok := portScan.Tool.InputSchema.Properties["ports"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "common", portsProp["default"])

	cronStatus := srv.GetTool("get_cron_status")
	require.NotNil(t, cronStatus)
	periodProp, ok := cronStatus.Tool.InputSchema.Properties["period"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "30d", periodProp["default"])
	assert.Equal(t, []string{"24h", "7d", "30d"}, periodProp["enum"])

	watchlist := srv.GetTool("manage_cron_watchlist")
	require.NotNil(t, watchlist)
	actionProp, ok := watchlist.Tool.InputSchema.Properties["action"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []string{"list", "add", "update", "remove", "pause", "resume", "run_now"}, actionProp["enum"])

	destTool := srv.GetTool("manage_saved_destinations")
	require.NotNil(t, destTool)
	destActionProp, ok := destTool.Tool.InputSchema.Properties["action"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []string{"list", "save", "delete", "run"}, destActionProp["enum"])

	digestTool := srv.GetTool("render_run_digest")
	require.NotNil(t, digestTool)
	expectedDigestProps := map[string]string{
		"job_ids":        "array",
		"window":         "string",
		"since":          "string",
		"until":          "string",
		"target":         "string",
		"tool_name":      "string",
		"status":         "string",
		"incidents_only": "boolean",
		"limit":          "number",
	}
	for propName, wantType := range expectedDigestProps {
		prop, hasProp := digestTool.Tool.InputSchema.Properties[propName].(map[string]any)
		require.Truef(t, hasProp, "render_run_digest missing property %q", propName)
		assert.Equalf(t, wantType, prop["type"], "render_run_digest property %q type", propName)
	}
}

func TestSetupServerReusesProvidedDispatcher(t *testing.T) {
	t.Parallel()

	customDisp, err := dispatch.New(dispatch.Config{Version: "2.3.4"})
	require.NoError(t, err)

	srv, gotDisp, err := server.SetupServerWithDispatcher(&server.NetUtilsConfig{
		Version:    "2.3.4",
		Dispatcher: customDisp,
	})
	require.NoError(t, err)
	assert.Same(t, customDisp, gotDisp)
	assert.Len(t, srv.ListTools(), 33)
}

func TestDefaultStdioAllowsMacLookupWithoutDoorway(t *testing.T) {
	t.Parallel()

	db := newLockedDeadbolt()
	srv, _, err := server.SetupServerWithDispatcher(&server.NetUtilsConfig{
		Deadbolt:     db,
		DefaultStdio: true,
	})
	require.NoError(t, err)

	out, isErr := invokeTool(t, t.Context(), srv, "mac_vendor_lookup", map[string]any{
		"mac": "00:11:32:AA:BB:CC",
	})
	assert.False(t, isErr)
	assert.Contains(t, out, "00:11:32:AA:BB:CC")

	remoteCtx := transport.WithDoorway(t.Context(), transport.DoorwayRemote)
	out, isErr = invokeTool(t, remoteCtx, srv, "mac_vendor_lookup", map[string]any{
		"mac": "00:11:32:AA:BB:CC",
	})
	assert.True(t, isErr)
	assert.Contains(t, out, "deadbolt is locked")
}

func TestDoorwayRemoteDeadboltUnlockStylesAndRelock(t *testing.T) {
	t.Parallel()

	db := newLockedDeadbolt()
	srv, _, err := server.SetupServerWithDispatcher(&server.NetUtilsConfig{
		Deadbolt:     db,
		DefaultStdio: false,
	})
	require.NoError(t, err)

	remoteCtx := transport.WithDoorway(t.Context(), transport.DoorwayRemote)

	out, isErr := invokeTool(t, remoteCtx, srv, "mac_vendor_lookup", map[string]any{
		"mac": "9C:8E:CD:0A:91:0C",
	})
	assert.True(t, isErr)
	assert.Contains(t, out, "deadbolt is locked")

	unlockOut, isErr := invokeTool(t, remoteCtx, srv, "unlock_netutils", map[string]any{
		"passphrase": testPassphrase,
	})
	assert.False(t, isErr)
	assert.NotEmpty(t, unlockOut)
	assert.True(t, db.IsUnlocked())

	styles := []string{"default", "quick", "rich", "json"}
	outputs := make(map[string]string, len(styles))
	for _, style := range styles {
		resOut, resErr := invokeTool(t, remoteCtx, srv, "mac_vendor_lookup", map[string]any{
			"mac":   "9C:8E:CD:0A:91:0C",
			"style": style,
		})
		assert.Falsef(t, resErr, "style %s failed: %s", style, resOut)
		assert.NotEmpty(t, resOut)
		outputs[style] = resOut
	}

	assert.True(t, json.Valid([]byte(outputs["json"])), "json style output must be valid JSON")
	assert.NotEqual(t, outputs["quick"], outputs["rich"])

	lockOut, isErr := invokeTool(t, remoteCtx, srv, "lock_netutils", nil)
	assert.False(t, isErr)
	assert.Contains(t, lockOut, "locked")
	assert.False(t, db.IsUnlocked())

	blockedOut, isErr := invokeTool(t, remoteCtx, srv, "mac_vendor_lookup", map[string]any{
		"mac": "9C:8E:CD:0A:91:0C",
	})
	assert.True(t, isErr)
	assert.Contains(t, blockedOut, "deadbolt is locked")
}

func TestDoorwayLANBypassesDeadboltAndSurfacesValidationErrors(t *testing.T) {
	t.Parallel()

	db := newLockedDeadbolt()
	srv, _, err := server.SetupServerWithDispatcher(&server.NetUtilsConfig{
		Deadbolt:     db,
		DefaultStdio: false,
	})
	require.NoError(t, err)

	lanCtx := transport.WithDoorway(t.Context(), transport.DoorwayLAN)

	out, isErr := invokeTool(t, lanCtx, srv, "mac_vendor_lookup", map[string]any{
		"mac": "02:42:AC:11:00:02",
	})
	assert.False(t, isErr)
	assert.Contains(t, out, "02:42:AC:11:00:02")

	errOut, isErr := invokeTool(t, lanCtx, srv, "mac_vendor_lookup", map[string]any{
		"mac": "invalid-mac",
	})
	assert.True(t, isErr)
	assert.Contains(t, errOut, "mac_vendor_lookup")

	// manage_saved_destinations without store surfaces error cleanly
	destOut, isErr := invokeTool(t, lanCtx, srv, "manage_saved_destinations", map[string]any{
		"action": "list",
	})
	assert.True(t, isErr)
	assert.Contains(t, destOut, "job store")
}
