package probe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/gosnmp/gosnmp"
	"github.com/hashicorp/mdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeDiscoverParamsClampingAndValidation(t *testing.T) {
	t.Parallel()

	cfg, err := normalizeDiscoverParams(DiscoverParams{})
	require.NoError(t, err)
	assert.Equal(t, protocolBoth, cfg.protocol)
	assert.Equal(t, 2000*time.Millisecond, cfg.timeout)
	assert.Equal(t, 100, cfg.maxResults)

	cfgMin, err := normalizeDiscoverParams(DiscoverParams{
		Protocol:   "SSDP",
		Service:    "ssdp:all",
		TimeoutMS:  10,
		MaxResults: 1,
	})
	require.NoError(t, err)
	assert.Equal(t, protocolSSDP, cfgMin.protocol)
	assert.Equal(t, 500*time.Millisecond, cfgMin.timeout)
	assert.Equal(t, 1, cfgMin.maxResults)

	cfgMax, err := normalizeDiscoverParams(DiscoverParams{
		Protocol:   "mdns",
		Service:    "_http._tcp",
		TimeoutMS:  60000,
		MaxResults: 9999,
	})
	require.NoError(t, err)
	assert.Equal(t, protocolMDNS, cfgMax.protocol)
	assert.Equal(t, 5000*time.Millisecond, cfgMax.timeout)
	assert.Equal(t, 256, cfgMax.maxResults)

	_, err = normalizeDiscoverParams(DiscoverParams{Protocol: "invalid"})
	require.Error(t, err)

	_, err = normalizeDiscoverParams(DiscoverParams{Service: "bad service"})
	require.Error(t, err)

	_, err = normalizeDiscoverParams(DiscoverParams{Service: "ssdp:all\r\nHOST:evil"})
	require.Error(t, err)
}

func TestSSDPResponderAndGuardFiltering(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	lc := &net.ListenConfig{}
	serverConn, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = serverConn.Close() }()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, readErr := serverConn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			if !strings.Contains(string(buf[:n]), "M-SEARCH") {
				continue
			}

			responses := []string{
				"HTTP/1.1 200 OK\r\n" +
					"ST: urn:schemas-upnp-org:device:Basic:1\r\n" +
					"USN: uuid:device-1::urn:schemas-upnp-org:device:Basic:1\r\n" +
					"LOCATION: http://127.0.0.1:8080/description.xml\r\n" +
					"SERVER: Linux/6.1 UPnP/1.0 TestDevice/1.0\r\n\r\n",
				// Duplicate packet should be deduplicated.
				"HTTP/1.1 200 OK\r\n" +
					"ST: urn:schemas-upnp-org:device:Basic:1\r\n" +
					"USN: uuid:device-1::urn:schemas-upnp-org:device:Basic:1\r\n" +
					"LOCATION: http://127.0.0.1:8080/description.xml\r\n" +
					"SERVER: Linux/6.1 UPnP/1.0 TestDevice/1.0\r\n\r\n",
				// Link-local metadata location must be filtered by TargetGuard.
				"HTTP/1.1 200 OK\r\n" +
					"ST: urn:metadata:evil\r\n" +
					"USN: uuid:evil-metadata\r\n" +
					"LOCATION: http://169.254.169.254/latest/meta-data/\r\n" +
					"SERVER: EvilMeta/1.0\r\n\r\n",
			}
			for _, resp := range responses {
				_, _ = serverConn.WriteTo([]byte(resp), raddr)
			}
		}
	}()

	guard, err := security.NewTargetGuard([]string{"127.0.0.0/8"}, nil)
	require.NoError(t, err)

	cfg := discoverConfig{
		protocol:   protocolSSDP,
		service:    defaultSSDPService,
		timeout:    500 * time.Millisecond,
		maxResults: 10,
	}

	res, err := executeDiscoverWithSSDPAddr(ctx, cfg, serverConn.LocalAddr().String(), guard)
	require.NoError(t, err)
	assert.Equal(t, protocolSSDP, res.Protocol)
	assert.Equal(t, 1, res.Count)
	require.Len(t, res.Services, 1)
	assert.Equal(t, "127.0.0.1", res.Services[0].IP)
	assert.Equal(t, 8080, res.Services[0].Port)
	assert.Equal(t, "http://127.0.0.1:8080/description.xml", res.Services[0].Location)
	assert.NotEmpty(t, res.Warnings)
}

func TestMDNSEntryLinkLocalFiltering(t *testing.T) {
	t.Parallel()

	entry := &mdns.ServiceEntry{
		Name:   "meta._http._tcp.local.",
		Host:   "meta.local.",
		AddrV4: net.ParseIP("169.254.169.254"),
		Port:   80,
	}
	_, warn, ok := convertMDNSEntry(entry, "_http._tcp", nil)
	assert.False(t, ok)
	assert.Contains(t, warn, "169.254.169.254")

	validEntry := &mdns.ServiceEntry{
		Name:   "nas._http._tcp.local.",
		Host:   "nas.local.",
		AddrV4: net.ParseIP("192.168.1.20"),
		Port:   5000,
		Info:   "model=DS920+",
	}
	svc, warn, ok := convertMDNSEntry(validEntry, "_http._tcp", nil)
	assert.True(t, ok)
	assert.Empty(t, warn)
	assert.Equal(t, "192.168.1.20", svc.IP)
	assert.Equal(t, 5000, svc.Port)
}

func TestSNMPValidationAndTargetGuard(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Missing community and env var must return validation error.
	_, err := ExecuteSNMPSwitchPort(ctx, SNMPParams{
		Target:  "127.0.0.1",
		Version: "2c",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidSNMPParams)

	// Missing v3 username must return validation error.
	_, err = ExecuteSNMPSwitchPort(ctx, SNMPParams{
		Target:  "127.0.0.1",
		Version: "3",
	}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidSNMPParams)

	// TargetGuard must block 169.254.169.254 before dialing.
	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	_, err = ExecuteSNMPSwitchPort(ctx, SNMPParams{
		Target:    "169.254.169.254",
		Version:   "2c",
		Community: "readonly",
	}, guard)
	require.Error(t, err)
	assert.ErrorIs(t, err, security.ErrTargetDenied)

	// Valid SNMPv3 AuthPriv parameter combinations.
	flags, usm, err := parseSNMPV3Params(&SNMPParams{
		Username:  "netops",
		AuthProto: "sha256",
		AuthPass:  "auth-secret-123",
		PrivProto: "aes",
		PrivPass:  "priv-secret-456",
	})
	require.NoError(t, err)
	assert.Equal(t, gosnmp.AuthPriv, flags)
	assert.Equal(t, gosnmp.SHA256, usm.AuthenticationProtocol)
	assert.Equal(t, gosnmp.AES, usm.PrivacyProtocol)

	// Priv without Auth must fail.
	_, _, err = parseSNMPV3Params(&SNMPParams{
		Username:  "netops",
		PrivProto: "des",
		PrivPass:  "priv-secret",
	})
	require.Error(t, err)
}

func TestSNMPFDBAndLLDPOIDParsers(t *testing.T) {
	t.Parallel()

	mac, ok := parseFDBMACFromOID(".1.3.6.1.2.1.17.4.3.1.2.0.17.50.170.187.204", oidDot1dTpFdbPort)
	assert.True(t, ok)
	assert.Equal(t, "00:11:32:aa:bb:cc", mac)

	_, ok = parseFDBMACFromOID(".1.3.6.1.2.1.17.4.3.1.2.0.17.999.170.187.204", oidDot1dTpFdbPort)
	assert.False(t, ok)

	_, ok = parseFDBMACFromOID(".1.3.6.1.2.1.17.4.3.1.2.0.17.50", oidDot1dTpFdbPort)
	assert.False(t, ok)

	key, localPort, ok := parseLLDPSuffix(".1.0.8802.1.1.2.1.4.1.1.9.12345.4.1", oidLldpRemSysName)
	assert.True(t, ok)
	assert.Equal(t, "12345.4.1", key)
	assert.Equal(t, 4, localPort)
}

func TestSNMPEnvFallback(t *testing.T) {
	t.Setenv("SNMP_DEFAULT_COMMUNITY", "env-ro")
	cfg, err := normalizeSNMPParams(&SNMPParams{
		Target:  "127.0.0.1",
		Version: "2c",
	})
	require.NoError(t, err)
	assert.Equal(t, "env-ro", cfg.community)

	t.Setenv("SNMP_V3_USERNAME", "env-user")
	t.Setenv("SNMP_V3_AUTH_PROTO", "md5")
	t.Setenv("SNMP_V3_AUTH_PASS", "env-auth")
	cfg3, err := normalizeSNMPParams(&SNMPParams{
		Target:  "127.0.0.1",
		Version: "3",
	})
	require.NoError(t, err)
	assert.Equal(t, gosnmp.AuthNoPriv, cfg3.msgFlags)
	assert.Equal(t, "env-user", cfg3.usm.UserName)
	assert.Equal(t, gosnmp.MD5, cfg3.usm.AuthenticationProtocol)
}

func TestMockSNMPv2cSwitchPortAllModes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mib := []gosnmp.SnmpPDU{
		{Name: oidSysDescr, Type: gosnmp.OctetString, Value: []byte("TestSwitch OS 1.0")},
		{Name: oidSysUpTime, Type: gosnmp.TimeTicks, Value: uint32(9006100)}, // 1d 01:01:01
		{Name: oidSysName, Type: gosnmp.OctetString, Value: []byte("sw-core-01")},
		{Name: oidIfDescr + ".1", Type: gosnmp.OctetString, Value: []byte("Gi1/0/1")},
		{Name: oidIfDescr + ".2", Type: gosnmp.OctetString, Value: []byte("Gi1/0/2")},
		{Name: oidIfPhysAddress + ".1", Type: gosnmp.OctetString, Value: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x01}},
		{Name: oidIfAdminStatus + ".1", Type: gosnmp.Integer, Value: 1},
		{Name: oidIfAdminStatus + ".2", Type: gosnmp.Integer, Value: 1},
		{Name: oidIfOperStatus + ".1", Type: gosnmp.Integer, Value: 1},
		{Name: oidIfOperStatus + ".2", Type: gosnmp.Integer, Value: 2},
		{Name: oidDot1dBasePortIfIdx + ".1", Type: gosnmp.Integer, Value: 1},
		{Name: oidDot1dBasePortIfIdx + ".2", Type: gosnmp.Integer, Value: 2},
		{Name: oidDot1dTpFdbPort + ".170.187.204.221.238.1", Type: gosnmp.Integer, Value: 1},
		{Name: oidDot1dTpFdbStatus + ".170.187.204.221.238.1", Type: gosnmp.Integer, Value: 3},
		{Name: oidIfHighSpeed + ".1", Type: gosnmp.Gauge32, Value: uint32(1000)},
		{Name: oidIfHighSpeed + ".2", Type: gosnmp.Gauge32, Value: uint32(1000)},
		{Name: oidIfAlias + ".1", Type: gosnmp.OctetString, Value: []byte("uplink-ap-01")},
		{Name: oidLldpRemChassisID + ".100.1.1", Type: gosnmp.OctetString, Value: []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02}},
		{Name: oidLldpRemPortID + ".100.1.1", Type: gosnmp.OctetString, Value: []byte("eth0")},
		{Name: oidLldpRemPortDesc + ".100.1.1", Type: gosnmp.OctetString, Value: []byte("LAN Uplink")},
		{Name: oidLldpRemSysName + ".100.1.1", Type: gosnmp.OctetString, Value: []byte("ap-livingroom")},
		{Name: oidLldpRemSysDesc + ".100.1.1", Type: gosnmp.OctetString, Value: []byte("UniFi AP")},
	}

	port, stopServer := startMockSNMPServer(t, ctx, "test-ro", mib)
	defer stopServer()

	guard, err := security.NewTargetGuard([]string{"127.0.0.0/8"}, nil)
	require.NoError(t, err)

	res, err := ExecuteSNMPSwitchPort(ctx, SNMPParams{
		Target:    "127.0.0.1",
		Port:      port,
		Version:   "2c",
		Community: "test-ro",
		Mode:      "all",
	}, guard)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", res.ResolvedIP)
	assert.Equal(t, "sw-core-01", res.SysName)
	assert.Equal(t, "TestSwitch OS 1.0", res.SysDescr)
	assert.Equal(t, "1d 01:01:01", res.SysUpTime)

	require.Len(t, res.Interfaces, 2)
	assert.Equal(t, "Gi1/0/1", res.Interfaces[0].Name)
	assert.Equal(t, "up", res.Interfaces[0].OperStatus)
	assert.Equal(t, uint64(1000), res.Interfaces[0].SpeedMbps)
	assert.Equal(t, "00:11:22:33:44:01", res.Interfaces[0].MAC)
	assert.Equal(t, "uplink-ap-01", res.Interfaces[0].Alias)
	assert.Equal(t, "down", res.Interfaces[1].OperStatus)

	require.Len(t, res.FDB, 1)
	assert.Equal(t, "aa:bb:cc:dd:ee:01", res.FDB[0].MAC)
	assert.Equal(t, 1, res.FDB[0].BridgePort)
	assert.Equal(t, 1, res.FDB[0].IfIndex)
	assert.Equal(t, "Gi1/0/1", res.FDB[0].IfName)
	assert.Equal(t, "learned", res.FDB[0].Status)

	require.Len(t, res.Neighbors, 1)
	assert.Equal(t, 1, res.Neighbors[0].LocalPort)
	assert.Equal(t, "Gi1/0/1", res.Neighbors[0].IfName)
	assert.Equal(t, "aa:bb:cc:00:00:02", res.Neighbors[0].ChassisID)
	assert.Equal(t, "eth0", res.Neighbors[0].PortID)
	assert.Equal(t, "ap-livingroom", res.Neighbors[0].SysName)
}

func startMockSNMPServer(
	t *testing.T,
	ctx context.Context,
	community string,
	entries []gosnmp.SnmpPDU,
) (uint16, func()) {
	t.Helper()

	sorted := append([]gosnmp.SnmpPDU(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		return compareOIDs(sorted[i].Name, sorted[j].Name) < 0
	})

	byOID := make(map[string]gosnmp.SnmpPDU, len(sorted))
	for _, pdu := range sorted {
		byOID[pdu.Name] = pdu
	}

	lc := &net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	require.NoError(t, err)

	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	codec := &gosnmp.GoSNMP{Version: gosnmp.Version2c}

	go func() {
		buf := make([]byte, 8192)
		for {
			n, raddr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			req, decErr := codec.SnmpDecodePacket(buf[:n])
			if decErr != nil || req.Community != community {
				continue
			}

			var respVars []gosnmp.SnmpPDU
			switch req.PDUType {
			case gosnmp.GetRequest:
				for _, v := range req.Variables {
					if pdu, found := byOID[v.Name]; found {
						respVars = append(respVars, pdu)
					} else {
						respVars = append(respVars, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject})
					}
				}
			case gosnmp.GetNextRequest, gosnmp.GetBulkRequest:
				if len(req.Variables) > 0 {
					startOID := req.Variables[0].Name
					maxReps := int(req.MaxRepetitions)
					if req.PDUType == gosnmp.GetNextRequest || maxReps <= 0 {
						maxReps = 1
					}
					for _, pdu := range sorted {
						if compareOIDs(pdu.Name, startOID) > 0 {
							respVars = append(respVars, pdu)
							if len(respVars) >= maxReps {
								break
							}
						}
					}
					if len(respVars) == 0 {
						respVars = append(respVars, gosnmp.SnmpPDU{Name: startOID, Type: gosnmp.EndOfMibView})
					}
				}
			}

			respPkt := &gosnmp.SnmpPacket{
				Version:   gosnmp.Version2c,
				Community: req.Community,
				PDUType:   gosnmp.GetResponse,
				RequestID: req.RequestID,
				Variables: respVars,
			}
			wire, encErr := respPkt.MarshalMsg()
			if encErr == nil {
				_, _ = conn.WriteTo(wire, raddr)
			}
		}
	}()

	return uint16(udpAddr.Port), func() { _ = conn.Close() }
}

func compareOIDs(a, b string) int {
	pa := splitOIDParts(a)
	pb := splitOIDParts(b)
	n := min(len(pa), len(pb))
	for i := range n {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	switch {
	case len(pa) < len(pb):
		return -1
	case len(pa) > len(pb):
		return 1
	default:
		return 0
	}
}

func splitOIDParts(oid string) []int {
	trimmed := strings.TrimPrefix(oid, ".")
	if trimmed == "" {
		return nil
	}
	raw := strings.Split(trimmed, ".")
	parts := make([]int, 0, len(raw))
	for _, s := range raw {
		v, err := strconv.Atoi(s)
		if err != nil {
			panic(fmt.Sprintf("invalid test OID %q: %v", oid, err))
		}
		parts = append(parts, v)
	}
	return parts
}
