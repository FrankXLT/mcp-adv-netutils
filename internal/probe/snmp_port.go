package probe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/gosnmp/gosnmp"
)

// SNMPParams defines parameters for read-only SNMP switch/device port probing.
type SNMPParams struct {
	Target     string `json:"target"`
	Port       uint16 `json:"port,omitempty"`
	Version    string `json:"version,omitempty"`
	Community  string `json:"community,omitempty"`
	Username   string `json:"username,omitempty"`
	AuthProto  string `json:"auth_proto,omitempty"`
	AuthPass   string `json:"auth_pass,omitempty"`
	PrivProto  string `json:"priv_proto,omitempty"`
	PrivPass   string `json:"priv_pass,omitempty"`
	Mode       string `json:"mode,omitempty"`
	MaxEntries int    `json:"max_entries,omitempty"`
}

// SNMPInterface represents an interface entry from IF-MIB.
type SNMPInterface struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	OperStatus  string `json:"oper_status,omitempty"`
	AdminStatus string `json:"admin_status,omitempty"`
	SpeedMbps   uint64 `json:"speed_mbps,omitempty"`
	MAC         string `json:"mac,omitempty"`
	Alias       string `json:"alias,omitempty"`
}

// SNMPFDBEntry represents a Bridge-MIB forwarding database MAC-to-port entry.
type SNMPFDBEntry struct {
	MAC        string `json:"mac"`
	BridgePort int    `json:"bridge_port"`
	IfIndex    int    `json:"if_index,omitempty"`
	IfName     string `json:"if_name,omitempty"`
	Status     string `json:"status,omitempty"`
}

// SNMPNeighbor represents an LLDP-MIB remote neighbor entry.
type SNMPNeighbor struct {
	LocalPort int    `json:"local_port"`
	IfName    string `json:"if_name,omitempty"`
	ChassisID string `json:"chassis_id,omitempty"`
	PortID    string `json:"port_id,omitempty"`
	PortDesc  string `json:"port_desc,omitempty"`
	SysName   string `json:"sys_name,omitempty"`
	SysDesc   string `json:"sys_desc,omitempty"`
}

// SNMPResult holds read-only SNMP probe output.
type SNMPResult struct {
	Target     string          `json:"target"`
	ResolvedIP string          `json:"resolved_ip"`
	SysName    string          `json:"sys_name,omitempty"`
	SysDescr   string          `json:"sys_descr,omitempty"`
	SysUpTime  string          `json:"sys_uptime,omitempty"`
	Interfaces []SNMPInterface `json:"interfaces,omitempty"`
	FDB        []SNMPFDBEntry  `json:"fdb,omitempty"`
	Neighbors  []SNMPNeighbor  `json:"neighbors,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	Timestamp  string          `json:"timestamp"`
}

type snmpConfig struct {
	target     string
	port       uint16
	version    gosnmp.SnmpVersion
	community  string
	msgFlags   gosnmp.SnmpV3MsgFlags
	usm        *gosnmp.UsmSecurityParameters
	mode       string
	maxEntries int
}

type oidWalkStep[T any] struct {
	oid   string
	apply func(entry *T, pdu gosnmp.SnmpPDU)
}

const (
	oidSysDescr           = ".1.3.6.1.2.1.1.1.0"
	oidSysUpTime          = ".1.3.6.1.2.1.1.3.0"
	oidSysName            = ".1.3.6.1.2.1.1.5.0"
	oidIfDescr            = ".1.3.6.1.2.1.2.2.1.2"
	oidIfPhysAddress      = ".1.3.6.1.2.1.2.2.1.6"
	oidIfAdminStatus      = ".1.3.6.1.2.1.2.2.1.7"
	oidIfOperStatus       = ".1.3.6.1.2.1.2.2.1.8"
	oidIfHighSpeed        = ".1.3.6.1.2.1.31.1.1.1.15"
	oidIfAlias            = ".1.3.6.1.2.1.31.1.1.1.18"
	oidDot1dBasePortIfIdx = ".1.3.6.1.2.1.17.1.4.1.2"
	oidDot1dTpFdbPort     = ".1.3.6.1.2.1.17.4.3.1.2"
	oidDot1dTpFdbStatus   = ".1.3.6.1.2.1.17.4.3.1.3"
	oidLldpRemChassisID   = ".1.0.8802.1.1.2.1.4.1.1.5"
	oidLldpRemPortID      = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLldpRemPortDesc    = ".1.0.8802.1.1.2.1.4.1.1.8"
	oidLldpRemSysName     = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidLldpRemSysDesc     = ".1.0.8802.1.1.2.1.4.1.1.10"
)

var (
	errInvalidSNMPParams = errors.New("invalid SNMP parameters")
	authProtoMap         = map[string]gosnmp.SnmpV3AuthProtocol{"": gosnmp.NoAuth, "none": gosnmp.NoAuth, "md5": gosnmp.MD5, "sha": gosnmp.SHA, "sha1": gosnmp.SHA, "sha256": gosnmp.SHA256}
	privProtoMap         = map[string]gosnmp.SnmpV3PrivProtocol{"": gosnmp.NoPriv, "none": gosnmp.NoPriv, "des": gosnmp.DES, "aes": gosnmp.AES, "aes128": gosnmp.AES}
	ifStatusNames        = map[int]string{1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
	fdbStatusNames       = map[int]string{1: "other", 2: "invalid", 3: "learned", 4: "self", 5: "mgmt"}
)

// ExecuteSNMPSwitchPort performs a strictly read-only SNMPv2c or SNMPv3 probe after guard validation.
//
//nolint:gocritic // Exported API accepts SNMPParams value cleanly.
func ExecuteSNMPSwitchPort(ctx context.Context, params SNMPParams, guard *security.TargetGuard) (*SNMPResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", errInvalidSNMPParams)
	}
	cfg, err := normalizeSNMPParams(&params)
	if err != nil {
		return nil, err
	}
	ips, err := guard.ValidateHostOrIP(ctx, cfg.target)
	if err != nil {
		return nil, fmt.Errorf("target validation failed: %w", err)
	}
	resolvedIP := ips[0]
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			resolvedIP = v4
			break
		}
	}

	client := &gosnmp.GoSNMP{
		Target: resolvedIP.String(), Port: cfg.port, Transport: "udp", Version: cfg.version, Community: cfg.community,
		Context: ctx, Timeout: 3 * time.Second, Retries: 1, MaxOids: gosnmp.MaxOids, MaxRepetitions: 25,
	}
	if cfg.version == gosnmp.Version3 {
		client.SecurityModel, client.MsgFlags, client.SecurityParameters = gosnmp.UserSecurityModel, cfg.msgFlags, cfg.usm
	}
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect to %s:%d failed: %w", resolvedIP.String(), cfg.port, err)
	}
	defer func() {
		if client.Conn != nil {
			_ = client.Conn.Close()
		}
	}()

	res := &SNMPResult{Target: cfg.target, ResolvedIP: resolvedIP.String(), Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if err := collectSystemInfo(client, res); err != nil {
		return nil, err
	}
	return res, populateSNMPModeData(client, &cfg, res)
}

func populateSNMPModeData(client *gosnmp.GoSNMP, cfg *snmpConfig, res *SNMPResult) error {
	var ifNames map[int]string
	if cfg.mode == "summary" || cfg.mode == "interfaces" || cfg.mode == "all" {
		ifaces, warns, err := collectInterfaces(client, cfg.maxEntries, cfg.mode != "summary")
		res.Warnings = append(res.Warnings, warns...)
		if err != nil {
			return err
		}
		res.Interfaces = ifaces
		ifNames = make(map[int]string, len(ifaces))
		for i := range ifaces {
			ifNames[ifaces[i].Index] = ifaces[i].Name
		}
	}
	if cfg.mode == "fdb" || cfg.mode == "all" {
		if err := applyOptionalMIB(func() ([]SNMPFDBEntry, []string, error) { return collectFDB(client, ifNames, cfg.maxEntries) }, cfg.mode == "fdb", "fdb", &res.FDB, &res.Warnings); err != nil {
			return err
		}
	}
	if cfg.mode == "lldp" || cfg.mode == "all" {
		if err := applyOptionalMIB(func() ([]SNMPNeighbor, []string, error) { return collectLLDP(client, ifNames, cfg.maxEntries) }, cfg.mode == "lldp", "lldp", &res.Neighbors, &res.Warnings); err != nil {
			return err
		}
	}
	return nil
}

func applyOptionalMIB[T any](fn func() ([]T, []string, error), strict bool, label string, dst *[]T, warns *[]string) error {
	items, w, err := fn()
	*warns = append(*warns, w...)
	if err == nil {
		*dst = items
		return nil
	}
	if strict {
		return err
	}
	*warns = append(*warns, fmt.Sprintf("%s walk skipped: %v", label, err))
	return nil
}

func normalizeSNMPParams(params *SNMPParams) (snmpConfig, error) {
	target := strings.TrimSpace(params.Target)
	if target == "" {
		return snmpConfig{}, fmt.Errorf("%w: target must not be empty", errInvalidSNMPParams)
	}
	port := params.Port
	if port == 0 {
		port = 161
	}
	mode := strings.ToLower(strings.TrimSpace(firstNonEmpty(params.Mode, "summary")))
	if mode != "summary" && mode != "interfaces" && mode != "fdb" && mode != "lldp" && mode != "all" {
		return snmpConfig{}, fmt.Errorf("%w: unsupported mode %q", errInvalidSNMPParams, params.Mode)
	}
	cfg := snmpConfig{target: target, port: port, mode: mode, maxEntries: clampProbeInt(params.MaxEntries, 128, 1, 1024)}
	switch strings.ToLower(strings.TrimSpace(params.Version)) {
	case "", "2c", "v2c":
		community := strings.TrimSpace(firstNonEmpty(params.Community, os.Getenv("SNMP_DEFAULT_COMMUNITY")))
		if community == "" {
			return snmpConfig{}, fmt.Errorf("%w: SNMPv2c community is required (set community or SNMP_DEFAULT_COMMUNITY)", errInvalidSNMPParams)
		}
		cfg.version, cfg.community = gosnmp.Version2c, community
	case "3", "v3":
		flags, usm, err := parseSNMPV3Params(params)
		if err != nil {
			return snmpConfig{}, err
		}
		cfg.version, cfg.msgFlags, cfg.usm = gosnmp.Version3, flags, usm
	default:
		return snmpConfig{}, fmt.Errorf("%w: unsupported SNMP version %q (use 2c or 3)", errInvalidSNMPParams, params.Version)
	}
	return cfg, nil
}

func parseSNMPV3Params(params *SNMPParams) (gosnmp.SnmpV3MsgFlags, *gosnmp.UsmSecurityParameters, error) {
	user := strings.TrimSpace(firstNonEmpty(params.Username, os.Getenv("SNMP_V3_USERNAME")))
	if user == "" {
		return 0, nil, fmt.Errorf("%w: SNMPv3 username is required (set username or SNMP_V3_USERNAME)", errInvalidSNMPParams)
	}
	aStr := strings.ToLower(strings.TrimSpace(firstNonEmpty(params.AuthProto, os.Getenv("SNMP_V3_AUTH_PROTO"))))
	aPass := firstNonEmpty(params.AuthPass, os.Getenv("SNMP_V3_AUTH_PASS"))
	pStr := strings.ToLower(strings.TrimSpace(firstNonEmpty(params.PrivProto, os.Getenv("SNMP_V3_PRIV_PROTO"))))
	pPass := firstNonEmpty(params.PrivPass, os.Getenv("SNMP_V3_PRIV_PASS"))

	aProto, okA := authProtoMap[aStr]
	pProto, okP := privProtoMap[pStr]
	if !okA || !okP {
		return 0, nil, fmt.Errorf("%w: unsupported SNMPv3 auth_proto %q or priv_proto %q", errInvalidSNMPParams, aStr, pStr)
	}
	if (pProto != gosnmp.NoPriv && aProto == gosnmp.NoAuth) || (aProto != gosnmp.NoAuth && aPass == "") || (pProto != gosnmp.NoPriv && pPass == "") {
		return 0, nil, fmt.Errorf("%w: invalid SNMPv3 auth/priv protocol and passphrase combination", errInvalidSNMPParams)
	}
	flags := gosnmp.NoAuthNoPriv
	if aProto != gosnmp.NoAuth {
		flags = gosnmp.AuthNoPriv
		if pProto != gosnmp.NoPriv {
			flags = gosnmp.AuthPriv
		}
	}
	return flags, &gosnmp.UsmSecurityParameters{UserName: user, AuthenticationProtocol: aProto, AuthenticationPassphrase: aPass, PrivacyProtocol: pProto, PrivacyPassphrase: pPass}, nil
}

func collectSystemInfo(client *gosnmp.GoSNMP, res *SNMPResult) error {
	pkt, err := client.Get([]string{oidSysDescr, oidSysUpTime, oidSysName})
	if err != nil {
		return fmt.Errorf("snmp system Get failed: %w", err)
	}
	if pkt == nil {
		return errors.New("snmp system Get returned empty packet")
	}
	for _, pdu := range pkt.Variables {
		switch "." + strings.TrimPrefix(pdu.Name, ".") {
		case oidSysDescr:
			res.SysDescr = formatSNMPValueString(pdu)
		case oidSysName:
			res.SysName = formatSNMPValueString(pdu)
		case oidSysUpTime:
			if bi := gosnmp.ToBigInt(pdu.Value); bi != nil && bi.IsUint64() {
				sec := bi.Uint64() / 100
				res.SysUpTime = fmt.Sprintf("%02d:%02d:%02d", (sec%86400)/3600, (sec%3600)/60, sec%60)
				if d := sec / 86400; d > 0 {
					res.SysUpTime = fmt.Sprintf("%dd %s", d, res.SysUpTime)
				}
			}
		}
	}
	return nil
}

func collectInterfaces(client *gosnmp.GoSNMP, maxEntries int, detailed bool) ([]SNMPInterface, []string, error) {
	steps := []oidWalkStep[SNMPInterface]{
		{oidIfDescr, func(e *SNMPInterface, p gosnmp.SnmpPDU) { e.Name = formatSNMPValueString(p) }},
		{oidIfOperStatus, func(e *SNMPInterface, p gosnmp.SnmpPDU) { e.OperStatus = mapIntLookup(p, ifStatusNames) }},
		{oidIfHighSpeed, func(e *SNMPInterface, p gosnmp.SnmpPDU) {
			if bi := gosnmp.ToBigInt(p.Value); bi != nil && bi.IsUint64() {
				e.SpeedMbps = bi.Uint64()
			}
		}},
	}
	if detailed {
		steps = append(steps,
			oidWalkStep[SNMPInterface]{oidIfAdminStatus, func(e *SNMPInterface, p gosnmp.SnmpPDU) { e.AdminStatus = mapIntLookup(p, ifStatusNames) }},
			oidWalkStep[SNMPInterface]{oidIfPhysAddress, func(e *SNMPInterface, p gosnmp.SnmpPDU) {
				if b, ok := p.Value.([]byte); ok && len(b) > 0 {
					e.MAC = net.HardwareAddr(b).String()
				}
			}},
			oidWalkStep[SNMPInterface]{oidIfAlias, func(e *SNMPInterface, p gosnmp.SnmpPDU) { e.Alias = formatSNMPValueString(p) }},
		)
	}
	return walkSortedMIB(client, steps, oidIfDescr, func(pduName, baseOID string) (int, *SNMPInterface, bool) {
		idx, ok := parseTrailingInt(pduName, baseOID)
		return idx, &SNMPInterface{Index: idx}, ok
	}, func(a, b *SNMPInterface) bool { return a.Index < b.Index }, maxEntries, "interfaces")
}

func collectFDB(client *gosnmp.GoSNMP, ifNames map[int]string, maxEntries int) ([]SNMPFDBEntry, []string, error) {
	portToIfIdx := make(map[int]int)
	if basePDUs, err := client.BulkWalkAll(oidDot1dBasePortIfIdx); err == nil {
		for _, pdu := range basePDUs {
			if bPort, ok := parseTrailingInt(pdu.Name, oidDot1dBasePortIfIdx); ok {
				if ifIdx, okVal := pduInt(pdu); okVal {
					portToIfIdx[bPort] = ifIdx
				}
			}
		}
	}
	steps := []oidWalkStep[SNMPFDBEntry]{
		{oidDot1dTpFdbPort, func(e *SNMPFDBEntry, p gosnmp.SnmpPDU) {
			if bPort, ok := pduInt(p); ok {
				e.BridgePort, e.IfIndex, e.IfName = bPort, portToIfIdx[bPort], ifNames[portToIfIdx[bPort]]
			}
		}},
		{oidDot1dTpFdbStatus, func(e *SNMPFDBEntry, p gosnmp.SnmpPDU) { e.Status = mapIntLookup(p, fdbStatusNames) }},
	}
	return walkSortedMIB(client, steps, oidDot1dTpFdbPort, func(pduName, baseOID string) (string, *SNMPFDBEntry, bool) {
		mac, ok := parseFDBMACFromOID(pduName, baseOID)
		return mac, &SNMPFDBEntry{MAC: mac}, ok
	}, func(a, b *SNMPFDBEntry) bool {
		if a.BridgePort != b.BridgePort {
			return a.BridgePort < b.BridgePort
		}
		return a.MAC < b.MAC
	}, maxEntries, "fdb entries")
}

func collectLLDP(client *gosnmp.GoSNMP, ifNames map[int]string, maxEntries int) ([]SNMPNeighbor, []string, error) {
	steps := []oidWalkStep[SNMPNeighbor]{
		{oidLldpRemChassisID, func(e *SNMPNeighbor, p gosnmp.SnmpPDU) { e.ChassisID = formatLLDPID(p) }},
		{oidLldpRemPortID, func(e *SNMPNeighbor, p gosnmp.SnmpPDU) { e.PortID = formatLLDPID(p) }},
		{oidLldpRemPortDesc, func(e *SNMPNeighbor, p gosnmp.SnmpPDU) { e.PortDesc = formatSNMPValueString(p) }},
		{oidLldpRemSysName, func(e *SNMPNeighbor, p gosnmp.SnmpPDU) { e.SysName = formatSNMPValueString(p) }},
		{oidLldpRemSysDesc, func(e *SNMPNeighbor, p gosnmp.SnmpPDU) { e.SysDesc = formatSNMPValueString(p) }},
	}
	return walkSortedMIB(client, steps, "", func(pduName, baseOID string) (string, *SNMPNeighbor, bool) {
		key, localPort, ok := parseLLDPSuffix(pduName, baseOID)
		return key, &SNMPNeighbor{LocalPort: localPort, IfName: ifNames[localPort]}, ok
	}, func(a, b *SNMPNeighbor) bool {
		if a.LocalPort != b.LocalPort {
			return a.LocalPort < b.LocalPort
		}
		return a.SysName < b.SysName
	}, maxEntries, "lldp neighbors")
}

func walkSortedMIB[K comparable, V any](client *gosnmp.GoSNMP, steps []oidWalkStep[V], requiredOID string, newEntry func(string, string) (K, *V, bool), less func(a, b *V) bool, maxEntries int, label string) ([]V, []string, error) {
	byKey := make(map[K]*V)
	var firstErr error
	succeeded := 0
	for _, step := range steps {
		pdus, err := client.BulkWalkAll(step.oid)
		if err != nil {
			if step.oid == requiredOID {
				return nil, nil, fmt.Errorf("snmp walk %s failed: %w", step.oid, err)
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("snmp walk %s failed: %w", step.oid, err)
			}
			continue
		}
		succeeded++
		for _, pdu := range pdus {
			if key, fresh, ok := newEntry(pdu.Name, step.oid); ok {
				entry, exists := byKey[key]
				if !exists {
					entry = fresh
					byKey[key] = entry
				}
				step.apply(entry, pdu)
			}
		}
	}
	if requiredOID == "" && succeeded == 0 && firstErr != nil {
		return nil, nil, firstErr
	}
	out := make([]V, 0, len(byKey))
	for _, v := range byKey {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return less(&out[i], &out[j]) })
	var warns []string
	if len(out) > maxEntries {
		out = out[:maxEntries]
		warns = append(warns, fmt.Sprintf("%s truncated to max_entries=%d", label, maxEntries))
	}
	return out, warns, nil
}

func oidSuffix(oid, baseOID string) (string, bool) {
	return strings.CutPrefix("."+strings.TrimPrefix(oid, "."), "."+strings.TrimPrefix(baseOID, ".")+".")
}

func parseFDBMACFromOID(oid, baseOID string) (string, bool) {
	suffix, ok := oidSuffix(oid, baseOID)
	parts := strings.Split(suffix, ".")
	if !ok || len(parts) != 6 {
		return "", false
	}
	mac := make(net.HardwareAddr, 6)
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return "", false
		}
		mac[i] = byte(v)
	}
	return mac.String(), true
}

func parseLLDPSuffix(oid, baseOID string) (string, int, bool) {
	suffix, ok := oidSuffix(oid, baseOID)
	parts := strings.Split(suffix, ".")
	if !ok || len(parts) < 3 {
		return "", 0, false
	}
	localPort, err := strconv.Atoi(parts[1])
	return suffix, localPort, err == nil && localPort >= 0
}

func parseTrailingInt(oid, baseOID string) (int, bool) {
	suffix, ok := oidSuffix(oid, baseOID)
	if !ok || strings.Contains(suffix, ".") {
		return 0, false
	}
	v, err := strconv.Atoi(suffix)
	return v, err == nil
}

func pduInt(pdu gosnmp.SnmpPDU) (int, bool) {
	if bi := gosnmp.ToBigInt(pdu.Value); bi != nil && bi.IsInt64() {
		if v := bi.Int64(); v >= math.MinInt32 && v <= math.MaxInt32 {
			return int(v), true
		}
	}
	return 0, false
}

func mapIntLookup(pdu gosnmp.SnmpPDU, names map[int]string) string {
	if v, ok := pduInt(pdu); ok {
		if name, found := names[v]; found {
			return name
		}
		return strconv.Itoa(v)
	}
	return ""
}

func formatSNMPValueString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return strings.TrimSpace(strings.ReplaceAll(string(v), "\x00", ""))
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func formatLLDPID(pdu gosnmp.SnmpPDU) string {
	if b, ok := pdu.Value.([]byte); ok {
		for _, ch := range b {
			if ch < 0x20 || ch > 0x7e {
				return net.HardwareAddr(b).String()
			}
		}
		return strings.TrimSpace(string(b))
	}
	return formatSNMPValueString(pdu)
}
