package traceroute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FrankXLT/mcp-adv-netutils/internal/probe"
	"github.com/FrankXLT/mcp-adv-netutils/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTracerouteHelperProcess acts as a deterministic mock `traceroute` binary in subprocesses.
func TestTracerouteHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	args := os.Args
	sepIdx := -1
	for i, arg := range args {
		if arg == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx < 0 {
		fmt.Fprintln(os.Stderr, "missing -- separator")
		os.Exit(2)
	}

	cmdArgs := args[sepIdx+1:]
	isICMP := len(cmdArgs) > 0 && cmdArgs[0] == "-I"
	if isICMP {
		cmdArgs = cmdArgs[1:]
	}
	// Expect: -n -q 2 -w <timeout> -m <maxHops> -- <target>
	if len(cmdArgs) != 9 || cmdArgs[0] != "-n" || cmdArgs[1] != "-q" || cmdArgs[2] != "2" || cmdArgs[3] != "-w" || cmdArgs[5] != "-m" || cmdArgs[7] != "--" {
		fmt.Fprintf(os.Stderr, "unexpected args: %v\n", args[sepIdx+1:])
		os.Exit(2)
	}
	target := cmdArgs[8]

	switch os.Getenv("TRACEROUTE_TEST_MODE") {
	case "normal":
		fmt.Printf("traceroute to %s (%s), 20 hops max, 60 byte packets\n", target, target)
		fmt.Println(" 1  192.168.1.1  0.500 ms  1.000 ms  1.500 ms")
		fmt.Println(" 2  * * *")
		fmt.Println(" 3  * 10.0.0.3  2.500 ms  3.500 ms")
		fmt.Println(" 4  10.0.0.4  4.000 ms  10.0.0.5  6.000 ms")
		fmt.Println(" 5  10.0.0.6  5.000 ms")
		fmt.Println("    10.0.0.7  7.000 ms")
		fmt.Println(" 6  127.0.0.1  0.250 ms  0.350 ms")
		os.Exit(0)
	case "icmp_unreached_udp_ok":
		fmt.Printf("traceroute to %s (%s), 20 hops max, 60 byte packets\n", target, target)
		fmt.Println(" 1  192.168.1.1  1.000 ms  1.200 ms")
		fmt.Println(" 2  * * *")
		if isICMP {
			os.Exit(1)
		}
		fmt.Printf(" 3  %s  2.000 ms  3.000 ms\n", target)
		fmt.Println(" 4  * * *")
		os.Exit(0)
	case "many_hops":
		fmt.Printf("traceroute to %s (%s), 20 hops max, 60 byte packets\n", target, target)
		for i := 1; i <= 14; i++ {
			fmt.Printf(" %d  10.0.1.%d  1.000 ms\n", i, i)
		}
		os.Exit(0)
	case "exit1_with_hops":
		fmt.Printf("traceroute to %s (%s), 20 hops max, 60 byte packets\n", target, target)
		fmt.Println(" 1  192.168.1.1  1.000 ms")
		fmt.Println(" 2  * * *")
		os.Exit(1)
	case "exit1_no_hops":
		fmt.Fprintln(os.Stderr, "traceroute: permission denied")
		os.Exit(1)
	case "sleep":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}

func helperCommandContext(mode string) func(ctx context.Context, name string, arg ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, arg ...string) *exec.Cmd {
		cs := append([]string{"-test.run=TestTracerouteHelperProcess", "--"}, arg...)
		cmd := exec.CommandContext(ctx, os.Args[0], cs...)
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			"TRACEROUTE_TEST_MODE="+mode,
		)
		return cmd
	}
}

func TestExecuteTargetValidation(t *testing.T) {
	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)

	tests := []struct {
		name      string
		target    string
		guard     *security.TargetGuard
		targetErr error
	}{
		{name: "empty", target: "", guard: nil, targetErr: security.ErrTargetInvalid},
		{name: "whitespace", target: "   ", guard: nil, targetErr: security.ErrTargetInvalid},
		{name: "leading_dash", target: "-n", guard: nil, targetErr: security.ErrTargetInvalid},
		{name: "leading_dash_padded", target: " --help", guard: guard, targetErr: security.ErrTargetInvalid},
		{name: "url_slash", target: "127.0.0.1/24", guard: guard, targetErr: security.ErrTargetInvalid},
		{name: "metadata_ipv4_blocked", target: "169.254.169.254", guard: guard, targetErr: security.ErrTargetDenied},
		{name: "metadata_ipv6_blocked", target: "fd00:ec2::254", guard: guard, targetErr: security.ErrTargetDenied},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, execErr := Execute(context.Background(), TracerouteParams{Target: tc.target}, tc.guard)
			require.Error(t, execErr)
			assert.True(t, errors.Is(execErr, tc.targetErr), "expected %v, got %v", tc.targetErr, execErr)
		})
	}

	t.Run("nil_context", func(t *testing.T) {
		//nolint:staticcheck // intentionally testing nil context guard
		_, execErr := Execute(nil, TracerouteParams{Target: "127.0.0.1"}, guard)
		require.Error(t, execErr)
	})
}

func TestExecuteParsingAndFlagProtection(t *testing.T) {
	guard, err := security.NewTargetGuard([]string{"127.0.0.0/8"}, nil)
	require.NoError(t, err)

	deps := execDeps{
		lookPath:       func(string) (string, error) { return "/usr/bin/traceroute", nil },
		commandContext: helperCommandContext("normal"),
		lookupIPAddr:   func(context.Context, string) ([]net.IPAddr, error) { return nil, errors.New("unused") },
		lookupAddr: func(ctx context.Context, addr string) ([]string, error) {
			_, ok := ctx.Deadline()
			assert.True(t, ok, "PTR lookup context must carry a timeout")
			if addr == "192.168.1.1" {
				return []string{"gw.home.arpa."}, nil
			}
			return nil, errors.New("no PTR")
		},
	}

	maxHops := 10
	timeout := 1
	res, err := executeWithDeps(context.Background(), TracerouteParams{
		Target:  "127.0.0.1",
		MaxHops: &maxHops,
		Timeout: &timeout,
	}, guard, deps)
	require.NoError(t, err)

	assert.Equal(t, "127.0.0.1", res.Target)
	assert.Equal(t, "127.0.0.1", res.ResolvedIP)
	assert.Equal(t, 10, res.MaxHops)
	assert.True(t, res.ReachedDestination)
	require.Len(t, res.Hops, 6)

	// Hop 1: normal with PTR hostname trimmed of trailing dot
	assert.Equal(t, 1, res.Hops[0].Hop)
	assert.Equal(t, "192.168.1.1", res.Hops[0].IP)
	assert.Equal(t, "gw.home.arpa", res.Hops[0].Hostname)
	assert.False(t, res.Hops[0].TimedOut)
	assert.InDelta(t, 1.0, res.Hops[0].AvgRTTMs, 0.001)

	// Hop 2: * * *
	assert.Equal(t, 2, res.Hops[1].Hop)
	assert.Equal(t, "*", res.Hops[1].IP)
	assert.True(t, res.Hops[1].TimedOut)

	// Hop 3: partial timeout (* 10.0.0.3 2.500 ms 3.500 ms)
	assert.Equal(t, 3, res.Hops[2].Hop)
	assert.Equal(t, "10.0.0.3", res.Hops[2].IP)
	assert.False(t, res.Hops[2].TimedOut)
	assert.Equal(t, []float64{2.5, 3.5}, res.Hops[2].RTTMs)
	assert.InDelta(t, 3.0, res.Hops[2].AvgRTTMs, 0.001)

	// Hop 4: multi-IP line (10.0.0.4 + 10.0.0.5)
	assert.Equal(t, 4, res.Hops[3].Hop)
	assert.Equal(t, "10.0.0.4", res.Hops[3].IP)
	assert.Equal(t, []float64{4.0, 6.0}, res.Hops[3].RTTMs)
	assert.InDelta(t, 5.0, res.Hops[3].AvgRTTMs, 0.001)

	// Hop 5: continuation line merged
	assert.Equal(t, 5, res.Hops[4].Hop)
	assert.Equal(t, "10.0.0.6", res.Hops[4].IP)
	assert.Equal(t, []float64{5.0, 7.0}, res.Hops[4].RTTMs)
	assert.InDelta(t, 6.0, res.Hops[4].AvgRTTMs, 0.001)

	// Hop 6: destination reached
	assert.Equal(t, 6, res.Hops[5].Hop)
	assert.Equal(t, "127.0.0.1", res.Hops[5].IP)
}

func TestExecuteBoundedConcurrentPTRLookups(t *testing.T) {
	var current atomic.Int32
	var maxSeen atomic.Int32

	deps := execDeps{
		lookPath:       func(string) (string, error) { return "/usr/bin/traceroute", nil },
		commandContext: helperCommandContext("many_hops"),
		lookupIPAddr:   func(context.Context, string) ([]net.IPAddr, error) { return nil, nil },
		lookupAddr: func(ctx context.Context, addr string) ([]string, error) {
			n := current.Add(1)
			for {
				prev := maxSeen.Load()
				if n <= prev || maxSeen.CompareAndSwap(prev, n) {
					break
				}
			}
			deadline, ok := ctx.Deadline()
			assert.True(t, ok)
			assert.LessOrEqual(t, time.Until(deadline), 1100*time.Millisecond)

			time.Sleep(20 * time.Millisecond)
			current.Add(-1)
			return []string{"hop-" + strings.ReplaceAll(addr, ".", "-") + ".local."}, nil
		},
	}

	res, err := executeWithDeps(context.Background(), TracerouteParams{Target: "127.0.0.1"}, nil, deps)
	require.NoError(t, err)
	require.Len(t, res.Hops, 14)

	assert.LessOrEqual(t, maxSeen.Load(), int32(ptrConcurrencyLimit))
	assert.GreaterOrEqual(t, maxSeen.Load(), int32(2))
	for i, hop := range res.Hops {
		assert.Equal(t, "hop-10-0-1-"+strconv.Itoa(i+1)+".local", hop.Hostname)
	}
}

func TestExecuteWaitErrorHandling(t *testing.T) {
	baseDeps := execDeps{
		lookPath:     func(string) (string, error) { return "/usr/bin/traceroute", nil },
		lookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) { return nil, nil },
		lookupAddr:   func(context.Context, string) ([]string, error) { return nil, errors.New("none") },
	}
	t.Run("exit1_with_parsed_hops_succeeds", func(t *testing.T) {
		deps := baseDeps
		deps.commandContext = helperCommandContext("exit1_with_hops")
		res, err := executeWithDeps(context.Background(), TracerouteParams{Target: "127.0.0.1"}, nil, deps)
		require.NoError(t, err)
		require.Len(t, res.Hops, 2)
		assert.False(t, res.ReachedDestination)
	})
	t.Run("exit1_with_no_hops_fails", func(t *testing.T) {
		deps := baseDeps
		deps.commandContext = helperCommandContext("exit1_no_hops")
		_, err := executeWithDeps(context.Background(), TracerouteParams{Target: "127.0.0.1"}, nil, deps)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "traceroute failed")
	})
	t.Run("canceled_context_fails", func(t *testing.T) {
		deps := baseDeps
		deps.commandContext = helperCommandContext("sleep")
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		_, err := executeWithDeps(ctx, TracerouteParams{Target: "127.0.0.1"}, nil, deps)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "traceroute canceled")
	})
}

func TestHandleTracerouteRejectsInvalidTarget(t *testing.T) {
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "traceroute", Arguments: map[string]any{"target": "-h"}}}
	_, err := HandleTraceroute(context.Background(), req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, security.ErrTargetInvalid))
}

func TestTracerouteResponseJSONSchema(t *testing.T) {
	res := TracerouteResponse{
		Target: "127.0.0.1", ResolvedIP: "127.0.0.1", MaxHops: 15,
		Hops:      []HopResult{{Hop: 1, IP: "127.0.0.1", RTTMs: []float64{0.5}, AvgRTTMs: 0.5}},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(res)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"target":"127.0.0.1"`)
}

func TestExecutePinsResolvedIPToCommand(t *testing.T) {
	t.Run("passes resolved IP to traceroute binary instead of hostname", func(t *testing.T) {
		var capturedTargetArg string
		baseCmd := helperCommandContext("normal")
		deps := execDeps{
			lookPath: func(string) (string, error) { return "/usr/bin/traceroute", nil },
			commandContext: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
				if len(arg) > 0 {
					capturedTargetArg = arg[len(arg)-1]
				}
				return baseCmd(ctx, name, arg...)
			},
			lookupIPAddr: func(_ context.Context, host string) ([]net.IPAddr, error) {
				assert.Equal(t, "pinned.example", host)
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			},
			lookupAddr: func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") },
		}

		res, err := executeWithDeps(context.Background(), TracerouteParams{Target: "pinned.example"}, nil, deps)
		require.NoError(t, err)
		assert.Equal(t, "127.0.0.1", capturedTargetArg)
		assert.Equal(t, "pinned.example", res.Target)
		assert.Equal(t, "127.0.0.1", res.ResolvedIP)
		assert.True(t, res.ReachedDestination)
	})

	t.Run("blocks hostname resolving to metadata IP before spawning command", func(t *testing.T) {
		var cmdCalled bool
		deps := execDeps{
			lookPath: func(string) (string, error) { return "/usr/bin/traceroute", nil },
			commandContext: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
				cmdCalled = true
				return helperCommandContext("normal")(ctx, name, arg...)
			},
			lookupIPAddr: func(_ context.Context, _ string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
			},
			lookupAddr: func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") },
		}

		_, err := executeWithDeps(context.Background(), TracerouteParams{Target: "rebind.example"}, nil, deps)
		require.Error(t, err)
		assert.ErrorIs(t, err, security.ErrTargetDenied)
		assert.False(t, cmdCalled)
	})

	for _, tc := range []struct {
		name    string
		ips     []net.IPAddr
		wantIP  string
		wantErr error
	}{
		{
			name:   "prefers IPv4 over IPv6 when dual-stack lookup returns IPv6 first",
			ips:    []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("198.51.100.1")}},
			wantIP: "198.51.100.1",
		},
		{
			name:    "blocks mixed valid IPv6 and metadata IPv4 before spawning command",
			ips:     []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("169.254.169.254")}},
			wantErr: security.ErrTargetDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var capturedArg string
			var cmdCalled bool
			deps := execDeps{
				lookPath: func(string) (string, error) { return "/usr/bin/traceroute", nil },
				commandContext: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
					cmdCalled = true
					if len(arg) > 0 {
						capturedArg = arg[len(arg)-1]
					}
					return helperCommandContext("normal")(ctx, name, arg...)
				},
				lookupIPAddr: func(context.Context, string) ([]net.IPAddr, error) { return tc.ips, nil },
				lookupAddr:   func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") },
			}
			res, err := executeWithDeps(context.Background(), TracerouteParams{Target: "dualstack.example"}, nil, deps)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				assert.False(t, cmdCalled)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantIP, capturedArg)
			assert.Equal(t, tc.wantIP, res.ResolvedIP)
		})
	}
}

func TestValidateAndResolveTargetNilGuardFailClosed(t *testing.T) {
	errLookup := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("nxdomain")
	}
	emptyLookup := func(context.Context, string) ([]net.IPAddr, error) {
		return nil, nil
	}

	rejectedTargets := []string{
		"0177.0.0.1",
		"0251.0376.0251.0376",
		"0x7f000001",
		"0xa9.0xfe.0xa9.0xfe",
		"2130706433",
		"2852039166",
		"127.1",
		"169.254.43518",
		"169.254.169.254.",
		"[169.254.169.254]",
		"[::1]",
		"169.254.169.254:80",
		"::ffff:0251.0376.0251.0376",
		"foo..bar",
	}

	for _, target := range rejectedTargets {
		for _, tc := range []struct {
			name   string
			lookup func(context.Context, string) ([]net.IPAddr, error)
		}{
			{name: "lookup_error", lookup: errLookup},
			{name: "lookup_empty", lookup: emptyLookup},
		} {
			t.Run(target+"/"+tc.name, func(t *testing.T) {
				var cmdCalled bool
				deps := execDeps{
					lookPath: func(string) (string, error) { return "/usr/bin/traceroute", nil },
					commandContext: func(ctx context.Context, name string, arg ...string) *exec.Cmd {
						cmdCalled = true
						return helperCommandContext("normal")(ctx, name, arg...)
					},
					lookupIPAddr: tc.lookup,
					lookupAddr:   func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") },
				}

				_, err := executeWithDeps(context.Background(), TracerouteParams{Target: target}, nil, deps)
				require.Error(t, err)
				assert.ErrorIs(t, err, security.ErrTargetInvalid)
				assert.False(t, cmdCalled)
			})
		}
	}

	validHostnames := []string{
		"mock.example",
		"123.example.com",
		"0x1.example.com",
		"localhost",
	}
	for _, host := range validHostnames {
		t.Run("valid_hostname_fallback/"+host, func(t *testing.T) {
			deps := execDeps{
				lookPath:       func(string) (string, error) { return "/usr/bin/traceroute", nil },
				commandContext: helperCommandContext("normal"),
				lookupIPAddr:   emptyLookup,
				lookupAddr:     func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") },
			}

			res, err := executeWithDeps(context.Background(), TracerouteParams{Target: host}, nil, deps)
			require.NoError(t, err)
			assert.Equal(t, host, res.Target)
			assert.Empty(t, res.ResolvedIP)
		})
	}
}

func TestValidateAndResolveTargetGuardPrefersIPv4(t *testing.T) {
	assert.Equal(t, "127.0.0.1", selectPreferredIP([]net.IP{net.ParseIP("::1"), net.ParseIP("127.0.0.1")}).String())
	assert.Equal(t, "2001:db8::1", selectPreferredIP([]net.IP{net.ParseIP("2001:db8::1")}).String())

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for buf := make([]byte, 512); ; {
			n, addr, readErr := pc.ReadFrom(buf)
			if readErr != nil {
				return
			}
			var req dns.Msg
			if req.Unpack(buf[:n]) != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(&req)
			for _, q := range req.Question {
				hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 60}
				if q.Qtype == dns.TypeAAAA {
					resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8::1")})
				} else if q.Qtype == dns.TypeA {
					resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: net.ParseIP("198.51.100.1")})
				}
			}
			if wire, packErr := resp.Pack(); packErr == nil {
				_, _ = pc.WriteTo(wire, addr)
			}
		}
	}()

	origPreferGo, origDial := net.DefaultResolver.PreferGo, net.DefaultResolver.Dial
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, pc.LocalAddr().String())
	}
	t.Cleanup(func() {
		_ = pc.Close()
		<-done
		net.DefaultResolver.PreferGo, net.DefaultResolver.Dial = origPreferGo, origDial
	})

	guard, err := security.NewTargetGuard(nil, nil)
	require.NoError(t, err)
	target, resolvedIP, err := validateAndResolveTarget(context.Background(), "dualstack.example", guard, nil)
	require.NoError(t, err)
	assert.Equal(t, "dualstack.example", target)
	assert.Equal(t, "198.51.100.1", resolvedIP)
}

func TestExecuteFallbackCascade(t *testing.T) {
	noPTR := func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") }
	tests := []struct {
		name, cmdMode, wantMode    string
		tcpRes                     func(net.IP) *probe.MTRResult
		wantCLI, wantTCP, wantHops int
	}{
		{"fast_icmp_hit", "normal", "icmp", func(net.IP) *probe.MTRResult { return nil }, 1, 0, 6},
		{"icmp_to_tcp_trim", "exit1_no_hops", "tcp_443", func(ip net.IP) *probe.MTRResult {
			return &probe.MTRResult{ProbeMode: "tcp_443", Reached: true, Hops: []probe.MTRHop{
				{Hop: 1, IP: "192.168.1.1", Sent: 2, Received: 2, AvgMs: 1.5}, {Hop: 2, IP: "*", Sent: 2},
				{Hop: 3, IP: ip.String(), Sent: 2, Received: 2, AvgMs: 4}, {Hop: 4, IP: "*", Sent: 2},
			}}
		}, 1, 1, 3},
		{"tcp_to_udp", "icmp_unreached_udp_ok", "udp", func(net.IP) *probe.MTRResult {
			return &probe.MTRResult{ProbeMode: "tcp_443", Hops: []probe.MTRHop{{Hop: 1, IP: "192.168.1.1", Sent: 2, Received: 1, AvgMs: 1}}}
		}, 2, 1, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cliCalls, tcpCalls int
			baseCmd := helperCommandContext(tc.cmdMode)
			deps := execDeps{
				lookPath:       func(string) (string, error) { return "/usr/bin/traceroute", nil },
				commandContext: func(ctx context.Context, n string, a ...string) *exec.Cmd { cliCalls++; return baseCmd(ctx, n, a...) },
				lookupAddr:     noPTR,
				tcpFallbackFunc: func(_ context.Context, ip net.IP, _ int, _ time.Duration) *probe.MTRResult {
					tcpCalls++
					return tc.tcpRes(ip)
				},
			}
			res, err := executeWithDeps(context.Background(), TracerouteParams{Target: "127.0.0.1"}, nil, deps)
			require.NoError(t, err)
			assert.Equal(t, []int{tc.wantCLI, tc.wantTCP, tc.wantHops}, []int{cliCalls, tcpCalls, len(res.Hops)})
			assert.Equal(t, tc.wantMode, res.ProbeMode)
			assert.True(t, res.ReachedDestination && res.Hops[1].Silent)
			assert.Equal(t, "Gateway", res.Hops[0].Segment)
			assert.Equal(t, "Destination", res.Hops[tc.wantHops-1].Segment)
			assert.Equal(t, 1, res.SilentTransitHops)
			assert.Equal(t, 0.0, res.DestLossPct)
		})
	}
}

func TestFinalizeTracerouteResultCoPPAndTailFailures(t *testing.T) {
	unreached := &TracerouteResponse{
		Target: "198.51.100.1", ResolvedIP: "198.51.100.1", ReachedDestination: false,
		Hops: []HopResult{
			{Hop: 1, IP: "192.168.1.1", RTTMs: []float64{1, 1.2}}, {Hop: 2, IP: "*", TimedOut: true},
			{Hop: 3, IP: "203.0.113.1", RTTMs: []float64{4, 5}}, {Hop: 4, IP: "*", TimedOut: true},
		},
	}
	finalizeTracerouteResult(unreached, net.ParseIP("198.51.100.1"))
	require.Len(t, unreached.Hops, 4)
	assert.True(t, unreached.Hops[1].Silent)
	assert.False(t, unreached.Hops[3].Silent)
	assert.Equal(t, 1, unreached.SilentTransitHops)
	assert.Equal(t, 100.0, unreached.DestLossPct)
}

type delayedCancelCtx struct {
	context.Context
	cancelOn int32
	calls    atomic.Int32
}

func (c *delayedCancelCtx) Done() <-chan struct{} { return nil }
func (c *delayedCancelCtx) Err() error {
	if c.calls.Add(1) >= c.cancelOn {
		return context.Canceled
	}
	return nil
}

func TestExecuteCancelAfterCLIExitAndDestLossEdges(t *testing.T) {
	noPTR := func(context.Context, string) ([]string, error) { return nil, errors.New("no PTR") }
	for _, tc := range []struct {
		name, mode string
		cancelOn   int32
	}{
		{"icmp_cancel_after_clean_exit", "normal", 2},
		{"udp_cancel_after_clean_exit", "icmp_unreached_udp_ok", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := execDeps{
				lookPath:       func(string) (string, error) { return "/usr/bin/traceroute", nil },
				commandContext: helperCommandContext(tc.mode),
				lookupAddr:     noPTR,
			}
			ctx := &delayedCancelCtx{Context: context.Background(), cancelOn: tc.cancelOn}
			res, err := executeWithDeps(ctx, TracerouteParams{Target: "127.0.0.1"}, nil, deps)
			require.ErrorIs(t, err, context.Canceled)
			assert.Nil(t, res)
		})
	}

	assert.Equal(t, 100.0, computeDestLossPct([]HopResult{{RTTMs: []float64{1, 2}}}, false))
	assert.Equal(t, 0.0, computeDestLossPct(nil, true))
	assert.Equal(t, 100.0, computeDestLossPct([]HopResult{{IP: "*"}}, true))
	assert.Equal(t, 50.0, computeDestLossPct([]HopResult{{RTTMs: []float64{1.5}}}, true))
	assert.Equal(t, 0.0, computeDestLossPct([]HopResult{{RTTMs: []float64{1.0, 2.0}}}, true))
	assert.Equal(t, 0.0, computeDestLossPct([]HopResult{{RTTMs: []float64{1.0, 2.0, 3.0}}}, true))
}
