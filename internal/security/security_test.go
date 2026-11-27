package security

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestNormalizePhrase(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		same bool
	}{
		{
			name: "case and punctuation stripped",
			a:    "Correct, Horse-Battery Staple!",
			b:    "correcthorsebatterystaple",
			same: true,
		},
		{
			name: "digits preserved and symbols removed",
			a:    "Alpha-99 / Bravo_01!",
			b:    "alpha99bravo01",
			same: true,
		},
		{
			name: "distinct phrases yield different digests",
			a:    "correct horse battery",
			b:    "correct horse staple",
			same: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ha := NormalizePhrase(tc.a)
			hb := NormalizePhrase(tc.b)
			assert.Len(t, ha, 64)
			assert.Len(t, hb, 64)
			if tc.same {
				assert.Equal(t, ha, hb)
			} else {
				assert.NotEqual(t, ha, hb)
			}
		})
	}
}

func TestVerifyPassphrase(t *testing.T) {
	secret := "correct horse battery staple"
	hash := NormalizePhrase(secret)
	tenWords := "one two three four five six seven eight nine ten"
	elevenWords := "one two three four five six seven eight nine ten eleven"

	tests := []struct {
		name     string
		spoken   string
		expected string
		want     bool
	}{
		{name: "exact match", spoken: secret, expected: hash, want: true},
		{name: "uppercase expected hash", spoken: secret, expected: strings.ToUpper(hash), want: true},
		{name: "punctuation and casing", spoken: "Correct, Horse-Battery Staple!", expected: hash, want: true},
		{name: "wrapper my spoken passphrase is", spoken: "my spoken passphrase is correct horse battery staple", expected: hash, want: true},
		{name: "wrapper the voice code", spoken: "the voice code: correct horse battery staple", expected: hash, want: true},
		{name: "wrapper password is", spoken: "password is correct horse battery staple", expected: hash, want: true},
		{name: "wrapper my secret key", spoken: "my secret key correct horse battery staple", expected: hash, want: true},
		{name: "contiguous span inside noise", spoken: "please unlock right now correct horse battery staple thank you", expected: hash, want: true},
		{name: "10-token span in noise", spoken: "hey assistant " + tenWords + " please", expected: NormalizePhrase(tenWords), want: true},
		{name: "11-token phrase with wrapper", spoken: "hey my voice passcode is " + elevenWords, expected: NormalizePhrase(elevenWords), want: true},
		{name: "contraction whitespace token match", spoken: "don't can't won't", expected: NormalizePhrase("dontcantwont"), want: true},
		{name: "wrong passphrase", spoken: "incorrect horse battery staple", expected: hash, want: false},
		{name: "empty spoken phrase", spoken: "", expected: NormalizePhrase(""), want: false},
		{name: "punctuation only spoken", spoken: "!!! --- ???", expected: NormalizePhrase(""), want: false},
		{name: "short expected hash", spoken: secret, expected: hash[:63], want: false},
		{name: "long expected hash", spoken: secret, expected: hash + "0", want: false},
		{name: "non-hex expected hash", spoken: secret, expected: strings.Repeat("z", 64), want: false},
		{name: "empty expected hash", spoken: secret, expected: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyPassphrase(tc.spoken, tc.expected)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDeadboltDisabled(t *testing.T) {
	d := NewDeadbolt(DeadboltConfig{})
	assert.False(t, d.IsEnabled())
	assert.True(t, d.IsUnlocked())

	unlocked, expiresAt, reason := d.Unlock("anything")
	assert.True(t, unlocked)
	assert.True(t, expiresAt.IsZero())
	assert.Equal(t, "deadbolt disabled", reason)

	status := d.Status()
	assert.False(t, status.Enabled)
	assert.True(t, status.Unlocked)
}

func TestDeadboltTTLSlidingAndExpiry(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))

	defaultDB := NewDeadbolt(DeadboltConfig{PassHash: NormalizePhrase("alpha bravo")})
	assert.Equal(t, int64(1800), defaultDB.Status().TTLSeconds)

	d := NewDeadbolt(DeadboltConfig{
		PassHash: NormalizePhrase("alpha bravo"),
		TTL:      30 * time.Second, // clamped to MinDeadboltTTL (300s)
	})
	d.now = clk.Now

	assert.True(t, d.IsEnabled())
	assert.False(t, d.IsUnlocked())
	assert.Equal(t, int64(300), d.Status().TTLSeconds)

	ok, expiresAt, reason := d.Unlock("my voice passphrase is alpha bravo")
	require.True(t, ok)
	assert.Equal(t, "unlocked", reason)
	assert.Equal(t, clk.Now().Add(300*time.Second), expiresAt)

	clk.Advance(250 * time.Second)
	assert.True(t, d.IsUnlocked()) // slides unlockedAt to +250s

	// Status should not slide TTL.
	clk.Advance(200 * time.Second) // +450s total, +200s since slide
	st := d.Status()
	assert.True(t, st.Unlocked)
	assert.Equal(t, int64(100), st.RemainingSeconds)

	// Advance past remaining 100s without sliding -> expires cleanly.
	clk.Advance(100 * time.Second) // +300s since slide
	assert.False(t, d.IsUnlocked())
	assert.False(t, d.Status().Unlocked)

	// Explicit Lock closes an active unlock immediately.
	ok, _, _ = d.Unlock("alpha bravo")
	require.True(t, ok)
	assert.True(t, d.IsUnlocked())
	d.Lock()
	assert.False(t, d.IsUnlocked())
}

func TestDeadboltBruteForceBackoff(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	d := NewDeadbolt(DeadboltConfig{PassHash: NormalizePhrase("open sesame")})
	d.now = clk.Now

	for i := 1; i <= 4; i++ {
		ok, _, _ := d.Unlock("wrong guess")
		assert.False(t, ok)
		st := d.Status()
		assert.Equal(t, i, st.FailedAttempts)
		assert.False(t, st.LockedOut)
	}

	// 5th bad attempt triggers 30s cooldown lockout.
	ok, _, reason := d.Unlock("wrong guess")
	assert.False(t, ok)
	assert.Contains(t, reason, "30s")
	assert.True(t, d.Status().LockedOut)

	// Even correct passphrase is rejected during cooldown.
	clk.Advance(15 * time.Second)
	ok, _, reason = d.Unlock("open sesame")
	assert.False(t, ok)
	assert.Contains(t, reason, "locked")

	// After 30s passes, 6th bad attempt triggers 60s exponential backoff.
	clk.Advance(16 * time.Second)
	ok, _, reason = d.Unlock("still wrong")
	assert.False(t, ok)
	assert.Contains(t, reason, "1m0s")

	// After 60s passes, valid passphrase unlocks and resets failure count.
	clk.Advance(61 * time.Second)
	ok, _, reason = d.Unlock("open sesame")
	require.True(t, ok)
	assert.Equal(t, "unlocked", reason)
	st := d.Status()
	assert.Equal(t, 0, st.FailedAttempts)
	assert.False(t, st.LockedOut)
}

func TestDeadboltPersistenceAndConcurrency(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "nested", "deadbolt.json")
	clk := newFakeClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	hash := NormalizePhrase("hotel foxtrot")

	d1 := NewDeadbolt(DeadboltConfig{
		PassHash:               hash,
		AllowLockedCronSummary: true,
		StatePath:              statePath,
	})
	d1.now = clk.Now

	ok, _, _ := d1.Unlock("hotel foxtrot")
	require.True(t, ok)

	info, err := os.Stat(statePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	clk.Advance(100 * time.Second)
	require.True(t, d1.IsUnlocked()) // persists slid timestamp

	d2 := NewDeadbolt(DeadboltConfig{PassHash: hash, StatePath: statePath})
	d2.now = clk.Now
	assert.True(t, d2.IsUnlocked())

	// Rotating passphrase invalidates persisted unlock state.
	d3 := NewDeadbolt(DeadboltConfig{PassHash: NormalizePhrase("different phrase"), StatePath: statePath})
	d3.now = clk.Now
	assert.False(t, d3.IsUnlocked())

	// Concurrent stress under -race.
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d1.IsEnabled()
			_ = d1.IsUnlocked()
			_ = d1.Status()
			_, _, _ = d1.Unlock("wrong")
		}()
	}
	wg.Wait()
}

func TestSanitizeTarget(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "valid hostname trimmed", raw: "  example.com \t", want: "example.com"},
		{name: "valid srv underscore", raw: "_dmarc.example.com", want: "_dmarc.example.com"},
		{name: "valid ipv4", raw: "192.168.1.1", want: "192.168.1.1"},
		{name: "valid ipv6 zone", raw: "fe80::1%eth0", want: "fe80::1%eth0"},
		{name: "empty string", raw: "", wantErr: true},
		{name: "whitespace only", raw: "   \n\t ", wantErr: true},
		{name: "leading dash flag injection", raw: "-c", wantErr: true},
		{name: "leading space then dash", raw: "  --help", wantErr: true},
		{name: "internal whitespace", raw: "example.com -p 80", wantErr: true},
		{name: "control character", raw: "example.com\x00", wantErr: true},
		{name: "forward slash", raw: "example.com/path", wantErr: true},
		{name: "backslash", raw: `example.com\path`, wantErr: true},
		{name: "question mark", raw: "example.com?q=1", wantErr: true},
		{name: "hash fragment", raw: "example.com#frag", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SanitizeTarget(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrTargetInvalid)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTargetGuardMetadataAndCIDRPrecedence(t *testing.T) {
	t.Run("invalid cidr rejected", func(t *testing.T) {
		_, err := NewTargetGuard([]string{"not-a-cidr"}, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrTargetInvalid)
	})

	t.Run("metadata always blocked even if allow-cidrs includes it", func(t *testing.T) {
		g, err := NewTargetGuard([]string{"0.0.0.0/0, 169.254.0.0/16", "::/0"}, nil)
		require.NoError(t, err)

		for _, ipStr := range []string{"169.254.169.254", "169.254.0.1", "::ffff:169.254.169.254", "fd00:ec2::254"} {
			err := g.ValidateIP(net.ParseIP(ipStr))
			require.Error(t, err, "expected %s to be denied", ipStr)
			assert.ErrorIs(t, err, ErrTargetDenied)
		}
		require.NoError(t, g.ValidateIP(net.ParseIP("192.168.1.10")))
	})

	t.Run("deny-cidrs override allow-cidrs", func(t *testing.T) {
		g, err := NewTargetGuard([]string{"10.0.0.0/8, 192.168.1.0/24"}, []string{"10.20.0.0/16"})
		require.NoError(t, err)

		require.NoError(t, g.ValidateIP(net.ParseIP("10.30.1.5")))
		require.NoError(t, g.ValidateIP(net.ParseIP("192.168.1.50")))

		err = g.ValidateIP(net.ParseIP("10.20.1.5"))
		require.ErrorIs(t, err, ErrTargetDenied)

		err = g.ValidateIP(net.ParseIP("8.8.8.8"))
		require.ErrorIs(t, err, ErrTargetNotAllowed)
	})

	t.Run("blockPrivate enforces non-routable blocking", func(t *testing.T) {
		g, err := NewTargetGuardWithOptions(nil, nil, true)
		require.NoError(t, err)
		assert.True(t, g.BlockPrivate())

		for _, ipStr := range []string{"0.0.0.0", "0.1.2.3", "10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1"} {
			err := g.ValidateIP(net.ParseIP(ipStr))
			require.ErrorIs(t, err, ErrTargetDenied, "expected %s to be denied", ipStr)
		}
		require.NoError(t, g.ValidateIP(net.ParseIP("93.184.216.34")))
	})
}

func TestTargetGuardHostResolutionAndValidateCIDR(t *testing.T) {
	ctx := context.Background()
	g, err := NewTargetGuard([]string{"93.184.216.0/24, 10.0.0.0/8"}, []string{"10.99.0.0/16"})
	require.NoError(t, err)

	// Inject deterministic resolver for DNS rebinding / multi-IP checks.
	g.lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "ok.example":
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		case "rebind.example":
			return []net.IPAddr{
				{IP: net.ParseIP("93.184.216.34")},
				{IP: net.ParseIP("169.254.169.254")},
			}, nil
		default:
			return nil, errors.New("nxdomain")
		}
	}

	ips, err := g.ValidateHostOrIP(ctx, "ok.example")
	require.NoError(t, err)
	assert.Equal(t, []net.IP{net.ParseIP("93.184.216.34").To4()}, ips)

	_, err = g.ValidateHostOrIP(ctx, "rebind.example")
	require.ErrorIs(t, err, ErrTargetDenied)

	_, err = g.ValidateHostOrIP(ctx, "-o")
	require.ErrorIs(t, err, ErrTargetInvalid)

	_, err = g.ValidateHostOrIP(ctx, "169.254.169.254")
	require.ErrorIs(t, err, ErrTargetDenied)

	// ValidateCIDR checks overlap with 169.254.0.0/16, denyNets, and allowNets containment.
	for _, blocked := range []string{"169.254.0.0/16", "169.254.169.0/24", "169.0.0.0/8", "0.0.0.0/0", "10.0.0.0/8"} {
		_, _, err := g.ValidateCIDR(blocked)
		require.ErrorIs(t, err, ErrTargetDenied, "expected %s to be denied", blocked)
	}

	_, _, err = g.ValidateCIDR("192.168.0.0/16")
	require.ErrorIs(t, err, ErrTargetNotAllowed)

	_, _, err = g.ValidateCIDR("-10.1.0.0/16")
	require.ErrorIs(t, err, ErrTargetInvalid)

	ip, ipNet, err := g.ValidateCIDR("10.1.0.0/16")
	require.NoError(t, err)
	assert.Equal(t, "10.1.0.0", ip.String())
	assert.Equal(t, "10.1.0.0/16", ipNet.String())
}

func TestTargetGuardDialContextPinsValidatedIP(t *testing.T) {
	ctx := context.Background()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)

	var accepted atomic.Int32
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	t.Run("rejects invalid addresses and blocked IPs before dialing", func(t *testing.T) {
		metaGuard, gErr := NewTargetGuard(nil, nil)
		require.NoError(t, gErr)
		privGuard, gErr := NewTargetGuardWithOptions(nil, nil, true)
		require.NoError(t, gErr)
		privGuard.lookupIPAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}

		for _, badAddr := range []string{"127.0.0.1", ":80", "127.0.0.1:", " 127.0.0.1:80", "-evil:80"} {
			_, dErr := metaGuard.DialContext(ctx, "tcp", badAddr)
			require.ErrorIs(t, dErr, ErrTargetInvalid, "addr=%q", badAddr)
		}
		for _, blockedAddr := range []string{"169.254.169.254:80", "[fd00:ec2::254]:80"} {
			_, dErr := metaGuard.DialContext(ctx, "tcp", blockedAddr)
			require.ErrorIs(t, dErr, ErrTargetDenied, "addr=%q", blockedAddr)
		}

		_, dErr := privGuard.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		require.ErrorIs(t, dErr, ErrTargetDenied)
		_, dErr = privGuard.DialContext(ctx, "tcp", net.JoinHostPort("rebind-private.example", port))
		require.ErrorIs(t, dErr, ErrTargetDenied)
		assert.Zero(t, accepted.Load(), "blocked targets must fail before TCP dial")

		var nilGuard *TargetGuard
		_, dErr = nilGuard.DialContext(ctx, "tcp", "169.254.169.254:80")
		require.ErrorIs(t, dErr, ErrTargetDenied)
	})

	t.Run("pins validated IP for hostname with single lookup and fallback", func(t *testing.T) {
		g, gErr := NewTargetGuard(nil, nil)
		require.NoError(t, gErr)

		var lookups atomic.Int32
		g.lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			n := lookups.Add(1)
			if host == "fallback.example" {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.2")}, {IP: net.ParseIP("127.0.0.1")}}, nil
			}
			if n == 1 {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		}

		conn, dErr := g.DialContext(ctx, "tcp", net.JoinHostPort("pinned.example", port))
		require.NoError(t, dErr)
		assert.Equal(t, net.JoinHostPort("127.0.0.1", port), conn.RemoteAddr().String())
		_ = conn.Close()
		assert.Equal(t, int32(1), lookups.Load(), "DialContext must resolve hostname once without second lookup")

		connFB, fbErr := g.DialContext(ctx, "tcp", net.JoinHostPort("fallback.example", port))
		require.NoError(t, fbErr)
		assert.Equal(t, net.JoinHostPort("127.0.0.1", port), connFB.RemoteAddr().String())
		_ = connFB.Close()

		var nilGuard *TargetGuard
		connLit, litErr := nilGuard.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		require.NoError(t, litErr)
		_ = connLit.Close()
	})

	t.Run("dials IPv4 before IPv6 while preserving within-family order", func(t *testing.T) {
		g, gErr := NewTargetGuard(nil, nil)
		require.NoError(t, gErr)

		g.lookupIPAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("2001:db8::1")},
				{IP: net.ParseIP("127.0.0.2")},
				{IP: net.ParseIP("::1")},
				{IP: net.ParseIP("127.0.0.1")},
			}, nil
		}

		var dialed []string
		realDialer := &net.Dialer{}
		g.dialContext = func(dCtx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr == nil && host == "127.0.0.1" {
				return realDialer.DialContext(dCtx, network, addr)
			}
			return nil, os.NewSyscallError("connect", syscall.ECONNREFUSED)
		}

		conn, dErr := g.DialContext(ctx, "tcp", net.JoinHostPort("dualstack.example", port))
		require.NoError(t, dErr)
		assert.Equal(t, net.JoinHostPort("127.0.0.1", port), conn.RemoteAddr().String())
		_ = conn.Close()
		assert.Equal(t, []string{
			net.JoinHostPort("127.0.0.2", port),
			net.JoinHostPort("127.0.0.1", port),
		}, dialed)
	})

	t.Run("preserves IPv4 error over trailing IPv6 EADDRNOTAVAIL", func(t *testing.T) {
		closedLn, listenErr := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, listenErr)
		_, closedPort, splitErr := net.SplitHostPort(closedLn.Addr().String())
		require.NoError(t, splitErr)
		require.NoError(t, closedLn.Close())

		g, gErr := NewTargetGuard(nil, nil)
		require.NoError(t, gErr)

		g.lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host == "v6promote.example" {
				return []net.IPAddr{
					{IP: net.ParseIP("2001:db8::1")},
					{IP: net.ParseIP("2001:db8::2")},
				}, nil
			}
			return []net.IPAddr{
				{IP: net.ParseIP("2001:db8::1")},
				{IP: net.ParseIP("127.0.0.1")},
			}, nil
		}

		var dialed []string
		realDialer := &net.Dialer{}
		g.dialContext = func(dCtx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			host, _, addrErr := net.SplitHostPort(addr)
			if addrErr == nil && host == "127.0.0.1" {
				return realDialer.DialContext(dCtx, network, addr)
			}
			if addrErr == nil && host == "2001:db8::2" {
				return nil, os.NewSyscallError("connect", syscall.ECONNREFUSED)
			}
			return nil, os.NewSyscallError("connect", syscall.EADDRNOTAVAIL)
		}

		_, dErr := g.DialContext(ctx, "tcp", net.JoinHostPort("v4fail.example", closedPort))
		require.Error(t, dErr)
		require.ErrorIs(t, dErr, syscall.ECONNREFUSED)
		assert.False(t, errors.Is(dErr, syscall.EADDRNOTAVAIL))
		assert.Equal(t, []string{
			net.JoinHostPort("127.0.0.1", closedPort),
			net.JoinHostPort("2001:db8::1", closedPort),
		}, dialed)

		_, v6Err := g.DialContext(ctx, "tcp", net.JoinHostPort("v6promote.example", closedPort))
		require.Error(t, v6Err)
		require.ErrorIs(t, v6Err, syscall.ECONNREFUSED)
		assert.False(t, errors.Is(v6Err, syscall.EADDRNOTAVAIL))
	})
}
