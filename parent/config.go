package parent

import (
	"errors"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"
)

// Config configures the parent.
type Config struct {
	// InstanceID names this instance ([A-Za-z0-9_-]{1,48}, §11.1).
	InstanceID string
	// QueuePrefix is the deployment prefix plus "vault-control-"
	// (vettid.org: "vettid-org-vault-control-").
	QueuePrefix string
	// DLQARN, if set, receives messages after 3 receives (§11.5).
	DLQARN string

	// ControlListener accepts the enclave's control connection;
	// EgressListener its outbound connections (vsock, or TCP in
	// development).
	ControlListener net.Listener
	EgressListener  net.Listener

	// Allow is the egress allowlist: exact host names, port 443 only.
	Allow []string
	// Resolve, if set, maps an allowed host to the address actually
	// dialed (development and tests only: e.g. "relay.vettid.test" to a
	// local TLS front end). Release enclaves still verify the real name
	// against pinned roots, so this can only misroute.
	Resolve map[string]string

	Objects Objects
	Queues  Queues
	Tables  Tables
	Creds   CredentialSource

	// HealthAddr is the health endpoint's listen address ("" = none).
	HealthAddr string

	// Timing (defaults from §11.1): heartbeat every 20 s (≤ 30 s), lease
	// length 180 s renewed every 60 s.
	Heartbeat   time.Duration
	LeaseLength time.Duration
	LeaseRenew  time.Duration
	// RequestTimeout bounds the enclave's answer to one queue message.
	RequestTimeout time.Duration
	// SweepInterval runs the stale-queue sweeper (0 = default 10 min;
	// negative = never).
	SweepInterval time.Duration

	Logger *slog.Logger
	Now    func() time.Time
}

var (
	instanceIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)
	hostRE       = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// ErrConfig is an invalid configuration.
var ErrConfig = errors.New("parent: invalid configuration")

func (c *Config) defaults() error {
	if !instanceIDRE.MatchString(c.InstanceID) || c.QueuePrefix == "" || len(c.QueuePrefix)+len(c.InstanceID) > 80 {
		return ErrConfig
	}
	if c.ControlListener == nil || c.EgressListener == nil || c.Objects == nil || c.Queues == nil || c.Tables == nil || c.Creds == nil {
		return ErrConfig
	}
	for _, h := range c.Allow {
		if !hostRE.MatchString(h) {
			return ErrConfig
		}
	}
	if c.Heartbeat == 0 {
		c.Heartbeat = 20 * time.Second
	}
	if c.LeaseLength == 0 {
		c.LeaseLength = 180 * time.Second
	}
	if c.LeaseRenew == 0 {
		c.LeaseRenew = 60 * time.Second
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = 100 * time.Second
	}
	if c.SweepInterval == 0 {
		c.SweepInterval = 10 * time.Minute
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return nil
}

// QueueName is this instance's queue name (§11.1).
func (c *Config) QueueName() string { return c.QueuePrefix + c.InstanceID }

// DefaultAllow returns the release allowlist for a region (§12.2).
func DefaultAllow(relayHost, region string) []string {
	return []string{strings.ToLower(relayHost), "kms." + region + ".amazonaws.com", "android.googleapis.com"}
}
