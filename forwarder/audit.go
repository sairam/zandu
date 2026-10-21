package forwarder

import (
	"sync"
	"time"
)

// AuditEntry records one request handled by the proxy.
type AuditEntry struct {
	Time       time.Time `json:"time"`
	Client     string    `json:"client,omitempty"`
	Upstream   string    `json:"upstream,omitempty"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	RemoteIP   string    `json:"remote_ip"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason"`
	Status     int       `json:"status"`
	DurationMS int64     `json:"duration_ms"`
}

// AuditLog keeps the most recent entries in memory.
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	next    int
	full    bool
}

// NewAuditLog returns a log that retains up to size entries.
func NewAuditLog(size int) *AuditLog {
	if size < 1 {
		size = 1
	}
	return &AuditLog{entries: make([]AuditEntry, size)}
}

// Add records an entry, evicting the oldest when full.
func (a *AuditLog) Add(e AuditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries[a.next] = e
	a.next = (a.next + 1) % len(a.entries)
	if a.next == 0 {
		a.full = true
	}
}

// Recent returns up to limit entries, newest first.
func (a *AuditLog) Recent(limit int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.next
	if a.full {
		n = len(a.entries)
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]AuditEntry, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (a.next - 1 - i + len(a.entries)) % len(a.entries)
		out = append(out, a.entries[idx])
	}
	return out
}
