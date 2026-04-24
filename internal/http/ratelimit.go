package http

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	now         func() time.Time
	ipBuckets   map[string]*bucket
	userBuckets map[string]*bucket
}

type bucket struct {
	count     int
	resetTime time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return newRateLimiter(limit, window, time.Now)
}

func newRateLimiter(limit int, window time.Duration, now func() time.Time) *RateLimiter {
	if limit <= 0 {
		limit = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{
		limit:       limit,
		window:      window,
		now:         now,
		ipBuckets:   make(map[string]*bucket),
		userBuckets: make(map[string]*bucket),
	}
}

func (l *RateLimiter) Allow(ip, username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	ipAllowed := l.allow(l.ipBuckets, ip, now)
	userAllowed := l.allow(l.userBuckets, username, now)
	return ipAllowed && userAllowed
}

func (l *RateLimiter) allow(buckets map[string]*bucket, key string, now time.Time) bool {
	if key == "" {
		key = "-"
	}
	b, ok := buckets[key]
	if !ok || !now.Before(b.resetTime) {
		buckets[key] = &bucket{count: 1, resetTime: now.Add(l.window)}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}
