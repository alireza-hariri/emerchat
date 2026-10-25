package server

import (
	"sync"
	"time"
)

// limiter is a fixed-window counter keyed by IP or username.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*window
}

type window struct {
	count int
	reset time.Time
}

func newLimiter(max int, w time.Duration) *limiter {
	return &limiter{max: max, window: w, hits: map[string]*window{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.hits[key]
	if !ok || now.After(w.reset) {
		w = &window{reset: now.Add(l.window)}
		l.hits[key] = w
	}
	w.count++
	return w.count <= l.max
}

func (l *limiter) cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.hits {
		if now.After(w.reset) {
			delete(l.hits, k)
		}
	}
}
