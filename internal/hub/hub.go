// Package hub wakes long-polling requests when a user has new updates.
package hub

import "sync"

// Hub keeps one channel per waiting user. Notify closes it, waking every
// request (tab) that holds it, and the next Wait hands out a fresh one.
//
// To avoid lost wakeups a poller must call Wait *before* checking the
// database for updates, and writers must call Notify *after* committing.
type Hub struct {
	mu      sync.Mutex
	waiters map[int64]chan struct{}
}

func New() *Hub {
	return &Hub{waiters: map[int64]chan struct{}{}}
}

func (h *Hub) Wait(uid int64) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.waiters[uid]
	if !ok {
		ch = make(chan struct{})
		h.waiters[uid] = ch
	}
	return ch
}

func (h *Hub) Notify(uids ...int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, uid := range uids {
		if ch, ok := h.waiters[uid]; ok {
			close(ch)
			delete(h.waiters, uid)
		}
	}
}
