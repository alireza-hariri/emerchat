package hub

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNotifyWakesAllWaitersOfUser(t *testing.T) {
	h := New()
	a1, a2, b := h.Wait(1), h.Wait(1), h.Wait(2)
	h.Notify(1)
	for _, ch := range []<-chan struct{}{a1, a2} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("waiter for user 1 not woken")
		}
	}
	select {
	case <-b:
		t.Fatal("user 2 woken by notification for user 1")
	default:
	}
}

func TestWaitAfterNotifyGetsFreshChannel(t *testing.T) {
	h := New()
	old := h.Wait(1)
	h.Notify(1)
	fresh := h.Wait(1)
	<-old
	select {
	case <-fresh:
		t.Fatal("fresh channel already closed")
	default:
	}
}

func TestNotifyWithoutWaitersIsNoop(t *testing.T) {
	h := New()
	h.Notify(1, 2, 3)
	if len(h.waiters) != 0 {
		t.Fatal("notify created waiters")
	}
}

// Simulates the poll protocol (Wait, check, block) racing a writer
// (write, Notify) and checks no update is ever missed.
func TestNoLostWakeups(t *testing.T) {
	h := New()
	var version atomic.Int64
	const rounds = 2000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var seen int64
		for seen < rounds {
			ch := h.Wait(1)
			if v := version.Load(); v > seen {
				seen = v
				continue
			}
			select {
			case <-ch:
			case <-time.After(2 * time.Second):
				t.Errorf("lost wakeup at version %d", seen)
				return
			}
		}
	}()
	for i := 0; i < rounds; i++ {
		version.Add(1)
		h.Notify(1)
	}
	wg.Wait()
}
