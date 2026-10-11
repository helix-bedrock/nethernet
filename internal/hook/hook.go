// Package hook implements hook lists that can be changed at any time and cost
// nothing to check when empty. It is shared by the nethernet packages.
package hook

import (
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
)

// Verdict is returned by hooks that may stop what they observe. The public
// packages re-export it.
type Verdict uint8

const (
	// Allow lets the data or action continue. It is the zero value.
	Allow Verdict = iota
	// Drop stops the data or action. Later hooks are not called.
	Drop
)

// List is a list of hooks that can be added to and removed from at any time.
// Reads are a single atomic load and cost nothing when the list is empty, so
// unused hooks add no overhead to the paths that check them.
type List[F any] struct {
	mu   sync.Mutex
	next uint64
	fns  atomic.Pointer[[]Entry[F]]
}

// Entry is one registered hook.
type Entry[F any] struct {
	id uint64
	// Fn is the hook function.
	Fn F
}

// Add registers fn and returns a function that removes it. The returned
// function is safe to call more than once and from any goroutine.
func (h *List[F]) Add(fn F) (remove func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	id := h.next
	var cur []Entry[F]
	if p := h.fns.Load(); p != nil {
		cur = *p
	}
	updated := make([]Entry[F], len(cur), len(cur)+1)
	copy(updated, cur)
	updated = append(updated, Entry[F]{id: id, Fn: fn})
	h.fns.Store(&updated)
	return sync.OnceFunc(func() { h.remove(id) })
}

func (h *List[F]) remove(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.fns.Load()
	if p == nil {
		return
	}
	updated := make([]Entry[F], 0, len(*p))
	for _, e := range *p {
		if e.id != id {
			updated = append(updated, e)
		}
	}
	if len(updated) == 0 {
		h.fns.Store(nil)
		return
	}
	h.fns.Store(&updated)
}

// Get returns the current hooks, or nil if there are none.
func (h *List[F]) Get() []Entry[F] {
	if h == nil {
		return nil
	}
	if p := h.fns.Load(); p != nil {
		return *p
	}
	return nil
}

// Run calls each hook in each list in order until one returns Drop, and
// returns the result. A hook that panics is logged and treated as Allow, so a
// broken hook can never crash the server.
func Run[E any](log *slog.Logger, e *E, lists ...[]Entry[func(*E) Verdict]) Verdict {
	for _, list := range lists {
		for _, h := range list {
			if call(log, h.Fn, e) == Drop {
				return Drop
			}
		}
	}
	return Allow
}

func call[E any](log *slog.Logger, fn func(*E) Verdict, e *E) (v Verdict) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("nethernet: hook panicked", "panic", r, "stack", string(debug.Stack()))
			v = Allow
		}
	}()
	return fn(e)
}

// Observe calls hooks that only observe. Panics are logged.
func Observe[E any](log *slog.Logger, e E, lists ...[]Entry[func(E)]) {
	for _, list := range lists {
		for _, h := range list {
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Error("nethernet: hook panicked", "panic", r, "stack", string(debug.Stack()))
					}
				}()
				h.Fn(e)
			}()
		}
	}
}
