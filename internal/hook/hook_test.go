package hook

import (
	"log/slog"
	"testing"
)

func TestListAddRemove(t *testing.T) {
	var h List[func() int]
	if h.Get() != nil {
		t.Fatal("empty list is not nil")
	}
	r1 := h.Add(func() int { return 1 })
	r2 := h.Add(func() int { return 2 })
	if n := len(h.Get()); n != 2 {
		t.Fatalf("len = %d, want 2", n)
	}
	r1()
	r1()
	if got := h.Get(); len(got) != 1 || got[0].Fn() != 2 {
		t.Fatalf("after removing the first hook, got %d hooks", len(got))
	}
	r2()
	if h.Get() != nil {
		t.Fatal("list is not nil after removing every hook")
	}
}

func TestRunStopsAtDropAndRecoversPanics(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	var calls int
	var h List[func(*int) Verdict]
	h.Add(func(*int) Verdict { calls++; panic("broken") })
	h.Add(func(*int) Verdict { calls++; return Drop })
	h.Add(func(*int) Verdict { calls++; return Allow })
	var e int
	if v := Run(log, &e, h.Get()); v != Drop {
		t.Fatalf("Run = %v, want Drop", v)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (panic treated as Allow, stop at Drop)", calls)
	}
}
