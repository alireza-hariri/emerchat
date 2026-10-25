package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newUser(name string) NewUser {
	return NewUser{Username: name, DisplayName: name, AuthHash: []byte("h"), AuthSalt: []byte("s"),
		KDFSalt: "k", PublicKey: "p-" + name, WrappedPrivateKey: "w", WrapIV: "i"}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	for i := 0; i < 2; i++ {
		s, err := Open(path)
		if err != nil {
			t.Fatalf("open #%d: %v", i, err)
		}
		s.Close()
	}
}

func TestSecretIsStable(t *testing.T) {
	s := openTest(t)
	a, _ := s.Secret(context.Background())
	b, _ := s.Secret(context.Background())
	if len(a) != 32 || string(a) != string(b) {
		t.Fatal("secret changed between calls")
	}
}

func TestInviteRedeemedOnlyOnceUnderConcurrency(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.CreateInvite(ctx, "code", 0, false, 1e15, 1); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Register(ctx, "code", newUser(string(rune('a'+i))+"user"), 2)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	ok := 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrNotFound):
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d registrations succeeded, want 1", ok)
	}
}

func TestExpiredInviteRejected(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	s.CreateInvite(ctx, "old", 0, false, 100, 1)
	if _, err := s.Register(ctx, "old", newUser("bob"), 200); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestSearchEscapesWildcards(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	for _, n := range []string{"alice", "a_b"} {
		code := "c-" + n
		s.CreateInvite(ctx, code, 0, false, 1e15, 1)
		if _, err := s.Register(ctx, code, newUser(n), 2); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := s.SearchUsers(ctx, "a_", 10)
	if len(got) != 1 || got[0].Username != "a_b" {
		t.Fatalf("search a_ = %+v", got)
	}
}
