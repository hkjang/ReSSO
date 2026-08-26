package password

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	hash, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("correct password rejected: ok=%v err=%v", ok, err)
	}
	ok, err = Verify("incorrect", hash)
	if err != nil || ok {
		t.Fatalf("incorrect password accepted: ok=%v err=%v", ok, err)
	}
}

// The gate exists so that a burst of sign-ins cannot multiply Argon2's memory
// by the request rate. A hash that cannot be read is never going to reach the
// comparison, so taking a slot to find that out spends one on nothing while a
// real sign-in waits for it.
func TestAMalformedHashDoesNotTakeAHashingSlot(t *testing.T) {
	for i := 0; i < cap(hashGate); i++ {
		hashGate <- struct{}{}
	}
	t.Cleanup(func() {
		for i := 0; i < cap(hashGate); i++ {
			<-hashGate
		}
	})
	// Every slot is taken, so anything that waits for one cannot finish before
	// this deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := VerifyContext(ctx, "irrelevant", "not-a-hash")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a malformed hash was accepted")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("a malformed hash waited for a hashing slot instead of being refused for what it is")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a malformed hash never came back")
	}
}
