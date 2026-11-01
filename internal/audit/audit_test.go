package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJournal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	j, e := Open(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Open(p); e == nil {
		t.Fatal("multiple writers accepted")
	}
	event := Event{Decision: "call-intent", Nonce: "once", Expires: time.Now().Add(time.Minute).Unix()}
	if e = j.Consume(event); e != nil {
		t.Fatal(e)
	}
	if e = j.Consume(event); e != ErrReplay {
		t.Fatal("replay accepted", e)
	}
	head, n := j.Head()
	if n != 1 {
		t.Fatal(n)
	}
	j.Close()
	j, e = Open(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Consume(event); e != ErrReplay {
		t.Fatal("replay accepted after restart", e)
	}
	j.Close()
	b, _ := os.ReadFile(p)
	if _, _, e = Verify(bytes.NewReader(b), head, nil); e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string][]byte{"edited": bytes.Replace(b, []byte("call-intent"), []byte("call-allow!"), 1), "truncated": b[:len(b)-1], "deleted": {}, "duplicate": append(append([]byte{}, b...), b...)} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := Verify(bytes.NewReader(data), head, nil); e == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
}
func TestConcurrentConsume(t *testing.T) {
	j, e := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 30; i++ {
		wg.Go(func() {
			e := j.Consume(Event{Decision: "call-intent", Nonce: "same", Expires: time.Now().Add(time.Minute).Unix()})
			if e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("nonce must be consumed exactly once", success)
	}
}
func TestUnavailable(t *testing.T) {
	j, e := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	j.Close()
	if j.Healthy() {
		t.Fatal("closed journal healthy")
	}
	if e = j.Append(Event{Decision: "test"}); e == nil {
		t.Fatal("accepted write to closed journal")
	}
}
func TestUnsafeFiles(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	os.WriteFile(target, []byte{}, 0644)
	if _, e := Open(target); e == nil {
		t.Fatal("accepted public journal")
	}
	link := filepath.Join(d, "link")
	os.Symlink(target, link)
	if _, e := Open(link); e == nil {
		t.Fatal("accepted symlink")
	}
	if _, _, e := Verify(strings.NewReader(strings.Repeat("x", 40000)), "", nil); e == nil {
		t.Fatal("accepted oversized record")
	}
}
