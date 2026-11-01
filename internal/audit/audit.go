// Package audit implements a single-writer, fsync-before-action evidence journal.
// Hash chains require an independently retained head to detect complete rewriting.
package audit

import (
	"bufio"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/manasa1508/tool-gateway/internal/wire"
)

type Event struct {
	Time      string   `json:"time"`
	Principal string   `json:"principal,omitempty"`
	Task      string   `json:"task,omitempty"`
	Server    string   `json:"server,omitempty"`
	Tool      string   `json:"tool,omitempty"`
	Decision  string   `json:"decision"`
	Policy    string   `json:"policy,omitempty"`
	ArgsHash  string   `json:"args_hash,omitempty"`
	Findings  []string `json:"findings,omitempty"`
	Score     int      `json:"score,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	Expires   int64    `json:"expires,omitempty"`
}
type Entry struct {
	Seq   uint64 `json:"seq"`
	Prev  string `json:"prev"`
	Event Event  `json:"event"`
	Hash  string `json:"hash"`
}
type unsigned struct {
	Seq   uint64 `json:"seq"`
	Prev  string `json:"prev"`
	Event Event  `json:"event"`
}

func digest(e Entry) string { return wire.Hash(unsigned{e.Seq, e.Prev, e.Event}) }

type Journal struct {
	mu     sync.Mutex
	file   *os.File
	seq    uint64
	head   string
	spent  map[string]int64
	failed bool
	size   int64
}

var ErrReplay = errors.New("approval already consumed")

func Open(path string) (*Journal, error) {
	if st, e := os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
		return nil, errors.New("audit journal must be a private regular file (0600)")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = lock(f); e != nil {
		f.Close()
		return nil, e
	}
	j := &Journal{file: f, spent: map[string]int64{}}
	if st, e := f.Stat(); e == nil {
		j.size = st.Size()
	}
	if st, e := f.Stat(); e != nil || st.Size() > 256<<20 {
		j.Close()
		return nil, errors.New("journal exceeds 256 MiB: archive with an external checkpoint")
	}
	head, seq, e := Verify(f, "", func(e Entry) {
		if e.Event.Nonce != "" && e.Event.Expires > time.Now().Unix() {
			j.spent[e.Event.Nonce] = e.Event.Expires
		}
	})
	if e != nil {
		j.Close()
		return nil, e
	}
	j.head = head
	j.seq = seq
	if _, e = f.Seek(0, io.SeekEnd); e != nil {
		j.Close()
		return nil, e
	}
	return j, nil
}
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	e := j.file.Close()
	j.file = nil
	j.failed = true
	return e
}
func (j *Journal) Healthy() bool          { j.mu.Lock(); defer j.mu.Unlock(); return !j.failed && j.file != nil }
func (j *Journal) Head() (string, uint64) { j.mu.Lock(); defer j.mu.Unlock(); return j.head, j.seq }
func (j *Journal) Append(e Event) error   { j.mu.Lock(); defer j.mu.Unlock(); return j.append(e) }

// Consume atomically persists a nonce and a call intent before the external action.
func (j *Journal) Consume(e Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now().Unix()
	for n, exp := range j.spent {
		if exp <= now {
			delete(j.spent, n)
		}
	}
	if e.Nonce != "" {
		if _, ok := j.spent[e.Nonce]; ok {
			return ErrReplay
		}
		if e.Expires <= now {
			return errors.New("approval expired")
		}
	}
	if e := j.append(e); e != nil {
		return e
	}
	if e.Nonce != "" {
		j.spent[e.Nonce] = e.Expires
	}
	return nil
}
func (j *Journal) append(e Event) error {
	if j.failed || j.file == nil {
		return errors.New("audit journal unavailable")
	}
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	entry := Entry{Seq: j.seq + 1, Prev: j.head, Event: e}
	entry.Hash = digest(entry)
	b := append(wire.Canonical(entry), '\n')
	if len(b) > 32768 {
		return errors.New("audit event exceeds limit")
	}
	if j.size+int64(len(b)) > 256<<20 {
		j.failed = true
		return errors.New("audit journal capacity exhausted")
	}
	if _, err := j.file.Write(b); err != nil {
		j.failed = true
		return errors.New("audit write failed")
	}
	if err := j.file.Sync(); err != nil {
		j.failed = true
		return errors.New("audit fsync failed")
	}
	j.seq = entry.Seq
	j.head = entry.Hash
	j.size += int64(len(b))
	return nil
}

// Verify rejects truncated records, sequence gaps, duplicate JSON keys and edits.
func Verify(r io.Reader, expectedHead string, visit func(Entry)) (string, uint64, error) {
	br := bufio.NewReaderSize(r, 32768)
	var seq uint64
	head := ""
	for {
		b, e := br.ReadSlice('\n')
		if e == io.EOF && len(b) == 0 {
			break
		}
		if e != nil {
			return "", seq, errors.New("truncated or oversized audit record")
		}
		m, e := wire.Object(b)
		if e != nil {
			return "", seq, e
		}
		var v Entry
		if e = decodeEntry(m, &v); e != nil {
			return "", seq, e
		}
		if v.Seq != seq+1 || v.Prev != head || digest(v) != v.Hash {
			return "", seq, errors.New("audit chain verification failed")
		}
		head = v.Hash
		seq = v.Seq
		if visit != nil {
			visit(v)
		}
	}
	if expectedHead != "" && head != expectedHead {
		return head, seq, errors.New("audit checkpoint mismatch")
	}
	return head, seq, nil
}
