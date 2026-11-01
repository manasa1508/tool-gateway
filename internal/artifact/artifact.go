// Package artifact performs preflight checks without executing artifact code.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/manasa1508/tool-gateway/internal/scan"
	"github.com/manasa1508/tool-gateway/internal/wire"
)

type File struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}
type Report struct {
	Root     string      `json:"root"`
	Files    []File      `json:"files"`
	Findings scan.Report `json:"findings"`
}

func Inspect(root string) (Report, error) {
	r := Report{Files: []File{}}
	st, e := os.Lstat(root)
	if e != nil {
		return r, e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return r, errors.New("artifact root must be a real directory")
	}
	total := 0
	reports := map[string]scan.Finding{}
	e = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("artifact symlinks are not accepted")
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return errors.New("artifact contains special file")
		}
		if len(r.Files) >= 512 {
			return errors.New("artifact file count limit")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > 1048576 || total+int(info.Size()) > 8388608 {
			return errors.New("artifact size limit")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		total += len(b)
		if !utf8.Valid(b) {
			return errors.New("binary artifacts are unsupported; inspect source bundles")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		r.Files = append(r.Files, File{filepath.ToSlash(rel), hex.EncodeToString(h[:]), info.Mode()&0111 != 0})
		for _, f := range scan.Analyze(map[string]any{"path": rel, "content": string(b)}).Findings {
			reports[f.ID] = f
		}
		return nil
	})
	if e != nil {
		return r, e
	}
	if len(r.Files) == 0 {
		return r, errors.New("artifact is empty")
	}
	sort.Slice(r.Files, func(i, j int) bool { return r.Files[i].Path < r.Files[j].Path })
	r.Root = wire.Hash(r.Files)
	r.Findings.Findings = []scan.Finding{}
	for _, f := range reports {
		r.Findings.Findings = append(r.Findings.Findings, f)
		r.Findings.Score += f.Weight
		r.Findings.Secret = r.Findings.Secret || f.Secret
	}
	sort.Slice(r.Findings.Findings, func(i, j int) bool { return r.Findings.Findings[i].ID < r.Findings.Findings[j].ID })
	if r.Findings.Score > 100 {
		r.Findings.Score = 100
	}
	return r, nil
}
