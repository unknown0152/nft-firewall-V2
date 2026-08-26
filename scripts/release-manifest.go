//go:build ignore

// release-manifest generates the machine-readable manifest embedded in a release tree.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type fileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
}

type artifactRecord struct {
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

type manifest struct {
	SchemaVersion   int              `json:"schema_version"`
	Product         string           `json:"product"`
	Version         string           `json:"version"`
	GitCommit       string           `json:"git_commit"`
	GitTag          string           `json:"git_tag"`
	BuildDate       string           `json:"build_date"`
	SourceDateEpoch int64            `json:"source_date_epoch"`
	GoVersion       string           `json:"go_version"`
	Files           []fileRecord     `json:"files"`
	Artifacts       []artifactRecord `json:"artifacts"`
}

var (
	binaryPattern = regexp.MustCompile(`^binaries/linux-(amd64|arm64)/(nftfw|nftfwd|nftfw-web)$`)
	debPattern    = regexp.MustCompile(`^packages/nft-firewall-v2_[^/]+_(amd64|arm64)\.deb$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func main() {
	root := flag.String("root", "", "release tree root")
	version := flag.String("version", "", "release version")
	commit := flag.String("commit", "", "full Git commit")
	tag := flag.String("tag", "", "Git tag or 'unreleased'")
	buildDate := flag.String("build-date", "", "RFC3339 build date")
	epochText := flag.String("source-date-epoch", "", "Unix source epoch")
	goVersion := flag.String("go-version", "", "exact Go toolchain version")
	output := flag.String("output", "", "manifest output path")
	flag.Parse()

	if err := run(*root, *version, *commit, *tag, *buildDate, *epochText, *goVersion, *output); err != nil {
		fmt.Fprintln(os.Stderr, "release manifest:", err)
		os.Exit(1)
	}
}

func run(root, version, commit, tag, buildDate, epochText, goVersion, output string) error {
	if root == "" || version == "" || tag == "" || buildDate == "" || epochText == "" || goVersion == "" || output == "" {
		return errors.New("all flags are required")
	}
	if !commitPattern.MatchString(commit) {
		return errors.New("commit must be a full lowercase SHA-1")
	}
	if goVersion != "go1.27.0" {
		return fmt.Errorf("unsupported release toolchain %q", goVersion)
	}
	if _, err := time.Parse(time.RFC3339, buildDate); err != nil {
		return fmt.Errorf("invalid build date: %w", err)
	}
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil || epoch <= 0 {
		return errors.New("source date epoch must be positive")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	relOutput, err := filepath.Rel(root, output)
	if err != nil || relOutput == ".." || strings.HasPrefix(filepath.ToSlash(relOutput), "../") {
		return errors.New("output must be inside the release root")
	}

	var files []fileRecord
	var artifacts []artifactRecord
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == filepath.ToSlash(relOutput) || rel == "SHA256SUMS" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular release entry: %s", rel)
		}
		sum, err := hashFile(path)
		if err != nil {
			return err
		}
		record := fileRecord{Path: rel, SHA256: sum, Size: info.Size(), Mode: fmt.Sprintf("%04o", info.Mode().Perm())}
		files = append(files, record)
		if match := binaryPattern.FindStringSubmatch(rel); match != nil {
			artifacts = append(artifacts, artifactRecord{Path: rel, Kind: "executable", OS: "linux", Architecture: match[1], SHA256: sum, Size: info.Size()})
		} else if match := debPattern.FindStringSubmatch(rel); match != nil {
			artifacts = append(artifacts, artifactRecord{Path: rel, Kind: "debian-package", OS: "linux", Architecture: match[1], SHA256: sum, Size: info.Size()})
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })

	data := manifest{
		SchemaVersion: 2, Product: "NFT Firewall V2", Version: version,
		GitCommit: commit, GitTag: tag, BuildDate: buildDate,
		SourceDateEpoch: epoch, GoVersion: goVersion, Files: files, Artifacts: artifacts,
	}
	parent := filepath.Dir(output)
	tmp, err := os.CreateTemp(parent, ".release-manifest-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, output)
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
