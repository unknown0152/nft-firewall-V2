package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCurrentExposesBuildDisposition(t *testing.T) {
	previous := BuildDisposition
	previousIdentity := ArtifactIdentity
	BuildDisposition = StageRCandidateOnly
	ArtifactIdentity = "2.0.3~stage.r.aaaaaaaaaaaa|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|2026-08-24T00:00:00Z|stage-r-candidate-only"
	t.Cleanup(func() {
		BuildDisposition = previous
		ArtifactIdentity = previousIdentity
	})

	encoded, err := json.Marshal(Current())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"build_disposition":"stage-r-candidate-only"`) {
		t.Fatalf("version JSON omits exact build disposition: %s", encoded)
	}
	if !strings.Contains(string(encoded), `"artifact_identity":"2.0.3~stage.r.`) {
		t.Fatalf("version JSON omits composite artifact identity: %s", encoded)
	}
}

func TestStageRCandidateVersionCannotMasqueradeAsRelease(t *testing.T) {
	previousVersion, previousDisposition := Version, BuildDisposition
	t.Cleanup(func() {
		Version, BuildDisposition = previousVersion, previousDisposition
	})
	Version = "2.0.3~stage.r.aaaaaaaaaaaa"
	BuildDisposition = "release"
	if !IsStageRCandidateOnly() {
		t.Fatal("Stage R version escaped quarantine under a forged release disposition")
	}
}
