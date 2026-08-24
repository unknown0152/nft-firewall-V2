package version

import "strings"

// Build metadata is injected by -ldflags for release binaries.
var (
	Version          = "development"
	Commit           = "unknown"
	Date             = "unknown"
	BuildDisposition = "development"
	ArtifactIdentity = "development|unknown|unknown|development"
)

const StageRCandidateOnly = "stage-r-candidate-only"

type Info struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	Date             string `json:"build_date"`
	BuildDisposition string `json:"build_disposition"`
	ArtifactIdentity string `json:"artifact_identity"`
}

func Current() Info {
	return Info{
		Version:          Version,
		Commit:           Commit,
		Date:             Date,
		BuildDisposition: BuildDisposition,
		ArtifactIdentity: ArtifactIdentity,
	}
}

func IsStageRCandidateOnly() bool {
	return BuildDisposition == StageRCandidateOnly || strings.Contains(Version, "~stage.r.")
}
