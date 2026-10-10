package remediation

// The Dockerfile part of the plan covers images the user builds themselves.
// Their findings in the layers of the base image are not fixed by updating a
// language package; the fix is a newer base image in the build stage's FROM.
// A plan item here is one edit location (one FROM of one Dockerfile), shared
// by every workload built through it, and three images stay apart in it: the
// running image that supplies the findings and their layers, the current base
// (the registry content of the FROM's tag) and the candidate base (the newest
// patch of the same series). Counts are the result of comparing the two bases
// on the findings the running image has in the base's layers; the image
// rebuilt from the candidate base is never scanned.

// Reasons of the Dockerfile part.
const (
	// ReasonBaseLayersMismatch: the registry content behind the FROM's tag is
	// not the start of the running image's layers.
	ReasonBaseLayersMismatch Reason = "base_layers_mismatch"
	// ReasonBaseLayersUnusable: the layers of the running image or of the base
	// cannot be compared.
	ReasonBaseLayersUnusable Reason = "base_layers_unusable"
	// ReasonBaseOnBuild: the current or the candidate base has ONBUILD
	// triggers, which a build runs on top of its own instructions.
	ReasonBaseOnBuild Reason = "base_onbuild"
	// ReasonNoBaseFindings: no fixed finding of the running image is in a layer
	// of the confirmed base.
	ReasonNoBaseFindings Reason = "no_base_derived_findings"
	// ReasonBaseUnchanged: the floating tag points at the base the running
	// image was built from.
	ReasonBaseUnchanged Reason = "base_unchanged"
	// ReasonFloatingBaseUnconfirmed: the floating tag no longer points at the
	// base the running image's layers start with, so what it was built from,
	// why it changed and what a rebuild improves are unknown.
	ReasonFloatingBaseUnconfirmed Reason = "floating_base_unconfirmed"
	// ReasonDockerfileSetNotAdopted: the workloads sharing one edit location do
	// not all confirm and adopt the same candidate.
	ReasonDockerfileSetNotAdopted Reason = "dockerfile_set_not_adopted"
	// ReasonDockerfileFileNotFound and ReasonDockerfileFileUnusable: the
	// Dockerfile is not at the named path, or is not a regular file the
	// editor can use.
	ReasonDockerfileFileNotFound Reason = "dockerfile_file_not_found"
	ReasonDockerfileFileUnusable Reason = "dockerfile_file_unusable"
)

// DockerfileOrigin says how a Dockerfile location was found.
type DockerfileOrigin string

const (
	// DockerfileFromMapping: the configuration names the Dockerfile.
	DockerfileFromMapping DockerfileOrigin = "mapping"
	// DockerfileFromCompose: read from the service's build section in the
	// Compose file.
	DockerfileFromCompose DockerfileOrigin = "compose_build"
	// DockerfileFromBoth: named in the configuration and read from the build
	// section, and the two agree.
	DockerfileFromBoth DockerfileOrigin = "mapping_and_compose_build"
)

// DockerfileMapping ties a running Compose workload to the Dockerfile that
// builds its image.
type DockerfileMapping struct {
	// Workload is the Compose workload key, compose/<project>/<service>;
	// Project and Service are its parts.
	Workload   string
	Project    string
	Service    string
	Repository string
	BaseBranch string
	Path       string // repository-relative, normalized
	Target     string // the build stage of the running image; "" for the last stage
}

// DockerfileSource says where a unit's Dockerfile came from and which FROM of
// it is edited.
type DockerfileSource struct {
	Repository string `json:"repository"`
	BaseBranch string `json:"base_branch"`
	// CommitSHA is the commit the branch resolved to; the Compose file and the
	// Dockerfile were both read from it. Empty when it could not be resolved.
	CommitSHA string `json:"commit_sha,omitempty"`
	Path      string `json:"path"`
	// Targets are the build stages the unit's workloads name, sorted; "" stands
	// for the last stage.
	Targets     []string         `json:"targets,omitempty"`
	Origin      DockerfileOrigin `json:"origin,omitempty"`
	ComposePath string           `json:"compose_path,omitempty"`
	Files       []SourceFile     `json:"files,omitempty"`
	// Stage is the index of the FROM that is edited, StageName its AS name and
	// Line its line; set once the Dockerfile has been read.
	Stage *int `json:"stage,omitempty"`
	// Platform is the static --platform of the edited FROM, "" when it has
	// none.
	Platform  string `json:"platform,omitempty"`
	StageName string `json:"stage_name,omitempty"`
	Line      int    `json:"line,omitempty"`
}

// LayerConfirmation is the outcome of matching the running image's
// filesystem layers against the base's.
type LayerConfirmation struct {
	// Status is "confirmed", "mismatch" or "unusable" (see BaseLayerStatus),
	// or "not_checked" when the check was not reached.
	Status string `json:"status"`
	// BaseLayers is how many layers the confirmed base contributes and
	// ImageLayers how many the running image has.
	BaseLayers  int    `json:"base_layers,omitempty"`
	ImageLayers int    `json:"image_layers,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// LayerNotChecked is the Status of a LayerConfirmation that was not reached.
const LayerNotChecked = "not_checked"

// LayerCounts is how many findings of the running image Trivy placed in the
// base's layers, above them, or could not place.
type LayerCounts struct {
	Base    int `json:"base"`
	Upper   int `json:"upper"`
	Unknown int `json:"unknown"`
}

// DockerfileEntity is one running image of an edit location with its three
// images, layer confirmation and comparison.
type DockerfileEntity struct {
	Services []ServiceRef `json:"services,omitempty"`
	// Running is the running image; CurrentBase the registry content of the
	// FROM's tag today; CandidateBase the content of the candidate tag. The
	// last two are nil until they were resolved.
	Running       ImageState  `json:"running"`
	CurrentBase   *ImageState `json:"current_base,omitempty"`
	CandidateBase *ImageState `json:"candidate_base,omitempty"`

	Layers   LayerConfirmation `json:"layers"`
	Findings LayerCounts       `json:"findings_by_layer"`

	Category Category `json:"category"`
	Reason   Reason   `json:"reason,omitempty"`
	Detail   string   `json:"detail,omitempty"`

	// Targets are the fixed findings in the base's layers, the set the
	// comparison is judged on.
	Targets []Target `json:"targets,omitempty"`
	// BaselineScan and CandidateScan are IDs into Plan.Scans: the scans of the
	// current base and of the candidate base.
	BaselineScan  string              `json:"baseline_scan,omitempty"`
	CandidateScan string              `json:"candidate_scan,omitempty"`
	Comparison    *VerificationResult `json:"comparison,omitempty"`
	Decision      *Decision           `json:"decision,omitempty"`
}

// DockerfileCounts summarizes an item's comparison across its running
// images: a target counts as resolved only when every image that has it
// resolves it.
type DockerfileCounts struct {
	Targets    int `json:"targets"`
	Resolved   int `json:"resolved"`
	Remaining  int `json:"remaining"`
	Introduced int `json:"introduced"`
}

// DockerfileItem is the plan entry of one edit location.
type DockerfileItem struct {
	Key       string   `json:"key"`
	Workloads []string `json:"workloads"`
	Priority  Priority `json:"priority,omitempty"` // strongest priority among the findings of the workloads' images

	Category Category `json:"category"`
	Reason   Reason   `json:"reason,omitempty"`
	Detail   string   `json:"detail,omitempty"`

	Source DockerfileSource `json:"source"`
	// BaseRef is the image the FROM names, as written; BaseKind classifies its
	// tag.
	BaseRef  string  `json:"base_ref,omitempty"`
	BaseKind TagKind `json:"base_kind,omitempty"`
	// Candidate is the candidate base, set when one was chosen and compared.
	Candidate *ImageState `json:"candidate,omitempty"`

	Entities []DockerfileEntity `json:"entities,omitempty"`
	Counts   DockerfileCounts   `json:"counts"`

	// FinalImageVerified is always false: the image rebuilt from the candidate
	// base is not built or scanned, and the instructions after the FROM can
	// change what the comparison of the bases shows.
	FinalImageVerified bool `json:"final_image_verified"`
}

// CountDockerfile returns how many Dockerfile items are in category c.
func (p Plan) CountDockerfile(c Category) int {
	n := 0
	for _, it := range p.DockerfileItems {
		if it.Category == c {
			n++
		}
	}
	return n
}
