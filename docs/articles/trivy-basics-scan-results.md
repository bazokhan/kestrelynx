---
description: "Understand Trivy scan coverage and read JSON findings, fix status, and severity sources. Combine results with KEV and EPSS to prioritize remediation."
---

# Trivy Basics and How to Read Scan Results

Published: September 10, 2026

## Introduction

Trivy is a tool for checking container images for vulnerabilities. To use its
results, you need to understand what was scanned and what each field means,
as well as the number and severity of the findings.

This article explains Trivy's basics, scan targets, how to read JSON output,
and considerations when using the results for vulnerability management.

## What is Trivy?

Trivy is an open-source security scanner developed by Aqua Security. In
addition to known vulnerabilities, it can detect misconfigurations and
credentials embedded in files.

| Feature | What it checks or produces |
| --- | --- |
| Vulnerability scanning | Known vulnerabilities in OS packages and dependencies |
| Misconfiguration scanning | Configuration issues in Dockerfiles, Kubernetes, Terraform, and other files |
| Secret detection | Content that appears to contain sensitive information, such as API keys |
| License scanning | Package license information |
| SBOM generation | An inventory of detected software components |

Not every feature is enabled for every target. Coverage depends on the
combination of target, scanners, and options.[^trivy]

Vulnerability detection works by identifying software and its version, then
matching it against the corresponding vulnerability information. Trivy does
not send attacks to an application to test whether exploitation succeeds.

A detected vulnerability and a successful attack in your environment are
therefore different things.

## Trivy scan targets

Common scan targets and commands include:

| Target | Example command | Main contents examined |
| --- | --- | --- |
| Container image | `trivy image nginx:1.20` | OS packages, libraries, files, and other image contents |
| Local directory | `trivy fs ./my-project` | Dependency manifests, configuration files, and other files in the specified location |
| Git repository | `trivy repo https://github.com/owner/repo` | Dependency manifests, configuration files, and other repository contents |

The repository URL is a placeholder. Replace it with the URL of the
repository you want to scan.

`trivy fs` also accepts a single file. You can specify a supported lock file
directly to check its dependencies for vulnerabilities.[^filesystem]

`trivy repo` scans source repositories. The documentation describes support
for files such as lock files, but excludes build artifacts such as JARs and
binaries.[^repository]

### Why file and image scans produce different results

Consider a Node.js application repository containing a `package-lock.json`
file and a Dockerfile.

- A repository scan examines dependencies recorded in files such as lock files.
- An image scan examines the OS packages and libraries actually present in the built image.
- A base image named in a Dockerfile's `FROM` instruction is not automatically scanned by scanning the repository.

Development files and the artifacts you distribute and run provide different
information. Neither type of scan necessarily produces more findings than
the other.

Development dependencies are not necessarily scanned just because they
appear in a lock file. Check support for the language and the settings for
including development dependencies.

### Shared output formats

`fs`, `repo`, and `image` support common output formats, including tables and
JSON.

```bash
trivy fs --format json ./my-project
trivy image --format json nginx:1.20
```

The basic JSON structure and main vulnerability fields are shared, but some
fields, such as image IDs and layer information, are specific to the target.
Not every field is always present.[^reporting]

## Installing Trivy

Follow the [official installation instructions](https://trivy.dev/docs/latest/getting-started/installation/)
to install Trivy. Then check its version:

```bash
trivy --version
```

## Scanning an image and producing JSON output

The basic command for scanning an image is:

```bash
trivy image nginx:1.20
```

Trivy downloads its vulnerability database when needed, including on the
first run. Installing Trivy and updating vulnerability information are
separate operations. The same Trivy version can produce different results
depending on the database it uses.[^database]

To save the results as JSON, specify the output format and file name:

```bash
trivy image --format json --output trivy_nginx.json nginx:1.20
```

To explicitly request the package inventory as well, use:

```bash
trivy image --format json --list-all-pkgs \
  --output trivy_nginx.json nginx:1.20
```

An existing output file with the same name is overwritten. Use a different
name if you want to keep earlier results.[^reporting]

## How to read scan results

This section uses counts and JSON excerpts from a scan of `nginx:1.20`
performed with Trivy 0.71.2 on September 9, 2026.

The version you install and the results of a new scan may differ from this
example.

### Scan target and counts

| Item | Recorded value |
| --- | --- |
| Trivy | 0.71.2 |
| Report creation time | September 9, 2026, 10:45 JST |
| Target | `nginx:1.20` |
| Detected OS | Debian 11.3 |
| nginx package version | 1.20.2 |
| Packages in the inventory | 142 |
| Vulnerability finding records | 866 |
| Unique vulnerability IDs | 548 |

The finding counts by severity are:

| Severity | Finding records |
| --- | ---: |
| CRITICAL | 32 |
| HIGH | 217 |
| MEDIUM | 348 |
| LOW | 238 |
| UNKNOWN | 31 |

The 866 records do not mean there are 866 different CVEs. A CVE affecting
multiple packages can produce multiple records. These counts also cover
packages throughout the image, not just nginx itself.

These figures summarize the scan taken at the time shown above. Running the
same command again does not necessarily produce the same results.

### Overall JSON structure

With only the main fields included, the JSON output has this structure:

```json
{
  "Trivy": {
    "Version": "0.71.2"
  },
  "ArtifactName": "nginx:1.20",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {
      "Family": "debian",
      "Name": "11.3"
    }
  },
  "Results": [
    {
      "Target": "nginx:1.20 (debian 11.3)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Packages": [],
      "Vulnerabilities": []
    }
  ]
}
```

This example illustrates the overall structure and omits some fields.
`Packages` and `Vulnerabilities` are shown as empty arrays for clarity; the
actual scan results contain package and vulnerability records.

`Metadata` describes the scan target, while `Results` is an array of results
for individual targets. The example shows one element in `Results`. That
element has a `Packages` inventory and a `Vulnerabilities` list.

The output can be divided into three main groups:

| Group | Contents |
| --- | --- |
| Report information | Trivy version, creation time, target name, and identifiers |
| `Metadata` | OS, image, layers, build history, and startup configuration |
| `Results` | Detected packages and vulnerabilities |

To examine vulnerabilities, start with `Vulnerabilities` in `Results`, then
consult `Packages` and `Metadata` as needed.

## Main fields in a vulnerability record

Vulnerability records are stored in the `Vulnerabilities` array of each
`Results` element (`Results[].Vulnerabilities[]`). Here are the main fields
from a record whose `PkgName` is `apt`:

```json
{
  "VulnerabilityID": "CVE-2011-3374",
  "PkgName": "apt",
  "InstalledVersion": "2.2.4",
  "Status": "affected",
  "Severity": "LOW",
  "SeveritySource": "debian"
}
```

| Field | How to read it |
| --- | --- |
| `VulnerabilityID` | Which vulnerability was detected |
| `PkgName` | Which package it affects |
| `InstalledVersion` | The version installed in the image |
| `FixedVersion` | A version with a fix; omitted when that information is unavailable |
| `Status` | The remediation status reported by the vulnerability source |
| `Severity` | The severity selected by Trivy |
| `SeveritySource` | The source of the selected severity |

This record reports that apt 2.2.4 is affected by CVE-2011-3374 and uses
Debian's LOW severity rating. It does not tell you whether a running
application calls the vulnerable functionality.

### How Status relates to the fixed version

The same scan's `Results[].Vulnerabilities[]` also contains a record whose
`PkgName` is `bsdutils`. Its main fields are:

```json
{
  "VulnerabilityID": "CVE-2024-28085",
  "PkgName": "bsdutils",
  "InstalledVersion": "1:2.36.1-8+deb11u1",
  "FixedVersion": "2.36.1-8+deb11u2",
  "Status": "fixed"
}
```

`Status: fixed` means a fixed version is available, not that the image has
already been fixed. Here, the installed version ends in `deb11u1`, while
the fixed version is `deb11u2`.

The statuses and their finding counts in this JSON output are:

| Status | Meaning | Finding records |
| --- | --- | ---: |
| `fixed` | A fixed version is available | 437 |
| `affected` | The package is listed as affected | 305 |
| `fix_deferred` | The fix has been deferred | 90 |
| `will_not_fix` | There are no plans to fix it | 34 |

An absent `FixedVersion` does not mean the package is safe or unaffected.
A fix may not be available, or the information may not have been
recorded.[^filtering]

## Severity selection and CVSS

`Severity` is a rating that Trivy selects from external vulnerability
information. It is not a CVSS score calculated independently by Trivy.

Trivy selects external assessments and, when necessary, maps them to a
severity level. By default, it prefers the relevant vendor's severity. If
that is unavailable, it derives a severity from the supplied CVSS score.
If that information is also unavailable, it consults sources such as NVD.

When NVD and Debian rate the same CVE differently, Trivy's `Severity` may
therefore differ from what you see in NVD. Vendors can account for
distribution details such as build options and default settings.[^severity]

The earlier `apt` record contains these assessment fields:

```json
{
  "Severity": "LOW",
  "SeveritySource": "debian",
  "VendorSeverity": {
    "debian": 1,
    "nvd": 1
  },
  "CVSS": {
    "nvd": {
      "V2Score": 4.3,
      "V3Score": 3.7
    }
  }
}
```

This excerpt includes NVD scores in `CVSS`, but its `SeveritySource` is
`debian`. The presence of `CVSS.nvd` does not mean the displayed severity
was determined solely from NVD's scores.

`VendorSeverity` uses enumeration values: 0 for UNKNOWN, 1 for LOW, 2 for
MEDIUM, 3 for HIGH, and 4 for CRITICAL. These are not CVSS scores.

`CVSS` can also contain assessments from different CVSS versions for each
source. A `V3Vector` beginning with `CVSS:3.1` represents a v3.1 assessment.
Not every CVE has a v4.0 score.

## Combining results with KEV and EPSS

This scan's JSON includes CVSS assessments, but no dedicated fields for
KEV membership or EPSS scores.

| Information | What it tells you | How to obtain it for these results |
| --- | --- | --- |
| CVSS | Technical severity | Read `CVSS` in the JSON output |
| KEV | Whether CISA has confirmed exploitation and included the CVE in its catalog | Match CVE IDs against the KEV Catalog |
| EPSS | The estimated probability of exploitation in the wild within the next 30 days | Retrieve scores using CVE IDs |

CISA publishes KEV data as JSON and CSV. Absence from the catalog does not
prove that a vulnerability has not been exploited.[^kev]

FIRST provides EPSS through an API and CSV files, among other formats. The
API is useful for looking up a small number of CVEs, while daily CSV files
are useful for bulk retrieval. EPSS is not the probability that your
particular server will be compromised.[^epss][^epss-data]

To enrich Trivy results with this information, use `VulnerabilityID` as the
common key.

## Considerations when using scan results

### No reported vulnerabilities does not necessarily mean safe

This scan confirmed that nginx was present in the image, but did not report
any vulnerabilities for nginx.

Completing an image scan does not mean every package in the image was
checked for vulnerabilities. If nginx was excluded from vulnerability
scanning, its vulnerabilities would not be detected.

For example, Trivy uses Debian's vulnerability information when checking
Debian packages. That information covers packages distributed by Debian.
Packages installed from another source, such as the nginx developers, may
be excluded from the scan.[^third-party]

The nginx package in this example was also recorded as coming from a
source other than Debian. These results alone do not establish whether it
was checked, so the absence of reported vulnerabilities cannot establish
that it is safe.

### Check OS end-of-support information

This scan recorded the following values in `Metadata.OS`:

```json
{
  "Family": "debian",
  "Name": "11.3",
  "EOSL": true
}
```

This records Trivy's assessment that the OS had reached the end of support
at the time of the scan. It does not necessarily account for current
support contracts or every extended support program. Consult the OS
provider's information when making operational decisions.

### Results can change for the same image

Even if an image is unchanged, newly published vulnerabilities and
corrections to existing information can change the findings. This is why
rescanning an image later is useful, even if it was scanned when built.

To investigate differences, record the image digest, Trivy version, scan
time, options, and information about the vulnerability database used.

### Filtered vulnerabilities still exist

For example, `--ignore-unfixed` excludes findings such as vulnerabilities
without an available fix. This can help focus on actionable fixes, but it
does not provide a complete picture.

Severity filters and exclusion settings have the same limitation. Before
comparing finding counts, check that the scan conditions match.[^filtering]

## JSON field reference

This section lists fields in this scan's JSON output, including fields not
covered earlier. It is not a complete schema shared by every Trivy scan
target.

The structure below shows where the fields belong. `Metadata` and `Results`
are both top-level properties. `Packages` and `Vulnerabilities` are
properties of each element in the `Results` array.

This JSONC example includes explanatory comments. Some fields are omitted,
and hash values are replaced with `"..."`. Trivy's actual JSON output does
not contain comments.

```jsonc
{
  "SchemaVersion": 2, // Version of the report's JSON structure
  "Trivy": {
    "Version": "0.71.2" // Trivy version used for the scan
  },
  "ArtifactName": "nginx:1.20", // Name of the scan target
  "Metadata": { // Information about the target image
    "OS": {
      "Family": "debian", // OS distribution in the image
      "Name": "11.3" // OS version
    },
    "Layers": [ // Image layers
      {
        "Digest": "..." // Hash of this layer
      }
    ],
    "ImageConfig": {
      "architecture": "amd64" // CPU architecture of the image
    }
  },
  "Results": [ // Results for individual targets
    {
      "Class": "os-pkgs", // This element contains OS package scan results
      "Packages": [ // Packages found in the image
        {
          "Name": "apt", // Package name
          "Version": "2.2.4" // Package version
        }
      ],
      "Vulnerabilities": [ // Detected vulnerabilities
        {
          "VulnerabilityID": "CVE-2011-3374", // Vulnerability ID
          "PkgName": "apt", // Package affected by this vulnerability
          "InstalledVersion": "2.2.4" // Version of that package
        }
      ]
    }
  ]
}
```

Each section below identifies where its fields belong. A dot (`.`)
separates levels in the property hierarchy, and `[]` represents each array
element.

### Report information (top level of the JSON)

These are top-level properties, except for `Trivy.Version`, which is the
`Version` property of the top-level `Trivy` object.

| Field | Meaning |
| --- | --- |
| `SchemaVersion` | JSON structure version; 2 in this example |
| `Trivy.Version` | Trivy version used for the scan |
| `ReportID` | Report identifier |
| `CreatedAt` | Report creation time |
| `ArtifactID` | Identifier Trivy uses for the scan target |
| `ArtifactName` | Target name |
| `ArtifactType` | Target type; `container_image` in this example |

### Metadata (target image information)

These fields belong to the top-level `Metadata` object.

| Field in `Metadata` | Meaning |
| --- | --- |
| `Size` | Total image layer size in bytes |
| `OS.Family` | OS distribution family |
| `OS.Name` | Detected OS version |
| `OS.EOSL` | Trivy's end-of-support assessment |
| `ImageID` | Image identifier |
| `Reference` | Target image reference string |
| `RepoTags` | List of tags |
| `RepoDigests` | References combining repository names and digests |
| `DiffIDs` | Hashes of uncompressed layers |
| `Layers` | Information about individual layers |
| `Layers[].Size` | Size of each layer in bytes |
| `Layers[].Digest` | Hash of the distributed layer data |
| `Layers[].DiffID` | Hash of the uncompressed layer data |
| `ImageConfig` | Image configuration; its fields are described in the next table |

Identifiers and hashes serve different purposes. Similar names do not make
them interchangeable.[^report-types][^layer-size]

### ImageConfig (configuration in Metadata)

These fields belong to `Metadata.ImageConfig`. They describe configuration
recorded in the image.

| Field in `Metadata.ImageConfig` | Meaning |
| --- | --- |
| `architecture` | CPU architecture; `amd64` in this example |
| `os` | OS type; `linux` in this example |
| `created` | Image creation time |
| `history` | Build history |
| `history[].created` | Creation time of each build step |
| `history[].created_by` | Command or other information describing how the step was generated |
| `history[].empty_layer` | `true` if the step does not add a filesystem layer |
| `rootfs.type` | Filesystem structure type; `layers` in this example |
| `rootfs.diff_ids` | Uncompressed hashes of the constituent layers |
| `config.Entrypoint` | Program executed at startup |
| `config.Cmd` | Default command and arguments |
| `config.Env` | Environment variables |
| `config.Labels` | Additional metadata, such as maintainer information |
| `config.Labels.maintainer` | Label identifying the maintainer |
| `config.ExposedPorts` | Intended ports; `80/tcp` in this example |
| `config.StopSignal` | Signal used to stop the container; `SIGQUIT` in this example |

`ExposedPorts` alone does not publish a port on the host. Environment
variables and startup commands can also be overridden at runtime, so these
fields do not describe the observed state of a running container.[^image-config]

### Results (results for individual targets)

These fields belong to each element of the top-level `Results` array.

| Field in `Results[]` | Meaning |
| --- | --- |
| `Target` | Target name for this result |
| `Class` | Result classification; `os-pkgs` for OS packages in this example |
| `Type` | Type of target analyzed; `debian` in this example |
| `Packages` | Inventory of detected packages |
| `Vulnerabilities` | List of vulnerability finding records |

### Packages (package inventory in Results)

These fields belong to each element of `Results[].Packages[]`.

| Field in `Results[].Packages[]` | Meaning |
| --- | --- |
| `ID` | Package ID, such as `adduser@3.118` |
| `Name` | Package name |
| `Identifier.PURL` | Standard Package URL identifying the package type, name, version, and other attributes |
| `Identifier.UID` | Identifier used to distinguish packages |
| `Version` | Package version |
| `Release` | Distribution package revision |
| `Epoch` | Numeric value used to adjust version comparison order |
| `Arch` | Supported architecture; `all` means architecture-independent |
| `SrcName` | Name of the source package |
| `SrcVersion` / `SrcRelease` / `SrcEpoch` | Source package version information |
| `Licenses` | List of licenses |
| `Maintainer` | Package maintainer |
| `Repository.Class` | Repository classification: `official` for the OS provider's repository, or `third-party` for another provider |
| `DependsOn` | IDs of packages this package depends on |
| `Layer.Digest` / `Layer.DiffID` | Layer hashes associated with the package |
| `InstalledFiles` | Paths of installed files belonging to the package |
| `AnalyzedBy` | Analyzer used; `dpkg` in this example |

The presence of license information or file lists does not itself indicate
that a problem was detected.[^package-types]

### Vulnerabilities (vulnerability list in Results)

These fields belong to each element of `Results[].Vulnerabilities[]`.

| Field in `Results[].Vulnerabilities[]` | Meaning |
| --- | --- |
| `VulnerabilityID` | Vulnerability identifier, such as a CVE ID |
| `PkgID` / `PkgName` | ID and name of the affected package |
| `PkgIdentifier.PURL` / `PkgIdentifier.UID` | Identifiers for the affected package |
| `InstalledVersion` | Installed version |
| `FixedVersion` | Version with a fix |
| `Status` | Remediation status reported by the information source |
| `Layer.Digest` / `Layer.DiffID` | Layer information for the affected package |
| `Severity` | Selected severity |
| `SeveritySource` | Source of the selected severity |
| `VendorSeverity` | Enumerated severity values by source |
| `CVSS` | CVSS assessments by source |
| `CVSS.*.V2Score` | CVSS v2 score; `*` represents a source name such as `nvd` |
| `CVSS.*.V3Score` | CVSS v3 score |
| `CVSS.*.V40Score` | CVSS v4.0 score |
| `CVSS.*.V2Vector` | Vector string describing the CVSS v2 assessment |
| `CVSS.*.V3Vector` | Vector string describing the CVSS v3 assessment |
| `CVSS.*.V40Vector` | Vector string describing the CVSS v4.0 assessment |
| `CweIDs` | CWE IDs classifying the type of weakness |
| `Title` / `Description` | Title and detailed description |
| `PrimaryURL` | Main page with further details |
| `References` | List of related resource URLs |
| `DataSource.ID` / `DataSource.Name` / `DataSource.URL` | ID, name, and URL of the advisory source used for detection |
| `VendorIDs` | Vendor advisory IDs and similar identifiers |
| `Fingerprint` | Hash identifying a combination of target, package, vulnerability, and related attributes |
| `PublishedDate` | Publication time of the vulnerability information |
| `LastModifiedDate` | Last modification time of the vulnerability information |

`PublishedDate` and `LastModifiedDate` do not indicate when the vulnerability
was first detected in this image. `DataSource` and `SeveritySource` also
serve different purposes: the source used for detection and the source of
the selected severity, respectively.[^vulnerability-types]

## Summary

Trivy is a security scanner that detects known vulnerabilities and
configuration issues in targets such as container images, local files, and
Git repositories.

- Scan coverage depends on the target and options.
- JSON output includes package inventories, vulnerability records, and image configuration.
- The number of finding records differs from the number of unique vulnerability IDs.
- `Status: fixed` indicates that a fix is available, not that the target image has been fixed.
- Read `Severity` together with `SeveritySource` and `CVSS` to understand the assessment.
- Detecting a package does not necessarily mean it was checked against vulnerability information.
- Matching CVE IDs against KEV and EPSS adds information for prioritizing remediation.

When reading results, distinguish between which packages are present, what
was detected by matching vulnerability information, and what you should
prioritize in your environment.

Finding counts and severity alone do not determine impact or remediation
priority. Check the scope of the scan and the basis of the assessments,
then consider fix availability, observed exploitation, and how the packages
are used.

## References

Document reviewed: September 10, 2026. The counts and JSON excerpts in this
article are based on a scan performed with Trivy 0.71.2 on September 9, 2026.

///Footnotes Go Here///

[^trivy]: [Trivy: Official repository](https://github.com/aquasecurity/trivy)

[^filesystem]: [Trivy: Filesystem](https://trivy.dev/docs/latest/guide/target/filesystem/)

[^repository]: [Trivy: Code Repository](https://trivy.dev/docs/latest/target/repository/)

[^reporting]: [Trivy: Reporting](https://trivy.dev/docs/latest/configuration/reporting/)

[^database]: [Trivy: Databases](https://trivy.dev/docs/latest/configuration/db/)

[^filtering]: [Trivy: Status and filtering](https://trivy.dev/docs/latest/configuration/filtering/)

[^severity]: [Trivy: Severity selection](https://trivy.dev/docs/latest/guide/scanner/vulnerability/#severity-selection)

[^kev]: [CISA: Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

[^epss]: [FIRST: EPSS FAQ](https://www.first.org/epss/faq)

[^epss-data]: [FIRST: EPSS Get the Data](https://www.first.org/epss/data)

[^third-party]: [Trivy: Third-party packages](https://trivy.dev/docs/latest/guide/scanner/vulnerability/#third-party-packages)

[^report-types]: [Trivy: Report types](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types)

[^layer-size]: [Trivy: Layer size specification](https://github.com/aquasecurity/trivy/issues/8767)

[^image-config]: [OCI: Image Configuration](https://github.com/opencontainers/image-spec/blob/main/config.md)

[^package-types]: [Trivy 0.71.2: Package type](https://pkg.go.dev/github.com/aquasecurity/trivy@v0.71.2/pkg/fanal/types#Package)

[^vulnerability-types]: [Trivy: Detected vulnerability type](https://pkg.go.dev/github.com/aquasecurity/trivy/pkg/types#DetectedVulnerability)

---

KestreLynx is open-source software that regularly scans images used by running Docker and Kubernetes containers with Trivy and sends changes since the last scan and priorities based on severity, CISA KEV, and EPSS to Slack or a webhook. For Docker and Compose, remediation plans and pull requests (experimental) support remediation from comparing update candidates to creating GitHub pull requests, with both features disabled by default. Users handle merging, rebuilding, and deployment.

[Learn more about KestreLynx](../index.md) · [View the source on GitHub](https://github.com/kitsunetrail/kestrelynx)
