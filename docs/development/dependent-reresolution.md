# Development of re-resolution through dependent packages

- **Status:** Implemented (PR creation verified in the production environment).
- **Started:** October 15, 2026
- **Last updated:** October 18, 2026

## Purpose

Enable fixes for vulnerabilities blocked by a dependent package's requirement for an older version by updating that dependent package within the range declared by the project.
Check each dependency position to ensure that the update does not increase vulnerabilities.

## Fixes through dependent package updates

During remediation PR operations, `@nestjs/platform-express` 11.1.27 required exactly `multer` 2.1.1, so updating `multer` alone could not fix the vulnerability.

```text
Before: Project → @nestjs/platform-express 11.1.27 → multer 2.1.1 (vulnerable)
After:  Project → @nestjs/platform-express 11.2.7 → multer 2.4.0
```

Updating the dependent package, `@nestjs/platform-express`, to a newer version within the range declared in the project's `package.json` also brings `multer` to a fixed version.
This is re-resolution through dependent packages.

The package manager selects versions again within the declared ranges, and KestreLynx does not widen those ranges.

An earlier option was to include dependent packages in notifications, but the decision was to update them when they can be identified.

## Approach

- **Run normal updates first, and re-resolve only when a dependent package's requirement is proven to be the cause.**
    - This avoids updating dependent packages for vulnerabilities that normal updates can fix.
- **Resolve again from the top-level direct dependencies within the project's declared ranges, without widening those ranges or using `overrides`.**
    - This respects the version constraints allowed by the project.
- **Wait 72 hours after release before introducing a package version.**
    - This avoids adopting versions immediately after release.

See [Re-resolution through dependent packages](../documentation/remediation-logic.md#dependent-reresolution) for the mechanism and [Re-resolution support and limits](../documentation/remediation-reference.md#dependent-reresolution-limits) for its scope and limits.

## Decisions

### Checks against vulnerability increases

Updating a top-level direct dependency also changes packages beneath it, raising concerns about an increase in vulnerabilities.
The following conditions were adopted.

- Versions must not decrease on any dependency path.
- Other direct dependencies must remain unchanged, except for normal update targets and starting points for re-resolution.
- The update must not increase vulnerabilities.

### Treatment of carried vulnerabilities

Strict comparisons of package names, versions, and vulnerability IDs reject almost every update when a dependent package has another vulnerability that cannot be fixed within the declared range.
The decision was therefore to allow a vulnerability to be carried when only the version changes at the same dependency position and the same vulnerability remains.

```text
Before: A 1.0 → Y 1.0 (with CVE-2)
After:  A 2.0 → Y 1.1 (with CVE-2)
```

In this example, `CVE-2` remaining in `Y` is treated as carried.
Carried vulnerabilities remain unfixed, and a vulnerability targeted for fixing in this update cannot pass the checks by qualifying as carried.

### Checks at each dependency position

```text
Before: Project → A → X 1.0 (no vulnerabilities)
        Project → B → X 2.0 (with CVE-9)

After:  Project → A → X 2.0 (with CVE-9)
        Project → B (no longer uses X)
```

There is one occurrence of X with CVE-9 both before and after the update, so the count does not increase.
However, the update fails the checks because X at A's position changes from a version without vulnerabilities to one with CVE-9.

- For each dependency changed by the update, find its position before the update by following the same path from the project.
- Compare it with the old version at that position to check for new vulnerabilities.
- Reject the update if the position before the update cannot be found or uniquely determined.

Checks at each position reject the following changes even when the count does not increase.
In the table below, `→` represents a dependency, and `⇒` represents a change from before to after the update.

| Change | Example (before ⇒ after) | Reason for rejection |
| --- | --- | --- |
| A new vulnerable package is introduced | `A` (without X) ⇒ `A → X (vulnerable)` | X is absent from the same position before the update, so its vulnerability cannot be treated as carried |
| More dependent packages use a vulnerable package | `A → X (vulnerable)` ⇒ `A → X (vulnerable)`, `B → X (vulnerable)` | A vulnerable X is newly introduced at B's position |
| A new version has a vulnerability absent from the old version | `A → X 1.0 (CVE-2)` ⇒ `A → X 2.0 (CVE-2, CVE-9)` | CVE-9 is added, although it is absent from the old version at the same position |
| One version splits into multiple vulnerable versions | `A → X 1.0`, `B → X 1.0` ⇒ `A → X 1.1 (vulnerable)`, `B → X 1.2 (vulnerable)` | A split from one old version into multiple vulnerable versions cannot qualify as carrying vulnerabilities |
| Multiple paths merge into one | `A → X 1.0`, `B → X 2.0` ⇒ `A → X 3.0`, `B → X 3.0` | A single old version cannot be determined for comparison with X after the merge |

See [Re-resolution check conditions](../documentation/remediation-reference.md#dependent-reresolution-rules) for the detailed conditions.

## Verification methods and results

### Integration tests with actual package managers

Re-resolution and check results were verified using npm 10, pnpm 9.15.9, 10.34.4, and 12.11.2, and uv 0.13.

- For npm and pnpm, the `mkdirp 0.5.1 → minimist 0.0.8` example confirmed that `mkdirp` was the only direct dependency updated and that `minimist` reached a fixed version.
- The `rc 1.2.8 → minimist ^1.2.0` path confirmed that the `rc` version stayed unchanged because a normal update could fix the vulnerability.
- Tests confirmed that an update failed the checks when updating the dependent package could not fix the targeted vulnerability.
- For uv, tests confirmed that an update failed the checks because it introduced a new vulnerability in `cryptography`, even though the vulnerability in `pyopenssl` qualified as carried.

### Verification in the production environment

On October 18, 2026, the first run after deployment created a PR updating `@nestjs/platform-express` from 11.1.27 to 11.2.7 and `multer` from 2.1.1 to 2.4.0.

The checks at each dependency position also passed.
The next run associated the update with the existing PR without rerunning the same update.

## Unverified areas and next steps

- Verification after merging the PR created in the production environment remains pending.
- Acceptance of an update with carried vulnerabilities was verified only in unit tests because no such case could be produced with the integration tests' severity settings (HIGH and CRITICAL).
- pip is outside the scope of re-resolution through dependent packages.
- Measurements supporting the default limits remain pending.

## Update history

### October 18, 2026

- Documented the approach and checks for re-resolution through dependent packages.
- Documented carried vulnerabilities and checks at each dependency position.
- Recorded integration tests and verification in the production environment.

---

This article is a development record for KestreLynx. [About KestreLynx](../index.md)
