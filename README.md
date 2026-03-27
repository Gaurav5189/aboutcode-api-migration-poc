# ScanCode.io → VulnerableCode V2 Advisory API Migration — PoC

**GSoC 2026 Proposal PoC** | Project: *ScanCode.io: migrate to fetching advisories data from vulnerablecode*

This repository is a working Proof-of-Concept demonstrating the core technical work required for the GSoC migration project. It shows exactly how `scancode.io` will need to change its API consumption layer to work with VulnerableCode's new advisory-first model introduced in v37.0.0.

---

## Why This Migration Is Needed

VulnerableCode completed a major architectural shift in [PR #1866](https://github.com/aboutcode-org/vulnerablecode/pull/1866) — moving from a **vulnerability-first** model to an **advisory-first** model. ScanCode.io's `find_vulnerabilities` pipeline has not yet been updated to use this new model.

---

## The Core Conceptual Change

### Old Model — Vulnerability-First (what scancode.io currently does)

```
Query:    GET /api/packages?purl=pkg:pypi/django@2.2.0
                                │
                                ▼
Response: {
  "purl": "pkg:pypi/django@2.2.0",       ← Package is the center
  "affected_by_vulnerabilities": [        ← Vulnerabilities are nested inside
    {
      "vulnerability_id": "VCID-xxx",
      "risk_score": 4.9,
      "aliases": ["CVE-2021-33203"],
      "summary": "...",
    }
  ]
}
```

**Problem:** The package is the primary object. Vulnerability data is denormalized and duplicated across packages.

---

### New Model — Advisory-First (what scancode.io needs to do)

```
Query:    GET /api/v2/advisories/?affected_packages=pkg:pypi/django@2.2.0
                                │
                                ▼
Response: {
  "advisory_id": "VCID-xxx",             ← Advisory is the center
  "aliases": ["CVE-2021-33203"],
  "summary": "...",
  "date_published": "2021-06-02",
  "severities": [                         ← Structured severity (not flat risk_score)
    { "system": "cvssv3", "value": "4.9", "scoring_elements": "CVSS:3.1/..." }
  ],
  "affected_packages": [                  ← Packages are nested inside advisory
    {
      "purl": "pkg:pypi/django@2.2.0",
      "affected_version_range": "vers:pypi/>=2.2.0,<2.2.24",
      "fixed_version": "2.2.24",
    }
  ]
}
```

**Benefit:** The advisory is the single source of truth. All affected packages, fix versions, and severity data live in one place.

---

## Old JSON vs New JSON — Field Mapping

| Old V1 Field | New V2 Field | Notes |
|---|---|---|
| `vulnerability_id` (VCID) | `advisory_id` | Primary key has changed |
| `aliases` | `aliases` | Same — CVE/GHSA/RHSA etc. |
| `risk_score` (float) | `severities[].value` | Now structured per scoring system |
| `summary` | `summary` | Same |
| *(not present)* | `date_published` | New field in V2 |
| *(not present)* | `affected_version_range` | New — per-package version range |
| *(not present)* | `fixed_version` | New — per-package fix version |
| Package embeds vulns | Advisory embeds packages | **Core structural inversion** |

---

## Files in This PoC

### `fetcher.py`
Queries the live `public.vulnerablecode.io` API. Shows both the old V1 endpoint and the new V2 advisory endpoint side-by-side so you can see the structural difference in real responses.

```bash
python fetcher.py                  # anonymous (rate limited)
python fetcher.py --token <token>  # with API token
python fetcher.py --no-bulk        # skip bulk advisory demo call
```

Saves raw API responses to `testcase/live_api_comparison.json` for offline development.

### `mapper.py`
The most important file. Takes a raw V2 advisory JSON response and maps it into the data structure that `scancode.io` uses when saving vulnerability data to its database.

Works fully offline using embedded sample data — no API call needed.

```bash
python mapper.py
```

---

## Live API Test Results

The `live_api_comparison.json` file contains real responses captured from
`public.vulnerablecode.io` on 27/03/26.

### Key Finding

| Package | V1 `/api/packages/` | V2 `/api/v2/advisories/` |
|---|---|---|
| `pkg:pypi/django@2.2.0` | 37,000+ lines, full vulnerability data | `{}` — empty |
| `pkg:npm/lodash@4.17.4` | Full data with 4 vulnerabilities | `{}` — empty |

**The V2 advisory endpoint returned empty results for both test packages.**
This is not a bug in this PoC — it confirms that VulnerableCode's internal
migration to the advisory-first model is still in progress. The package data
exists in the V1 model but has not yet been fully re-indexed into the V2
advisory model.

This is precisely why the GSoC project is needed: scancode.io must be
migrated in parallel with VulnerableCode completing its advisory indexing.

---

## What Lines in scancode.io Need to Change

The main file to refactor is `scanpipe/pipes/vulnerablecode.py`.

### 1. The API endpoint URL

```python
# CURRENT (line ~30 in vulnerablecode.py)
VULNERABLECODE_API_URL = f"{base_url}/api/packages/"

# AFTER MIGRATION
VULNERABLECODE_ADVISORY_V2_URL = f"{base_url}/api/v2/advisories/"
```

### 2. The fetch function signature and params

```python
# CURRENT — queries by purl, gets package-centric response
def get_vulnerabilities_for_purl(purl, base_url, api_key=None):
    response = session.get(url, params={"purl": purl})
    packages = response.json().get("results", [])
    for package in packages:
        vulns = package.get("affected_by_vulnerabilities", [])  # old nested structure

# AFTER MIGRATION — queries by affected_packages, gets advisory-centric response
def get_advisories_for_purl(purl, base_url, api_key=None):
    response = session.get(url, params={"affected_packages": purl})
    advisories = response.json().get("results", [])
    for advisory in advisories:
        affected = advisory.get("affected_packages", [])  # new nested structure
```

### 3. The data extraction logic

```python
# CURRENT — extracts risk_score as a flat float
vulnerability_data = {
    "vulnerability_id": vuln.get("vulnerability_id"),
    "risk_score": vuln.get("risk_score"),       # flat float
    "summary": vuln.get("summary"),
    "aliases": vuln.get("aliases", []),
}

# AFTER MIGRATION — extracts structured severities
advisory_data = {
    "advisory_id": advisory.get("advisory_id"),
    "vulnerability_id": get_primary_cve(advisory.get("aliases", [])),
    "summary": advisory.get("summary"),
    "aliases": advisory.get("aliases", []),
    "severities": advisory.get("severities", []),   # structured list
    "risk_score": get_max_severity_score(advisory.get("severities", [])),
    "affected_version_range": get_version_range(advisory, purl),
    "fixed_version": get_fixed_version(advisory, purl),
}
```

### 4. The pipeline step in `find_vulnerabilities.py`

The `find_vulnerabilities` pipeline step loops over discovered packages and calls the pipe function. After migration, it will need to handle the inverted structure — one advisory can affect multiple packages, so the loop logic changes from "per package, find vulnerabilities" to "per advisory, annotate all affected packages."

---

## Running the PoC

```bash
# Clone the repo
git clone https://github.com/<your-username>/aboutcode-api-migration-poc
cd aboutcode-api-migration-poc

# Install dependencies
pip install -r requirements.txt

# Run the API fetcher (hits the live public API)
python fetcher.py

# Run the mapper demo (fully offline, no API needed)
python mapper.py

# Run unit tests for mapper behavior and edge cases
python -m unittest discover -s tests -v
```

---

## References

- [PR #1866 — Add advisory v2](https://github.com/aboutcode-org/vulnerablecode/pull/1866) — The PR that introduced the V2Advisory model
- [Issue #1882 — Advisory-first migration tracking](https://github.com/aboutcode-org/vulnerablecode/issues/1882)
- [PR #1966 — Migrate advisory todo to v2](https://github.com/aboutcode-org/vulnerablecode/pull/1966) — Internal VulnerableCode migration reference
- [scanpipe/pipes/vulnerablecode.py](https://github.com/aboutcode-org/scancode.io/blob/main/scanpipe/pipes/vulnerablecode.py) — The main file to be refactored
- [scanpipe/pipelines/find_vulnerabilities.py](https://github.com/aboutcode-org/scancode.io/blob/main/scanpipe/pipelines/find_vulnerabilities.py) — The pipeline to be updated

---

*This PoC was built as part of a GSoC 2026 proposal for the AboutCode organization.*