"""
mapper.py — V2 Advisory JSON → ScanCode.io Django Model Mapper
===============================================================
PoC for GSoC proposal: "ScanCode.io: migrate to fetching advisories data from vulnerablecode"

This is the most important file in the PoC. It shows exactly how the raw JSON
from the new V2 advisory API translates into the data structures that
scancode.io uses to populate its database.

The key insight of the advisory-first migration:
    OLD: one PURL → many vulnerabilities (package is the center)
    NEW: one advisory_id → many affected packages (advisory is the center)

This means scanpipe/pipes/vulnerablecode.py must be refactored to:
1. Query by PURL, but receive advisory-first responses
2. Invert the structure: for each advisory, find which of our packages are affected
3. Store using the new advisory model fields instead of vulnerability fields

Reference:
    https://github.com/aboutcode-org/vulnerablecode/pull/1866  (V2Advisory model)
    https://github.com/aboutcode-org/vulnerablecode/pull/1966  (Advisory ToDo migration)
"""

from dataclasses import dataclass, field
import logging
from typing import Any, Optional
LOG = logging.getLogger(__name__)




# Mock data structures — mirrors what the new V2 API returns

# This is what a single advisory looks like in the NEW V2 API response.
# Compare this to the OLD structure at the bottom of this file.

SAMPLE_V2_ADVISORY_RESPONSE = {
    "count": 1,
    "results": [
        {
            # PRIMARY IDENTIFIER — This is new. Old API used "vulnerability_id" (VCID)
            # Now the advisory is the primary key, not the vulnerability
            "advisory_id": "VCID-1234-abcd-5678",

            # ALIASES — CVEs, GHSAs, RHSAs, etc. (this still exists but is now secondary)
            "aliases": ["CVE-2021-33203", "GHSA-rxjp-mfm9-4pdh"],

            "summary": "Django path traversal vulnerability in AdminPasswordChangeForm",

            "url": "https://www.djangoproject.com/weblog/2021/jun/02/security-releases/",

            # DATE PUBLISHED — when the advisory was first published
            "date_published": "2021-06-02T00:00:00Z",

            # AFFECTED PACKAGES — NEW STRUCTURE. This is where it differs from old API.
            # Old API: each package object embeds its own vulnerabilities list.
            # New API: each advisory object embeds its list of affected packages.
            "affected_packages": [
                {
                    "purl": "pkg:pypi/django@2.2.0",
                    "affected_version_range": "vers:pypi/>=2.2.0,<2.2.24",
                    "fixed_version": "2.2.24",
                },
                {
                    "purl": "pkg:pypi/django@3.1.0",
                    "affected_version_range": "vers:pypi/>=3.1.0,<3.1.12",
                    "fixed_version": "3.1.12",
                },
            ],

            "severities": [
                {
                    "system": "cvssv3",
                    "value": "4.9",
                    "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
                }
            ],

            "references": [
                {
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33203",
                    "reference_type": "advisory",
                    "reference_id": "CVE-2021-33203",
                }
            ],
        }
    ],
}

# OLD V1 structure (current scancode.io parses this — shown for comparison)

SAMPLE_V1_PACKAGE_RESPONSE = {
    "count": 1,
    "results": [
        {
            "purl": "pkg:pypi/django@2.2.0",

            "affected_by_vulnerabilities": [
                {
                    "vulnerability_id": "VCID-1234-abcd-5678",
                    "summary": "Django path traversal vulnerability",
                    "risk_score": 4.9,
                    "references": [],
                    "aliases": ["CVE-2021-33203"],
                }
            ],
        }
    ],
}


# Data classes — mirrors the target Django model fields in scancode.io
# These represent what gets stored in the DiscoveredPackage.affected_by_vulnerabilities

@dataclass
class MappedSeverity:
    """Maps to the severity structure stored in DiscoveredPackage."""
    system: str
    value: str
    scoring_elements: Optional[str] = None


@dataclass
class MappedAffectedPackage:
    """Represents a single affected package extracted from a V2 advisory."""
    purl: str
    affected_version_range: Optional[str] = None
    fixed_version: Optional[str] = None


@dataclass
class MappedAdvisory:
    """
    The central output of the mapper.
    This is what scancode.io's find_vulnerabilities pipeline will build
    from each V2 advisory and then use to annotate DiscoveredPackage records.

    In the current (old) code, scanpipe/pipes/vulnerablecode.py builds
    a 'vulnerability_data' dict for each package. After migration, it will
    build a MappedAdvisory for each advisory, then fan out to packages.
    """
    # Primary identifier (advisory-first model)
    advisory_id: str

    summary: str
    url: Optional[str] = None
    date_published: Optional[str] = None

    aliases: list[str] = field(default_factory=list)

    affected_packages: list[MappedAffectedPackage] = field(default_factory=list)

    severities: list[MappedSeverity] = field(default_factory=list)

    references: list[dict[str, str]] = field(default_factory=list)

    primary_cve: Optional[str] = None

    max_severity_score: Optional[float] = None


# Core mapper function — this is what replaces the old parse logic

def map_v2_advisory_to_scancode(advisory_json: dict[str, Any]) -> MappedAdvisory:
    """
    Take a single advisory object from the V2 API response and convert it
    into a MappedAdvisory that scancode.io's pipeline can use.

    This function is the direct replacement for the parsing logic in:
        scanpipe/pipes/vulnerablecode.py → get_vulnerability_data() (current name TBD)

    Args:
        advisory_json: A single advisory dict from the V2 API "results" list.

    Returns:
        MappedAdvisory instance ready to be stored / used for package annotation.
    """
    advisory_id = advisory_json.get("advisory_id", "")
    if not advisory_id:
        LOG.warning("Advisory missing advisory_id: %s", advisory_json)

    aliases = advisory_json.get("aliases", [])
    if not isinstance(aliases, list):
        LOG.warning("Unexpected aliases type (%s), coercing to empty list", type(aliases).__name__)
        aliases = []

    summary = advisory_json.get("summary", "")
    url = advisory_json.get("url")
    date_published = advisory_json.get("date_published")

    affected_packages: list[MappedAffectedPackage] = []
    for pkg in advisory_json.get("affected_packages", []):
        affected_packages.append(
            MappedAffectedPackage(
                purl=pkg.get("purl", ""),
                affected_version_range=pkg.get("affected_version_range"),
                fixed_version=pkg.get("fixed_version"),
            )
        )

    severities: list[MappedSeverity] = []
    max_score: Optional[float] = None
    for sev in advisory_json.get("severities", []):
        mapped_sev = MappedSeverity(
            system=sev.get("system", ""),
            value=sev.get("value", ""),
            scoring_elements=sev.get("scoring_elements"),
        )
        severities.append(mapped_sev)

        try:
            score = float(sev.get("value", 0))
            if max_score is None or score > max_score:
                max_score = score
        except (ValueError, TypeError) as e:
            LOG.debug("Skipping non-numeric severity value=%r (%s)", sev.get("value"), e)


    primary_cve = None
    for alias in aliases:
        if alias.startswith("CVE-"):
            primary_cve = alias
            break
    if not primary_cve:
        for alias in aliases:
            if alias.startswith("GHSA-"):
                primary_cve = alias
                break

    references: list[dict[str, str]] = []
    for ref in advisory_json.get("references", []):
        references.append({
            "url": ref.get("url", ""),
            "reference_type": ref.get("reference_type", ""),
            "reference_id": ref.get("reference_id", ""),
        })

    return MappedAdvisory(
        advisory_id=advisory_id,
        summary=summary,
        url=url,
        date_published=date_published,
        aliases=aliases,
        affected_packages=affected_packages,
        severities=severities,
        references=references,
        primary_cve=primary_cve,
        max_severity_score=max_score,
    )


def map_v2_response_to_package_annotations(
    api_response: dict[str, Any],
    project_purls: list[str],
) -> dict[str, list[MappedAdvisory]]:
    """
    The top-level function that mirrors what the refactored find_vulnerabilities
    pipeline step will do in scancode.io.

    Takes the full V2 advisory API response and a list of PURLs that exist in
    the current scancode.io project, then returns a dict mapping each
    project PURL to a list of MappedAdvisory objects that affect it.

    This is the "advisory-first inversion":
        V2 gives us: advisory → [affected_purls]
        We need:     purl     → [advisories_affecting_it]

    Args:
        api_response:  The full JSON response from the V2 advisory API.
        project_purls: List of PURLs discovered in the scancode.io project.

    Returns:
        Dict of { purl: [MappedAdvisory, ...] }
    """
    purl_to_advisories: dict[str, list[MappedAdvisory]] = {purl: [] for purl in project_purls}

    for advisory_json in api_response.get("results", []):
        mapped = map_v2_advisory_to_scancode(advisory_json)

        for affected_pkg in mapped.affected_packages:
            if affected_pkg.purl in purl_to_advisories:
                purl_to_advisories[affected_pkg.purl].append(mapped)

    return purl_to_advisories


def advisory_to_db_dict(advisory: MappedAdvisory, purl: str) -> dict[str, Any]:
    """
    Convert a MappedAdvisory into the dict format that scancode.io
    stores in DiscoveredPackage.affected_by_vulnerabilities (a JSON field).

    This is the final step before writing to the database.
    The keys here must match the serializer fields in:
        scanpipe/api/serializers.py → DiscoveredPackageSerializer
    """
    # Find the specific affected_package entry for this purl
    affected = next(
        (p for p in advisory.affected_packages if p.purl == purl),
        None
    )

    return {
        "advisory_id": advisory.advisory_id,

        "vulnerability_id": advisory.primary_cve or advisory.advisory_id,

        "summary": advisory.summary,
        "url": advisory.url,
        "date_published": advisory.date_published,

        "aliases": advisory.aliases,

        "severities": [
            {
                "system": s.system,
                "value": s.value,
                "scoring_elements": s.scoring_elements,
            }
            for s in advisory.severities
        ],

        "risk_score": advisory.max_severity_score,

        "affected_version_range": affected.affected_version_range if affected else None,
        "fixed_version": affected.fixed_version if affected else None,

        "references": advisory.references,
    }


# Demo / self-test using the sample data defined above

def run_mapper_demo():
    """
    Run the mapper against the sample V2 response defined at the top.
    This works fully offline — no API call needed.
    """
    print("=" * 60)
    print("MAPPER DEMO — V2 Advisory → ScanCode.io DB Dict")
    print("=" * 60)

    project_purls = ["pkg:pypi/django@2.2.0", "pkg:pypi/requests@2.25.0"]

    print(f"\nProject PURLs: {project_purls}")
    print(f"Advisories in response: {SAMPLE_V2_ADVISORY_RESPONSE['count']}")

    # Run the top-level mapper
    annotations = map_v2_response_to_package_annotations(
        api_response=SAMPLE_V2_ADVISORY_RESPONSE,
        project_purls=project_purls,
    )

    print("\n--- MAPPING RESULT ---")
    for purl, advisories in annotations.items():
        print(f"\nPURL: {purl}")
        print(f"  Advisories affecting this package: {len(advisories)}")
        for adv in advisories:
            print(f"\n  Advisory ID    : {adv.advisory_id}")
            print(f"  Primary CVE    : {adv.primary_cve}")
            print(f"  Aliases        : {adv.aliases}")
            print(f"  Max Severity   : {adv.max_severity_score}")
            print(f"  Summary        : {adv.summary[:80]}...")

            db_dict = advisory_to_db_dict(adv, purl)
            print(f"\n  DB dict (what gets stored in affected_by_vulnerabilities):")
            for k, v in db_dict.items():
                print(f"    {k:<30}: {v}")

    print("\n--- OLD V1 structure (what we're migrating FROM) ---")
    old_pkg = SAMPLE_V1_PACKAGE_RESPONSE["results"][0]
    old_vuln = old_pkg["affected_by_vulnerabilities"][0]
    print(f"  Old vulnerability_id : {old_vuln['vulnerability_id']}")
    print(f"  Old risk_score       : {old_vuln['risk_score']}")
    print(f"  Old structure        : package embeds vulnerabilities")
    print(f"  New structure        : advisory embeds affected packages (inverted)")

    print("\n[OK] Mapper demo complete.")


if __name__ == "__main__":
    run_mapper_demo()