"""
fetcher.py — VulnerableCode Advisory V2 API Fetcher
=====================================================
PoC for GSoC proposal: "ScanCode.io: migrate to fetching advisories data from vulnerablecode"

This script demonstrates how scancode.io will query the NEW advisory-first API
introduced in vulnerablecode v37.0.0 (PR #1866).

OLD approach (vulnerability-first):
    GET /api/packages?purl=<purl>
    → returns package-centric data where each package embeds its vulnerabilities

NEW approach (advisory-first):
    GET /api/v2/advisories/?affected_packages=<purl>
    → returns advisory-centric data where each advisory lists its affected packages

Reference PRs:
    https://github.com/aboutcode-org/vulnerablecode/pull/1866
    https://github.com/aboutcode-org/vulnerablecode/issues/1882
    https://github.com/aboutcode-org/vulnerablecode/pull/1966
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from typing import Any, Iterable, Optional
import time

import requests


BASE_URL = "https://public.vulnerablecode.io"

# New V2 advisory endpoint (introduced in vulnerablecode v37.0.0)
ADVISORY_V2_ENDPOINT = f"{BASE_URL}/api/v2/advisories/"

# Old V1 package endpoint (current scancode.io still uses this)
PACKAGE_V1_ENDPOINT = f"{BASE_URL}/api/packages/"

# Test PURLs — these are known-vulnerable packages good for demo purposes
TEST_PURLS = [
    "pkg:pypi/django@2.2.0",       # Known vulnerable Django version (multiple CVEs)
    "pkg:npm/lodash@4.17.4",
]

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class VulnerableCodeClient:
    """
    Small wrapper around the public VulnerableCode instance.

    The public instance works without a token (anonymous), but an API token
    gives higher rate limits.
    """

    base_url: str = BASE_URL
    api_token: Optional[str] = None
    timeout_seconds: int = 15
    retry_count: int = 1
    retry_backoff_seconds: float = 1.0

    @property
    def advisory_v2_endpoint(self) -> str:
        return f"{self.base_url}/api/v2/advisories/"

    @property
    def package_v1_endpoint(self) -> str:
        return f"{self.base_url}/api/packages/"

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Token {self.api_token}"
        return headers

    def get_json(self, url: str, *, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        attempts = self.retry_count + 1
        for attempt in range(attempts):
            try:
                response = requests.get(url, params=params, headers=self.headers(), timeout=self.timeout_seconds)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response is not None else None
                if status_code == 429 and attempt < self.retry_count:
                    delay = self.retry_backoff_seconds * (attempt + 1)
                    LOG.warning("Rate limited on %s, retrying in %.1fs", url, delay)
                    time.sleep(delay)
                    continue
                LOG.error("HTTP error requesting %s: %s", url, e)
                break
            except requests.exceptions.ConnectionError:
                LOG.error("Connection error requesting %s", url)
                break
            except requests.exceptions.Timeout:
                LOG.error("Timeout requesting %s", url)
                break
            except ValueError as e:
                LOG.error("Invalid JSON from %s: %s", url, e)
                break
        return {}

    def post_json(self, url: str, *, json_body: dict[str, Any], timeout_seconds: Optional[int] = None) -> dict[str, Any]:
        timeout = timeout_seconds if timeout_seconds is not None else self.timeout_seconds
        attempts = self.retry_count + 1
        for attempt in range(attempts):
            try:
                response = requests.post(url, json=json_body, headers=self.headers(), timeout=timeout)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.HTTPError as e:
                status_code = e.response.status_code if e.response is not None else None
                if status_code == 429 and attempt < self.retry_count:
                    delay = self.retry_backoff_seconds * (attempt + 1)
                    LOG.warning("Rate limited on %s, retrying in %.1fs", url, delay)
                    time.sleep(delay)
                    continue
                LOG.error("HTTP error requesting %s: %s", url, e)
                break
            except requests.exceptions.ConnectionError:
                LOG.error("Connection error requesting %s", url)
                break
            except requests.exceptions.Timeout:
                LOG.error("Timeout requesting %s", url)
                break
            except ValueError as e:
                LOG.error("Invalid JSON from %s: %s", url, e)
                break
        return {}


# NEW V2 Advisory-first API

def fetch_advisories_for_purl(client: VulnerableCodeClient, purl: str) -> dict[str, Any]:
    """
    Fetch advisories from the NEW V2 advisory endpoint.

    In the new model, an Advisory is the primary object. It represents a
    single security advisory (e.g., CVE-2021-33203) and lists all packages
    it affects.

    This is the call that scanpipe/pipes/vulnerablecode.py will need to make
    after the GSoC migration.

    Returns the raw JSON response dict.
    """
    params = {"affected_packages": purl}
    LOG.info("[V2] Fetching advisories for: %s", purl)
    LOG.debug("URL: %s?affected_packages=%s", client.advisory_v2_endpoint, purl)
    data = client.get_json(client.advisory_v2_endpoint, params=params)
    LOG.info("Found %s advisories", data.get("count", 0))
    return data


def fetch_advisories_bulk(client: VulnerableCodeClient, purls: list[str]) -> dict[str, Any]:
    """
    Bulk fetch advisories for a list of PURLs using the V2 bulk endpoint.

    This is the efficient path for when scancode.io processes a whole project
    with many discovered packages — one request instead of N requests.

    The body mirrors the existing bulk_search endpoint pattern but for advisories.
    """
    body = {"affected_packages": purls}
    bulk_url = f"{client.advisory_v2_endpoint}bulk_search/"

    LOG.info("[V2 BULK] Fetching advisories for %s packages", len(purls))
    LOG.debug("Endpoint: %s", bulk_url)
    # Bulk endpoint may not be live yet on public instance.
    return client.post_json(bulk_url, json_body=body, timeout_seconds=30)


# OLD V1 Package-first API (current scancode.io behavior — for comparison)

def fetch_vulnerabilities_old_v1(client: VulnerableCodeClient, purl: str) -> dict[str, Any]:
    """
    Fetch vulnerability data using the OLD V1 package endpoint.

    This is what scanpipe/pipes/vulnerablecode.py currently does.
    The response is package-centric: you query by PURL and get back
    a list of packages each embedding their own vulnerability list.

    This approach is being replaced by the advisory-first V2 model.
    """
    params = {"purl": purl}
    LOG.info("[V1 OLD] Fetching vulnerabilities for: %s", purl)
    LOG.debug("URL: %s?purl=%s", client.package_v1_endpoint, purl)
    data = client.get_json(client.package_v1_endpoint, params=params)
    LOG.info("Found %s packages", data.get("count", 0))
    return data


# Main demo runner

def _purl_key(purl: str) -> str:
    return purl.replace(":", "_").replace("/", "_").replace("@", "_at_")


def run_demo(
    client: VulnerableCodeClient,
    *,
    purls: Iterable[str] = TEST_PURLS,
    save_samples: bool = True,
    output_path: str = "testcase/live_api_comparison.json",
    include_bulk: bool = True,
) -> dict[str, Any]:
    """
    Run the full fetch demo and optionally save raw API responses as JSON
    samples to disk (useful for developing the mapper offline).
    """
    results: dict[str, Any] = {}

    for purl in purls:
        purl_key = _purl_key(purl)

        # --- New V2 advisory endpoint ---
        advisory_data = fetch_advisories_for_purl(client, purl)
        results[f"v2_{purl_key}"] = advisory_data

        if advisory_data.get("results"):
            first = advisory_data["results"][0]
            LOG.info("Sample advisory ID: %s", first.get("advisory_id", "N/A"))
            LOG.info("Aliases: %s", first.get("aliases", []))
            LOG.info("Affected packages: %s", len(first.get("affected_packages", [])))
            LOG.info("Severities: %s", first.get("severities", []))

        # --- Old V1 package endpoint ---
        v1_data = fetch_vulnerabilities_old_v1(client, purl)
        results[f"v1_{purl_key}"] = v1_data

    if include_bulk:
        bulk_data = fetch_advisories_bulk(client, list(purls))
        results["v2_bulk"] = bulk_data

    if save_samples:
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        LOG.info("Saved raw API responses to: %s", output_path)

    return results


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch VulnerableCode advisory-v2 API samples.")
    parser.add_argument("--token", dest="api_token", default=None, help="Optional API token for higher rate limits.")
    parser.add_argument(
        "--no-save",
        dest="save_samples",
        action="store_false",
        help="Do not write sample responses to JSON output file.",
    )
    parser.add_argument(
        "--output",
        dest="output_path",
        default="testcase/live_api_comparison.json",
        help="Where to write sample responses JSON.",
    )
    parser.add_argument(
        "--purl",
        dest="purls",
        action="append",
        default=[],
        help="Fetch for this PURL (repeatable). Uses TEST_PURLS if omitted.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "--no-bulk",
        dest="include_bulk",
        action="store_false",
        help="Skip V2 bulk advisory demo call.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(message)s")
    client = VulnerableCodeClient(api_token=args.api_token)
    run_demo(
        client,
        purls=args.purls or TEST_PURLS,
        save_samples=args.save_samples,
        output_path=args.output_path,
        include_bulk=args.include_bulk,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())