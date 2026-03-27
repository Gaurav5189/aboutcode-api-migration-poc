import copy
import unittest

from mapper import (
    SAMPLE_V2_ADVISORY_RESPONSE,
    advisory_to_db_dict,
    map_v2_advisory_to_scancode,
    map_v2_response_to_package_annotations,
)


class MapperTests(unittest.TestCase):
    def test_map_v2_advisory_with_valid_data(self) -> None:
        advisory_json = SAMPLE_V2_ADVISORY_RESPONSE["results"][0]
        mapped = map_v2_advisory_to_scancode(advisory_json)

        self.assertEqual(mapped.advisory_id, "VCID-1234-abcd-5678")
        self.assertEqual(mapped.primary_cve, "CVE-2021-33203")
        self.assertEqual(mapped.max_severity_score, 4.9)
        self.assertEqual(len(mapped.affected_packages), 2)

    def test_map_v2_advisory_with_missing_fields(self) -> None:
        mapped = map_v2_advisory_to_scancode({})

        self.assertEqual(mapped.advisory_id, "")
        self.assertEqual(mapped.summary, "")
        self.assertEqual(mapped.aliases, [])
        self.assertEqual(mapped.affected_packages, [])
        self.assertIsNone(mapped.max_severity_score)

    def test_inversion_logic(self) -> None:
        project_purls = ["pkg:pypi/django@2.2.0", "pkg:pypi/requests@2.25.0"]
        annotations = map_v2_response_to_package_annotations(
            api_response=SAMPLE_V2_ADVISORY_RESPONSE,
            project_purls=project_purls,
        )

        self.assertEqual(len(annotations["pkg:pypi/django@2.2.0"]), 1)
        self.assertEqual(len(annotations["pkg:pypi/requests@2.25.0"]), 0)

    def test_non_numeric_severity_is_ignored_for_max_score(self) -> None:
        advisory_json = copy.deepcopy(SAMPLE_V2_ADVISORY_RESPONSE["results"][0])
        advisory_json["severities"].append({"system": "custom", "value": "HIGH"})
        mapped = map_v2_advisory_to_scancode(advisory_json)

        self.assertEqual(mapped.max_severity_score, 4.9)

    def test_advisory_to_db_dict_package_specific_fields(self) -> None:
        advisory_json = SAMPLE_V2_ADVISORY_RESPONSE["results"][0]
        mapped = map_v2_advisory_to_scancode(advisory_json)
        db_dict = advisory_to_db_dict(mapped, "pkg:pypi/django@2.2.0")

        self.assertEqual(db_dict["vulnerability_id"], "CVE-2021-33203")
        self.assertEqual(db_dict["fixed_version"], "2.2.24")
        self.assertEqual(db_dict["risk_score"], 4.9)


if __name__ == "__main__":
    unittest.main()
