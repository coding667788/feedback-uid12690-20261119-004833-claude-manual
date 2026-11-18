"""输入结构、引用完整性、规模上限与错误码测试。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution import load_case  # noqa: E402
from solution.errors import (  # noqa: E402
    INVALID_INPUT,
    LIMIT_EXCEEDED,
    UNKNOWN_REFERENCE,
    VerifierInputError,
)
from solution.model import split_repo  # noqa: E402
from tests.builders import attestation, digest, make_case, trust  # noqa: E402


def _minimal_ok_case() -> dict:
    decls = [
        attestation("r1", "R", "b1", 100),
        attestation("r2", "R", "b2", 100),
    ]
    return make_case("V", "R", decls, issuers=["b1", "b2"], trusted=[trust("R")])


class InputValidationTests(unittest.TestCase):
    def test_digest_must_be_sha256_hex(self):
        case = _minimal_ok_case()
        case["declarations"][0]["artifact_digest"] = "not-a-digest"
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, INVALID_INPUT)

    def test_boolean_is_not_accepted_as_time(self):
        case = _minimal_ok_case()
        case["declarations"][0]["issued_at"] = True
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, INVALID_INPUT)

    def test_duplicate_dependency_pin_rejected_but_same_digest_allowed(self):
        # 同 digest + 同 dep_summary 的重复锚点拒绝
        decls = [
            attestation("r1", "R", "b1", 100, deps=[("A", "s1"), ("A", "s1")]),
            attestation("a1", "A", "b1", 90),
        ]
        case = make_case("V", "R", decls, issuers=["b1"], trusted=[trust("A")])
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, INVALID_INPUT)

        # 同 digest、不同 dep_summary（不同兄弟依赖）合法
        decls2 = [
            attestation("r2", "R", "b1", 100, deps=[("A", "s1"), ("A", "s2")]),
            attestation("a1", "A", "b1", 90),
        ]
        case2 = make_case("V2", "R", decls2, issuers=["b1"], trusted=[trust("A")])
        loaded = load_case(case2)
        self.assertEqual(loaded.case_id, "V2")

    def test_unknown_builder_reference(self):
        case = _minimal_ok_case()
        case["declarations"][0]["builder"] = "ghost"
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, UNKNOWN_REFERENCE)

    def test_unknown_root_artifact(self):
        case = _minimal_ok_case()
        case["query"]["root_artifact"] = digest("GHOST")
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, UNKNOWN_REFERENCE)

    def test_revocation_trace_must_match_issued_at(self):
        decls = [attestation("r1", "R", "b1", 100)]
        case = make_case("V", "R", decls, issuers=["b1"], trusted=[trust("R")])
        case["revocations"] = [
            {
                "id": "rv1",
                "declaration_id": "r1",
                "occurred_at": 200,
                "sequence": 0,
                "trace_issued_at": 999,
            }
        ]
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, INVALID_INPUT)

    def test_revocation_unknown_declaration(self):
        case = _minimal_ok_case()
        case["revocations"] = [
            {
                "id": "rv1",
                "declaration_id": "nope",
                "occurred_at": 200,
                "sequence": 0,
                "trace_issued_at": 100,
            }
        ]
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, UNKNOWN_REFERENCE)

    def test_repo_segment_split_and_empty_segment(self):
        self.assertEqual(split_repo("ci/project"), ("ci", "project"))
        with self.assertRaises(VerifierInputError) as ctx:
            split_repo("ci//project")
        self.assertEqual(ctx.exception.code, INVALID_INPUT)

    def test_artifact_limit_enforced(self):
        decls = [
            attestation(f"d{i}", chr(ord("A") + i), "b1", 100) for i in range(4)
        ]
        case = make_case(
            "V",
            "A",
            decls,
            issuers=["b1"],
            trusted=[trust(chr(ord("A") + i)) for i in range(4)],
        )
        case["limits"] = {"max_artifacts": 3}
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, LIMIT_EXCEEDED)

    def test_issuer_limit_enforced(self):
        case = _minimal_ok_case()
        case["limits"] = {"max_issuers": 1}
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, LIMIT_EXCEEDED)

    def test_duplicate_trusted_source_rejected(self):
        case = _minimal_ok_case()
        # 同一 (repo, commit) 的可信源码重复登记
        case["trusted_sources"].append(dict(case["trusted_sources"][0]))
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, INVALID_INPUT)

    def test_trusted_source_digest_may_share_artifact_digest_space(self):
        """源码快照摘要与构建产物摘要属于不同身份空间，数值相同不构成冲突。"""
        case = _minimal_ok_case()
        case["trusted_sources"] = [
            {"repo": "ci/R", "commit": "c1", "digest": digest("R")}
        ]
        loaded = load_case(case)
        self.assertEqual(loaded.query.root_artifact, digest("R"))

    def test_duplicate_revocation_sequence_rejected(self):
        decls = [attestation("r1", "R", "b1", 100), attestation("r2", "R", "b2", 100)]
        case = make_case("V", "R", decls, issuers=["b1", "b2"], trusted=[trust("R")])
        case["revocations"] = [
            {
                "id": "rv1",
                "declaration_id": "r1",
                "occurred_at": 200,
                "sequence": 5,
                "trace_issued_at": 100,
            },
            {
                "id": "rv2",
                "declaration_id": "r2",
                "occurred_at": 210,
                "sequence": 5,
                "trace_issued_at": 100,
            },
        ]
        with self.assertRaises(VerifierInputError) as ctx:
            load_case(case)
        self.assertEqual(ctx.exception.code, INVALID_INPUT)


if __name__ == "__main__":
    unittest.main()
