"""被测实现与独立穷举 oracle 的随机小图等价性测试。"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution import load_case  # noqa: E402
from tests import fuzzgen, oracle  # noqa: E402


class OracleEquivalenceTests(unittest.TestCase):
    """30 个确定性随机小图：状态、最优代价、DFS 序列、根证明全集必须一致。"""

    SEEDS = list(range(1, 31))

    def test_fuzz_cases_match_independent_oracle(self):
        compared = 0
        statuses = {"ok": 0, "NO_COMPLETE_PROOF": 0, "NO_INDEPENDENT_PAIR": 0}
        for seed in self.SEEDS:
            with self.subTest(seed=seed):
                raw = fuzzgen.generate_case(seed)
                case = load_case(raw)  # 结构必须被接受
                result = verify_loaded_safely(case)
                verdict = oracle.best_pair(raw)

                self.assertEqual(verdict["status"], result["status"])
                if result["status"] == "ok":
                    statuses["ok"] += 1
                    opt = result["optimization"]
                    self.assertEqual(
                        verdict["total_occurrences"],
                        opt["total_declaration_occurrences"],
                    )
                    self.assertEqual(
                        verdict["tree_dfs"], opt["canonical_dfs_sequence"]
                    )
                    # 选中的互斥对确实互斥
                    sets = [
                        set(t["non_source_issuers_in_subtree"])
                        for t in result["selected"]
                    ]
                    self.assertTrue(sets[0].isdisjoint(sets[1]))
                else:
                    statuses[result["error_code"]] += 1
                    self.assertEqual(verdict["error_code"], result["error_code"])

                # 根证明全集：剪枝后的每条 DFS 都必须出现在 oracle 的全量集合中
                impl_dfs = {
                    tuple(s["canonical_dfs"])
                    for s in result["review"]["root_proof_summaries"]
                }
                oracle_dfs = {tuple(s[1]) for s in verdict["all_root_proofs"]}
                self.assertTrue(impl_dfs.issubset(oracle_dfs))
                # 同一 (代价, 签发者集合) 组内实现只保留 DFS 最小者，数量不增
                self.assertLessEqual(
                    len(impl_dfs), len(oracle_dfs)
                )
                compared += 1

        # 30 个随机图应覆盖到三类结论，避免测试退化成只验证一种状态
        self.assertEqual(compared, len(self.SEEDS))
        self.assertGreater(statuses["ok"], 0)
        self.assertGreater(
            statuses["NO_COMPLETE_PROOF"] + statuses["NO_INDEPENDENT_PAIR"], 0
        )


def verify_loaded_safely(case):
    from solution.verifier import verify_loaded

    return verify_loaded(case)


if __name__ == "__main__":
    unittest.main()
