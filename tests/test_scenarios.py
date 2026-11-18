"""规范场景测试：人工期望值断言 + 独立穷举 oracle 交叉核对。

断言分两层：
1. scenarios.py 中人工推导的期望值（状态、代价、DFS 序列、签发者集合）；
2. tests.oracle 独立穷举给出的结论，必须与被测实现逐项一致。
任何一层都不读取被测实现的输出作为期望值。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# 路径自举：discover -s tests 时项目根不在 sys.path，必须先于 solution 导入
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from solution import verify_case  # noqa: E402
from solution.errors import NO_COMPLETE_PROOF, NO_INDEPENDENT_PAIR  # noqa: E402
from tests import oracle, scenarios  # noqa: E402


def _dfs_trees(result: dict) -> list[list[str]]:
    return result["optimization"]["canonical_dfs_sequence"]


def _issuer_sets(result: dict) -> list[set[str]]:
    return [set(t["non_source_issuers_in_subtree"]) for t in result["selected"]]


def _tree_costs(result: dict) -> list[int]:
    return [t["declaration_occurrences_in_subtree"] for t in result["selected"]]


class ScenarioExpectationTests(unittest.TestCase):
    """对每个手工场景核对人工期望值，并与独立 oracle 对比。"""

    def _assert_oracle_agrees(self, case: dict, result: dict) -> None:
        verdict = oracle.best_pair(case)
        self.assertEqual(verdict["status"], result["status"])
        if result["status"] == "ok":
            self.assertEqual(
                verdict["total_occurrences"],
                result["optimization"]["total_declaration_occurrences"],
            )
            self.assertEqual(verdict["tree_dfs"], _dfs_trees(result))
            self.assertEqual(verdict["tree_costs"], _tree_costs(result))
            self.assertEqual(verdict["tree_issuers"], _issuer_sets(result))
        else:
            self.assertEqual(verdict["error_code"], result["error_code"])

    def test_a_local_shortest_dead_end(self):
        case, expected = scenarios.case_a_local_shortest_dead_end()
        result = verify_case(case)
        self.assertEqual(result["status"], expected["status"])
        self.assertEqual(
            result["optimization"]["total_declaration_occurrences"],
            expected["total_occurrences"],
        )
        self.assertEqual(_dfs_trees(result), expected["tree_dfs"])
        self.assertEqual(_tree_costs(result), expected["tree_costs"])
        self.assertEqual(_issuer_sets(result), expected["tree_issuers"])
        # 互斥性是硬约束，额外独立复核
        first, second = _issuer_sets(result)
        self.assertTrue(first.isdisjoint(second))
        self._assert_oracle_agrees(case, result)

    def test_a2_two_layer_forces_longer_choice(self):
        """题目点名场景：局部最短组合无解，改选更长路径后成功。"""
        case, expected = scenarios.case_a2_local_shortest_dead_end_two_layer()
        result = verify_case(case)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            result["optimization"]["total_declaration_occurrences"], 7
        )
        self.assertEqual(_tree_costs(result), [3, 4])
        self.assertEqual(_dfs_trees(result), expected["tree_dfs"])
        self.assertEqual(_issuer_sets(result), [
            expected["first_tree_issuers"],
            expected["second_tree_issuers"],
        ])
        # 代价 3 的短根树两两之间永远构不成互斥对（强制共享非叶子依赖 bk）
        review = result["review"]
        cheap = [
            s for s in review["root_proof_summaries"] if s["occurrences"] == 3
        ]
        self.assertTrue(cheap, "应当存在代价 3 的局部最短根树")
        for s in cheap:
            self.assertIn("bk", s["non_source_issuers"])
        for idx, s in enumerate(cheap):
            for t in cheap[idx + 1 :]:
                self.assertFalse(
                    set(s["non_source_issuers"]).isdisjoint(
                        set(t["non_source_issuers"])
                    )
                )
        self._assert_oracle_agrees(case, result)

    def test_b_bypass_breaks_cycle(self):
        """题目点名场景：旁路声明打破 R->A->B->A 循环。"""
        case, expected = scenarios.case_b_bypass_breaks_cycle()
        result = verify_case(case)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(_dfs_trees(result), expected["tree_dfs"])
        self.assertEqual(_issuer_sets(result), expected["tree_issuers"])
        # 输出树中沿任何根-叶路径都不得重复同一产物摘要
        for tree in result["selected"]:
            self._assert_no_path_repeat(tree)
        self._assert_oracle_agrees(case, result)

    def test_b2_pure_cycle_has_no_complete_proof(self):
        case, expected = scenarios.case_b2_pure_cycle_no_complete_proof()
        result = verify_case(case)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error_code"], NO_COMPLETE_PROOF)
        self.assertEqual(result["error_code"], expected["error_code"])
        self._assert_oracle_agrees(case, result)

    def test_c1_early_cutoff_revocation_invisible(self):
        case, expected = scenarios.case_c_early_cutoff()
        result = verify_case(case)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(_dfs_trees(result), expected["tree_dfs"])
        self.assertEqual(
            [r["id"] for r in result["review"]["visible_revocations"]],
            expected["visible_revocation_ids"],
        )
        self._assert_oracle_agrees(case, result)

    def test_c2_late_cutoff_pair_destroyed(self):
        """题目点名场景：撤销追溯改变历史截点查询，配对被破坏。"""
        case, expected = scenarios.case_c_late_cutoff_pair_destroyed()
        result = verify_case(case)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error_code"], NO_INDEPENDENT_PAIR)
        visible = {r["id"] for r in result["review"]["visible_revocations"]}
        self.assertEqual(visible, set(expected["visible_revocation_ids"]))
        self._assert_oracle_agrees(case, result)

    def test_c3_sequence_cutoff_filters_second_revocation(self):
        case, expected = scenarios.case_c_sequence_cutoff()
        result = verify_case(case)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(_dfs_trees(result), expected["tree_dfs"])
        self.assertEqual(
            [r["id"] for r in result["review"]["visible_revocations"]],
            expected["visible_revocation_ids"],
        )
        self._assert_oracle_agrees(case, result)

    def test_d_shared_dependency_does_not_fake_independence(self):
        """题目点名场景：共享依赖 b3 是真实共享，不能伪造互斥独立性。"""
        case, expected = scenarios.case_d_shared_dependency()
        result = verify_case(case)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error_code"], NO_INDEPENDENT_PAIR)
        # 单棵树代价 5：r/x/y 三个非叶子声明 + 两个叶子声明，可信源码不计
        summary = result["review"]["root_proof_summaries"]
        self.assertEqual(
            {s["occurrences"] for s in summary},
            {expected["single_tree_occurrences"]},
        )
        for s in summary:
            self.assertIn("b3", s["non_source_issuers"])
        self._assert_oracle_agrees(case, result)

    def test_d2_shared_trusted_source_is_allowed(self):
        case, expected = scenarios.case_d2_shared_source_allowed()
        result = verify_case(case)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(_dfs_trees(result), expected["tree_dfs"])
        self._assert_oracle_agrees(case, result)

    def test_e_small_set_but_longer_proof(self):
        """题目点名场景：对签发者集合较小却较长的备选证明正确判断。"""
        case, expected = scenarios.case_e_small_set_longer_proof()
        result = verify_case(case)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            result["optimization"]["total_declaration_occurrences"],
            expected["total_occurrences"],
        )
        self.assertEqual(_tree_costs(result), expected["tree_costs"])
        self.assertEqual(_dfs_trees(result), expected["tree_dfs"])
        self.assertEqual(_issuer_sets(result), expected["tree_issuers"])
        # 长链（集合小 {b1}）与短链（集合大 {b2,b3}）是唯一互斥组合；
        # 所有根树代价相同，选择由 DFS 字典序而非集合大小决定
        review = result["review"]
        costs = {s["occurrences"] for s in review["root_proof_summaries"]}
        self.assertEqual(costs, {4})
        chosen_sets = _issuer_sets(result)
        self.assertTrue(chosen_sets[0].isdisjoint(chosen_sets[1]))
        self._assert_oracle_agrees(case, result)

    def test_f_authorization_left_closed_right_open(self):
        case, expected = scenarios.case_f_authorization_boundaries()
        result = verify_case(case)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error_code"], NO_INDEPENDENT_PAIR)
        eligible = [
            row["declaration_id"]
            for row in result["review"]["declaration_eligibility"]
            if row["eligible"]
        ]
        self.assertEqual(eligible, expected["eligible_ids"])
        reasons = {
            row["declaration_id"]: row["reasons"]
            for row in result["review"]["declaration_eligibility"]
        }
        self.assertTrue(any("授权" in x for x in reasons["r2"]))
        self.assertTrue(any("授权" in x for x in reasons["r3"]))
        self._assert_oracle_agrees(case, result)

    def test_g_bad_signature(self):
        case, expected = scenarios.case_g_bad_signature()
        result = verify_case(case)
        self.assertEqual(result["error_code"], expected["error_code"])
        self._assert_oracle_agrees(case, result)

    def test_h_untrusted_leaf_rejected(self):
        case, expected = scenarios.case_h_untrusted_leaf_rejected()
        result = verify_case(case)
        self.assertEqual(result["error_code"], expected["error_code"])
        self._assert_oracle_agrees(case, result)

    def test_i_sibling_diversity_single_tree(self):
        case, expected = scenarios.case_i_sibling_choice_diversity()
        result = verify_case(case)
        self.assertEqual(result["error_code"], expected["error_code"])
        self.assertEqual(
            result["review"]["root_proof_count_after_pruning"],
            expected["root_proof_count"],
        )
        self.assertEqual(
            result["review"]["root_proof_summaries"][0]["canonical_dfs"],
            expected["single_tree_dfs"],
        )
        self._assert_oracle_agrees(case, result)

    def test_j_sibling_same_artifact_different_declarations(self):
        """同一产物在不同兄弟分支可选用不同声明（穷举四种组合，剪枝合一）。"""
        case, expected = scenarios.case_j_sibling_same_artifact_different_declarations()
        result = verify_case(case)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["error_code"], expected["error_code"])
        self.assertEqual(
            result["review"]["root_proof_count_after_pruning"],
            expected["pruned_root_proof_count"],
        )
        # 独立 oracle 不剪枝，必须能看到全部四棵兄弟组合树
        # oracle 摘要元组顺序为 (cost, dfs, issuers)
        verdict = oracle.best_pair(case)
        brute_dfs = sorted([list(t[1]) for t in verdict["all_root_proofs"]])
        self.assertEqual(brute_dfs, expected["all_dfs_before_pruning"])
        # 被测实现剪枝后保留的 DFS 必须是四者之一且字典序最小
        kept = result["review"]["root_proof_summaries"][0]["canonical_dfs"]
        self.assertEqual(kept, min(expected["all_dfs_before_pruning"]))

    def _assert_no_path_repeat(self, tree: dict, seen: frozenset | None = None) -> None:
        """递归确认每条根-叶路径上声明节点的产物摘要不重复（循环防护输出侧复核）。

        可信源码叶子复用了叶子声明的产物摘要，但它不是声明出现，跳过检查。
        """
        seen = frozenset() if seen is None else seen
        if tree["kind"] == "leaf":
            return
        digest = tree["artifact_digest"]
        self.assertNotIn(digest, seen)
        for child in tree["children"]:
            self._assert_no_path_repeat(child, seen | {digest})


if __name__ == "__main__":
    unittest.main()
