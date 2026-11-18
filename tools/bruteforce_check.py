"""纯暴力交叉验证脚本（非 unittest，开发期核对用，也可手动重放）。

与 tests/oracle.py 的定位不同：这里把“展开为全部根-叶路径集合 + 笛卡尔积
重组”的判定再用另一种写法实现一遍，并对每个场景同时核对：
  1) 被测实现的最优代价/DFS 与暴力结果一致；
  2) 剪枝保留的每条 DFS 都确实是某棵合法证明树；
  3) 选中的两棵树非源码签发者互斥、且不存在更优互斥对。

运行：python -I tools/bruteforce_check.py
"""

from __future__ import annotations

import sys
from itertools import product
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from solution import load_case  # noqa: E402
from solution.verifier import verify_loaded  # noqa: E402
from tests.scenarios import all_scenarios  # noqa: E402


def _visible(case):
    q = case.query
    out = set()
    for rev in case.revocations:
        if rev.occurred_at <= q.audit_cutoff and (
            q.cutoff_sequence is None or rev.sequence <= q.cutoff_sequence
        ):
            out.add(rev.declaration_id)
    return out


def _ok(case, decl, revoked):
    if not decl.signature_valid or decl.id in revoked:
        return False
    if not any(
        a.issuer == decl.builder and a.covers(decl.source.segments, decl.issued_at)
        for a in case.authorizations
    ):
        return False
    if not decl.pins and (decl.source.repo, decl.source.commit) not in case.trusted_sources:
        return False
    return True


def brute_roots(case):
    """返回 (dfs 元组, 代价, 非源码签发者集合) 的全量清单，不去重不剪枝。"""
    revoked = _visible(case)
    producers = {}
    for d in case.declarations:
        producers.setdefault(d.artifact_digest, []).append(d)

    def expand(digest, ancestors):
        if digest in ancestors:
            return []
        out = []
        for decl in producers.get(digest, []):
            if not _ok(case, decl, revoked):
                continue
            if not decl.pins:
                out.append(((decl.id,), 1, frozenset()))
                continue
            pins = sorted(decl.pins, key=lambda p: (p.dep_summary, p.digest))
            options = []
            for pin in pins:
                child = expand(pin.digest, ancestors | {digest})
                if not child:
                    options = []
                    break
                options.append(child)
            if not options:
                continue
            for combo in product(*options):
                dfs = (decl.id,) + tuple(x for c in combo for x in c[0])
                cost = 1 + sum(c[1] for c in combo)
                issuers = frozenset({decl.builder}) | frozenset().union(
                    *(c[2] for c in combo)
                )
                out.append((dfs, cost, issuers))
        return out

    return expand(case.query.root_artifact, frozenset())


def main() -> int:
    failures = 0
    for raw, _expected in all_scenarios():
        case = load_case(raw)
        result = verify_loaded(case)
        all_trees = brute_roots(case)

        if not all_trees:
            assert result["status"] == "fail"
            assert result["error_code"] == "NO_COMPLETE_PROOF"
            print(f"{case.case_id}: 暴力无完备证明，与实现一致")
            continue

        # 暴力侧自己找最优互斥对
        best = None
        for i in range(len(all_trees)):
            for j in range(i + 1, len(all_trees)):
                a, b = all_trees[i], all_trees[j]
                if not a[2].isdisjoint(b[2]):
                    continue
                ordered = sorted((a, b), key=lambda t: t[0])
                key = (a[1] + b[1], ordered[0][0], ordered[1][0])
                if best is None or key < best[0]:
                    best = (key, ordered)

        impl_summaries = result["review"]["root_proof_summaries"]
        brute_dfs = {t[0] for t in all_trees}
        for s in impl_summaries:
            assert tuple(s["canonical_dfs"]) in brute_dfs, "剪枝结果不是合法证明树"

        if best is None:
            assert result["status"] == "fail"
            assert result["error_code"] == "NO_INDEPENDENT_PAIR"
            print(f"{case.case_id}: 暴力确认无独立对，与实现一致")
            continue

        _key, ordered = best
        brute_first, brute_second = ordered
        brute_cost = brute_first[1] + brute_second[1]
        assert result["status"] == "ok", case.case_id
        impl_cost = result["optimization"]["total_declaration_occurrences"]
        impl_dfs = result["optimization"]["canonical_dfs_sequence"]
        expected_dfs = [list(brute_first[0]), list(brute_second[0])]
        if impl_cost != brute_cost or expected_dfs != impl_dfs:
            failures += 1
            print(
                f"  不一致 {case.case_id}: 暴力={brute_cost}/{expected_dfs} "
                f"实现={impl_cost}/{impl_dfs}"
            )
        else:
            print(f"{case.case_id}: 最优一致 (代价 {impl_cost}, DFS {impl_dfs})")

    print("=" * 60)
    print("全部一致" if failures == 0 else f"{failures} 个不一致")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
