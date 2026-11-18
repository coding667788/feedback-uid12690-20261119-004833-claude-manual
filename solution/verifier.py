"""来源核验核心：声明资格、证明树穷举、双独立证明优选。

证明展开树的约定（与 README 一致）：
- 每个声明节点对应一条声明的一次出现，内部节点带依赖子树；没有依赖的叶子
  声明也是声明节点，同样计入声明出现次数、进入规范 DFS 序列。
- 叶子声明之下再挂一个“可信源码叶子”。只有外部预置的可信源码可作叶子，
  可信源码不是声明：不计出现次数、不进入 DFS 序列。
- “非源码签发者”= 非叶子声明（即有依赖的声明）的构建者集合；叶子声明的
  构建者是源码签发者，两个分支共用源码不破坏互斥性。
- 沿任一依赖路径重复出现同一产物即构成循环，该展开无效；不同兄弟分支允许
  重复同一产物（共享子图），同一产物在不同兄弟分支也可选用不同声明。
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Optional

from .errors import (
    NO_COMPLETE_PROOF,
    NO_INDEPENDENT_PAIR,
    SEARCH_CAP_EXCEEDED,
    VerifierInputError,
)
from .model import Case, Declaration, Pin, load_case

#: 穷举过程中构造的证明树节点数安全上限（题目规模下远不会触及）。
SEARCH_CAP = 200_000


@dataclass(frozen=True)
class ProofTree:
    """一棵规范化的证明展开树（frozen，可哈希、可按 DFS 元组字典序比较）。"""

    kind: str  # "node"（非源码声明出现） | "leaf"（可信源码）
    digest: str
    decl_id: Optional[str]
    builder: Optional[str]
    children: tuple["ProofTree", ...]
    leaf_repo: Optional[str]
    leaf_commit: Optional[str]
    cost: int
    non_source_issuers: frozenset[str]
    dfs: tuple[str, ...]


class _Solver:
    def __init__(self, case: Case):
        self.case = case
        self.memo: dict[tuple[str, frozenset[str]], list[ProofTree]] = {}
        self.nodes_built = 0
        self.visible_revocations = self._visible_revocations(case)
        self.revoked_ids = {r.declaration_id for r in self.visible_revocations}
        self.eligibility = {d.id: self._evaluate(d) for d in case.declarations}

    # ---------- 审计截点与声明资格 ----------

    @staticmethod
    def _visible_revocations(case: Case):
        q = case.query
        out = []
        for rev in case.revocations:
            if rev.occurred_at > q.audit_cutoff:
                continue
            if q.cutoff_sequence is not None and rev.sequence > q.cutoff_sequence:
                continue
            out.append(rev)
        return sorted(out, key=lambda r: (r.occurred_at, r.sequence))

    def _evaluate(self, decl: Declaration) -> tuple[bool, list[str]]:
        """与展开上下文无关的四条资格判定；返回（是否合格, 原因列表）。"""
        reasons: list[str] = []
        if not decl.signature_valid:
            reasons.append("模拟验签失败")
        if not self._authorized(decl):
            reasons.append("签发时间/仓库路径未命中左闭右开授权")
        if decl.id in self.revoked_ids:
            reasons.append("已被审计截点内可见的撤销记录撤销")
        if not decl.pins:
            if (decl.source.repo, decl.source.commit) not in self.case.trusted_sources:
                reasons.append("叶子声明的源码不是外部预置可信源码")
        return (not reasons), reasons

    def _authorized(self, decl: Declaration) -> bool:
        for auth in self.case.authorizations:
            if auth.issuer != decl.builder:
                continue
            if auth.covers(decl.source.segments, decl.issued_at):
                return True
        return False

    def _eligible(self, decl: Declaration) -> bool:
        return self.eligibility[decl.id][0]

    # ---------- 证明树穷举 ----------

    def _source_leaf(self, decl: Declaration) -> ProofTree:
        """可信源码叶子：不是声明，不计代价、不进 DFS。"""
        self._tick()
        trusted = self.case.trusted_by_source[(decl.source.repo, decl.source.commit)]
        return ProofTree(
            kind="leaf",
            digest=decl.artifact_digest,
            decl_id=None,
            builder=None,
            children=(),
            leaf_repo=trusted.repo,
            leaf_commit=trusted.commit,
            cost=0,
            non_source_issuers=frozenset(),
            dfs=(),
        )

    def _make_leaf_declaration(self, decl: Declaration) -> ProofTree:
        """叶子声明节点：计 1 次声明出现，但其构建者属于源码签发者。"""
        self._tick()
        source_leaf = self._source_leaf(decl)
        return ProofTree(
            kind="node",
            digest=decl.artifact_digest,
            decl_id=decl.id,
            builder=decl.builder,
            children=(source_leaf,),
            leaf_repo=None,
            leaf_commit=None,
            cost=1,
            non_source_issuers=frozenset(),
            dfs=(decl.id,),
        )

    def _make_node(self, decl: Declaration, ordered_pins: list[Pin], children: list[ProofTree]) -> ProofTree:
        self._tick()
        nsi = frozenset({decl.builder}) | frozenset().union(
            *(c.non_source_issuers for c in children)
        )
        dfs = (decl.id,) + tuple(x for c in children for x in c.dfs)
        return ProofTree(
            kind="node",
            digest=decl.artifact_digest,
            decl_id=decl.id,
            builder=decl.builder,
            children=tuple(children),
            leaf_repo=None,
            leaf_commit=None,
            cost=1 + sum(c.cost for c in children),
            non_source_issuers=nsi,
            dfs=dfs,
        )

    def _tick(self) -> None:
        self.nodes_built += 1
        if self.nodes_built > SEARCH_CAP:
            raise VerifierInputError(
                SEARCH_CAP_EXCEEDED,
                f"证明穷举构造节点数超过安全上限 {SEARCH_CAP}",
            )

    def trees_for(self, digest: str, forbidden: frozenset[str]) -> list[ProofTree]:
        """返回某产物在给定祖先集合下的全部“组内剪枝后”完备证明。

        forbidden 为当前依赖路径上已出现的产物摘要；再次命中即循环，返回空。
        """
        if digest in forbidden:
            return []
        key = (digest, forbidden)
        cached = self.memo.get(key)
        if cached is not None:
            return cached

        trees: list[ProofTree] = []
        for decl in self.case.producers(digest):
            if not self._eligible(decl):
                continue
            if not decl.pins:
                trees.append(self._make_leaf_declaration(decl))
                continue

            ordered_pins = sorted(decl.pins, key=lambda p: (p.dep_summary, p.digest))
            child_forbidden = forbidden | {digest}
            options_per_pin: list[list[ProofTree]] = []
            for pin in ordered_pins:
                options = self.trees_for(pin.digest, child_forbidden)
                if not options:
                    options_per_pin = []
                    break
                options_per_pin.append(options)
            if not options_per_pin:
                continue
            for combo in product(*options_per_pin):
                trees.append(self._make_node(decl, ordered_pins, list(combo)))

        pruned = self._prune(trees)
        self.memo[key] = pruned
        return pruned

    @staticmethod
    def _prune(trees: list[ProofTree]) -> list[ProofTree]:
        """同一 (出现次数, 非源码签发者集合) 只保留 DFS 字典序最小者。

        被剪枝树与保留树代价与签发者集合完全相同、DFS 更靠后，任何上层组合
        替换后都不会更优，也不会改变互斥性，因此剪枝对最终选择无损。
        """
        best: dict[tuple[int, frozenset[str]], ProofTree] = {}
        for tree in trees:
            group = (tree.cost, tree.non_source_issuers)
            incumbent = best.get(group)
            if incumbent is None or tree.dfs < incumbent.dfs:
                best[group] = tree
        out = list(best.values())
        out.sort(key=lambda t: (t.cost, t.dfs))
        return out

    # ---------- 双独立证明选择 ----------

    def solve(self) -> dict:
        root = self.case.query.root_artifact
        root_trees = self.trees_for(root, frozenset())

        review = self._review_counts(root_trees)
        if not root_trees:
            return {
                "status": "fail",
                "error_code": NO_COMPLETE_PROOF,
                "message": "根产物不存在可展开到可信源码的完备证明",
                "review": review,
            }

        best_key: Optional[tuple] = None
        best_pair: Optional[tuple[ProofTree, ProofTree]] = None
        for i, first in enumerate(root_trees):
            for second in root_trees[i + 1 :]:
                if not first.non_source_issuers.isdisjoint(second.non_source_issuers):
                    continue
                ordered = sorted((first, second), key=lambda t: t.dfs)
                pair_key = (
                    first.cost + second.cost,
                    ordered[0].dfs,
                    ordered[1].dfs,
                )
                if best_key is None or pair_key < best_key:
                    best_key = pair_key
                    best_pair = (ordered[0], ordered[1])

        if best_pair is None:
            return {
                "status": "fail",
                "error_code": NO_INDEPENDENT_PAIR,
                "message": "存在完备证明，但任意两份的非源码签发者集合均不互斥",
                "review": review,
            }

        first, second = best_pair
        return {
            "status": "ok",
            "selected": [_tree_to_dict(first), _tree_to_dict(second)],
            "optimization": {
                "total_declaration_occurrences": first.cost + second.cost,
                "first_tree_occurrences": first.cost,
                "second_tree_occurrences": second.cost,
                "canonical_dfs_sequence": [list(first.dfs), list(second.dfs)],
                "pair_ordering": "两棵树按各自规范 DFS 声明 ID 序列字典序归一排序",
            },
            "review": review,
        }

    # ---------- 可复核计数 ----------

    def _review_counts(self, root_trees: list[ProofTree]) -> dict:
        eligible_ids = [d.id for d in self.case.declarations if self._eligible(d)]
        return {
            "limits": dict(self.case.limits),
            "artifact_count": len(self.case.artifact_digests),
            "declaration_count": len(self.case.declarations),
            "issuer_count": len(self.case.issuers),
            "trusted_source_count": len(self.case.trusted_sources),
            "eligible_declaration_count": len(eligible_ids),
            "eligible_declaration_ids": sorted(eligible_ids),
            "revocation_total": len(self.case.revocations),
            "revocation_visible_count": len(self.visible_revocations),
            "visible_revocations": [
                {
                    "id": r.id,
                    "declaration_id": r.declaration_id,
                    "occurred_at": r.occurred_at,
                    "sequence": r.sequence,
                    "trace_issued_at": r.trace_issued_at,
                }
                for r in self.visible_revocations
            ],
            "root_proof_count_after_pruning": len(root_trees),
            "proof_trees_enumerated_nodes": self.nodes_built,
            "root_proof_summaries": [
                {
                    "occurrences": t.cost,
                    "non_source_issuers": sorted(t.non_source_issuers),
                    "canonical_dfs": list(t.dfs),
                }
                for t in root_trees
            ],
            "declaration_eligibility": [
                {
                    "declaration_id": d.id,
                    "eligible": self.eligibility[d.id][0],
                    "reasons": self.eligibility[d.id][1],
                }
                for d in sorted(self.case.declarations, key=lambda d: d.id)
            ],
        }


def _tree_to_dict(tree: ProofTree) -> dict:
    if tree.kind == "leaf":
        return {
            "kind": "leaf",
            "trusted_source": {"repo": tree.leaf_repo, "commit": tree.leaf_commit},
            "artifact_digest": tree.digest,
        }
    return {
        "kind": "node",
        "declaration_id": tree.decl_id,
        "builder": tree.builder,
        "artifact_digest": tree.digest,
        "declaration_occurrences_in_subtree": tree.cost,
        "non_source_issuers_in_subtree": sorted(tree.non_source_issuers),
        "canonical_dfs": list(tree.dfs),
        "children": [_tree_to_dict(c) for c in tree.children],
    }


def verify_loaded(case: Case) -> dict:
    """对已加载用例执行核验，返回带 case_id 的结果字典。"""
    result = _Solver(case).solve()
    return {"case_id": case.case_id, **result}


def verify_case(raw: dict) -> dict:
    """加载并核验单个原始用例字典；结构类错误抛 :class:`VerifierInputError`。"""
    case = load_case(raw)
    return verify_loaded(case)
