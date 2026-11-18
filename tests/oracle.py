"""独立穷举判定器（test oracle）。

本模块刻意不 import solution.*：资格规则、证明穷举、最优对选择全部按题目规范
重新实现一遍，作为独立判定。只在小规模用例上运行（节点数有硬上限），用于核对
被测实现在小图上的最优结果；测试期望值来自这里的独立计算或场景中的人工断言，
绝不从 solution.verifier 反推。
"""

from __future__ import annotations

from itertools import product

ORACLE_NODE_CAP = 100_000


class OracleError(RuntimeError):
    pass


def _repo_segments(repo: str) -> tuple[str, ...]:
    return tuple(repo.split("/"))


def _eligible(decl: dict, case: dict, revoked_ids: set[str]) -> tuple[bool, list[str]]:
    """oracle 自己的四条资格判定（与实现各自独立书写）。"""
    reasons = []
    if not decl.get("signature_valid", True):
        reasons.append("sig")
    seg = _repo_segments(decl["source"]["repo"])
    hit = False
    for auth in case["authorizations"]:
        if auth["issuer"] != decl["builder"]:
            continue
        a_seg = _repo_segments(auth["repo"])
        time_ok = auth["not_before"] <= decl["issued_at"] < auth["not_after"]
        path_ok = len(seg) >= len(a_seg) and seg[: len(a_seg)] == a_seg
        if time_ok and path_ok:
            hit = True
            break
    if not hit:
        reasons.append("auth")
    if decl["id"] in revoked_ids:
        reasons.append("revoked")
    if not decl["dependencies"]:
        pair = (decl["source"]["repo"], decl["source"]["commit"])
        trusted_pairs = {(t["repo"], t["commit"]) for t in case["trusted_sources"]}
        if pair not in trusted_pairs:
            reasons.append("untrusted-leaf")
    return (not reasons), reasons


def _visible_revocations(case: dict) -> list[dict]:
    q = case["query"]
    out = []
    for rev in case["revocations"]:
        if rev["occurred_at"] > q["audit_cutoff"]:
            continue
        if q.get("cutoff_sequence") is not None and rev["sequence"] > q["cutoff_sequence"]:
            continue
        out.append(rev)
    return out


class _Node:
    """oracle 自有树结构。

    声明节点（含叶子声明）：计 1 次出现、进入 DFS；非源码签发者集合只收集
    “有依赖的非叶子声明”的构建者，叶子声明的构建者视为源码签发者而排除。
    可信源码叶子仅用于闭合判定，本身不是声明。
    """

    __slots__ = ("is_leaf", "decl", "children", "cost", "issuers", "dfs")

    def __init__(self, is_leaf, decl, children):
        self.is_leaf = is_leaf
        self.decl = decl
        self.children = children
        if is_leaf:
            self.cost = 0
            self.issuers = frozenset()
            self.dfs = ()
        else:
            self.cost = 1 + sum(c.cost for c in children)
            if decl["dependencies"]:
                merged = {decl["builder"]}
            else:
                merged = set()  # 叶子声明：源码签发者，不参与互斥
            for c in children:
                merged |= c.issuers
            self.issuers = frozenset(merged)
            seq = [decl["id"]]
            for c in children:
                seq.extend(c.dfs)
            self.dfs = tuple(seq)


def enumerate_proofs(case: dict):
    """全量穷举（不做组内剪枝），返回根产物全部完备证明树。"""
    revs = _visible_revocations(case)
    revoked_ids = {r["declaration_id"] for r in revs}
    eligible = {}
    for decl in case["declarations"]:
        ok, _ = _eligible(decl, case, revoked_ids)
        eligible[decl["id"]] = ok

    producers: dict[str, list[dict]] = {}
    for decl in case["declarations"]:
        producers.setdefault(decl["artifact_digest"], []).append(decl)
    for rows in producers.values():
        rows.sort(key=lambda d: d["id"])

    counter = {"n": 0}

    def expand(digest: str, ancestors: frozenset[str]) -> list[_Node]:
        if digest in ancestors:  # 同一路径重复产物 = 循环，无效
            return []
        result: list[_Node] = []
        for decl in producers.get(digest, []):
            if not eligible[decl["id"]]:
                continue
            if not decl["dependencies"]:
                # 叶子声明节点（计 1 次、进 DFS），其下再挂可信源码叶子
                counter["n"] += 1
                if counter["n"] > ORACLE_NODE_CAP:
                    raise OracleError("oracle 穷举超上限")
                source_leaf = _Node(True, None, [])
                result.append(_Node(False, decl, [source_leaf]))
                continue
            pins = sorted(
                decl["dependencies"],
                key=lambda p: (p["dep_summary"], p["digest"]),
            )
            options = []
            for pin in pins:
                child_trees = expand(pin["digest"], ancestors | {digest})
                if not child_trees:
                    options = []
                    break
                options.append(child_trees)
            if not options:
                continue
            for combo in product(*options):
                counter["n"] += 1
                if counter["n"] > ORACLE_NODE_CAP:
                    raise OracleError("oracle 穷举超上限")
                result.append(_Node(False, decl, list(combo)))
        return result

    root = case["query"]["root_artifact"]
    return expand(root, frozenset()), counter["n"], revs


def best_pair(case: dict) -> dict:
    """独立给出规范结论：状态、最优代价、规范 DFS 对与全部根证明清单。"""
    trees, nodes, revs = enumerate_proofs(case)
    if not trees:
        return {
            "status": "fail",
            "error_code": "NO_COMPLETE_PROOF",
            "node_count": nodes,
            "all_root_proofs": [],
            "visible_revocations": revs,
        }

    winner = None
    for i in range(len(trees)):
        for j in range(i + 1, len(trees)):
            a, b = trees[i], trees[j]
            if not a.issuers.isdisjoint(b.issuers):
                continue
            ordered = sorted((a, b), key=lambda t: t.dfs)
            key = (a.cost + b.cost, ordered[0].dfs, ordered[1].dfs)
            if winner is None or key < winner[0]:
                winner = (key, ordered)

    summaries = sorted(
        ((t.cost, t.dfs, frozenset(t.issuers)) for t in trees),
        key=lambda x: (x[0], x[1]),
    )
    if winner is None:
        return {
            "status": "fail",
            "error_code": "NO_INDEPENDENT_PAIR",
            "node_count": nodes,
            "all_root_proofs": summaries,
            "visible_revocations": revs,
        }
    (_, (first, second)) = winner
    return {
        "status": "ok",
        "node_count": nodes,
        "total_occurrences": first.cost + second.cost,
        "tree_costs": [first.cost, second.cost],
        "tree_dfs": [list(first.dfs), list(second.dfs)],
        "tree_issuers": [set(first.issuers), set(second.issuers)],
        "all_root_proofs": summaries,
        "visible_revocations": revs,
    }
