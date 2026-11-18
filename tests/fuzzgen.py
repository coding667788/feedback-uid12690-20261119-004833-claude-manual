"""确定性随机小图生成器（仅供测试，使用固定种子，无外部随机源）。

生成的图刻意保持小而多样：随机环、随机叶子、随机签发者与授权窗口、随机撤销
和审计截点。结构性不变量（根非叶子、全部产物可达、可信源码对唯一）在生成阶段
就保证，使每个用例都能通过 load_case 的结构校验，再交给被测核验器与独立
oracle 对比。
"""

from __future__ import annotations

import random

from .builders import attestation, grant, make_case, revocation, trust

ISSUERS = ["b1", "b2", "b3", "b4"]
ALIASES = ["R", "A", "B", "C", "D", "E"]


def generate_case(seed: int) -> dict:
    rng = random.Random(seed)
    n_artifacts = rng.randint(2, 5)
    aliases = ALIASES[:n_artifacts]  # 首个为根 R
    issuers = ISSUERS[: rng.randint(2, 4)]

    trusted: list[dict] = []
    trusted_pairs: set[tuple[str, str]] = set()
    declarations: list[dict] = []
    decl_seq = 0

    def next_id() -> str:
        nonlocal decl_seq
        decl_seq += 1
        return f"g{decl_seq:02d}"

    def add_trust(alias: str) -> None:
        row = trust(alias)
        pair = (row["repo"], row["commit"])
        if pair not in trusted_pairs:
            trusted_pairs.add(pair)
            trusted.append(row)

    for idx, alias in enumerate(aliases):
        is_root = idx == 0
        # 根必须是非叶子；最后一个产物强制为叶子保证图可闭合；其余随机
        make_leaf = (not is_root) and (
            idx == n_artifacts - 1 or rng.random() < 0.35
        )
        if make_leaf:
            builder = rng.choice(issuers)
            declarations.append(
                attestation(next_id(), alias, builder, rng.randint(50, 150))
            )
            add_trust(alias)
            continue
        # 非叶子：依赖至少一个“其它”产物；候选包含同层/更早产物以制造潜在环
        candidates = [a for a in aliases if a != alias]
        n_deps = rng.randint(1, min(2, len(candidates)))
        deps_aliases = rng.sample(candidates, n_deps)
        pins = [(d, f"sum-{d}") for d in deps_aliases]
        n_choices = rng.randint(1, 2)
        for _ in range(n_choices):
            builder = rng.choice(issuers)
            declarations.append(
                attestation(
                    next_id(),
                    alias,
                    builder,
                    rng.randint(50, 150),
                    deps=pins,
                )
            )

    # 可达性兜底：从根做一次依赖遍历，未被任何路径触达的产物补叶子声明，
    # 同时把指向它的依赖改为真正可达，避免出现“声明存在但查询不可达”的死产物。
    reachable = _reachable_aliases(declarations, "R")
    for alias in aliases:
        if alias not in reachable:
            builder = rng.choice(issuers)
            declarations.append(
                attestation(next_id(), alias, builder, rng.randint(50, 150))
            )
            add_trust(alias)

    # 授权：大部分全时窗，少量窄窗口制造失配
    grants = []
    for issuer in issuers:
        if rng.random() < 0.2:
            grants.append(
                grant(issuer, not_before=0, not_after=rng.randint(60, 120))
            )
        else:
            grants.append(grant(issuer))

    # 撤销：随机撤销若干声明，审计截点在撤销前后取点
    revs = []
    for seq, decl in enumerate(
        rng.sample(declarations, k=rng.randint(0, min(2, len(declarations)))), start=1
    ):
        revs.append(
            revocation(f"rv{seq}", decl, sequence=seq, occurred_at=rng.randint(200, 400))
        )
    cutoff = rng.choice([100, 300, 500])

    return make_case(
        f"FUZZ-{seed}",
        "R",
        declarations,
        issuers=issuers,
        trusted=trusted,
        grants=grants,
        revocations=revs,
        audit_cutoff=cutoff,
    )


def _reachable_aliases(declarations: list[dict], root_alias: str) -> set[str]:
    """按别名摘要关系做可达性分析（测试工具，独立实现）。"""
    from .builders import digest

    alias_digest = {alias: digest(alias) for alias in ALIASES}
    digest_alias = {v: k for k, v in alias_digest.items()}
    producers: dict[str, list[dict]] = {}
    for decl in declarations:
        producers.setdefault(decl["artifact_digest"], []).append(decl)

    seen: set[str] = set()
    stack = [root_alias]
    while stack:
        alias = stack.pop()
        if alias in seen:
            continue
        seen.add(alias)
        for decl in producers.get(alias_digest[alias], []):
            for pin in decl["dependencies"]:
                child = digest_alias.get(pin["digest"])
                if child is not None and child not in seen:
                    stack.append(child)
    return seen
