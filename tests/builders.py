"""测试用例构造工具。

用例内的产物身份必须是 64 位十六进制摘要，手工书写不可读，因此测试与生成脚本
统一使用短别名（R/A/B/...），由 :func:`digest` 用标准库 sha256 确定性派生。
本模块只负责“构造输入数据”，不包含任何从被测实现反推期望值的逻辑。
"""

from __future__ import annotations

import hashlib
from typing import Optional


def digest(alias: str) -> str:
    """别名 -> 64 位小写十六进制 SHA-256（确定性，无随机源）。"""
    return hashlib.sha256(f"artifact:{alias}".encode("utf-8")).hexdigest()


def source(alias: str, commit: str = "c1", org: str = "ci", project: Optional[str] = None):
    """源码位置；project 缺省取产物别名，方便构造路径段前缀。"""
    return {"repo": f"{org}/{project or alias}", "commit": commit}


def attestation(
    decl_id: str,
    artifact_alias: str,
    builder: str,
    issued_at: int,
    deps: Optional[list[tuple[str, str]]] = None,
    *,
    repo_alias: Optional[str] = None,
    project: Optional[str] = None,
    commit: str = "c1",
    dep_summary: Optional[str] = None,
    org: str = "ci",
    signature_valid: bool = True,
):
    """构造一条声明。deps 为 (依赖产物别名, dep_summary) 列表。"""
    ra = repo_alias or artifact_alias
    if dep_summary is None:
        dep_summary = f"sum-{artifact_alias}-{decl_id}"
    return {
        "id": decl_id,
        "artifact_digest": digest(artifact_alias),
        "builder": builder,
        "issued_at": issued_at,
        "source": source(ra, commit=commit, org=org, project=project or ra),
        "dependency_summary": dep_summary,
        "dependencies": [
            {"digest": digest(alias), "dep_summary": dep_sum}
            for alias, dep_sum in (deps or [])
        ],
        "signature_valid": signature_valid,
    }


def trust(alias: str, commit: str = "c1", org: str = "ci", project: Optional[str] = None):
    """外部预置可信源码；digest 是源码快照自身摘要（与构建产物摘要身份空间不同）。

    叶子声明通过 (repo, commit) 精确匹配到这里，而不是通过产物摘要匹配。
    """
    p = project or alias
    source_digest = hashlib.sha256(f"source:{org}/{p}@{commit}".encode("utf-8")).hexdigest()
    return {
        "repo": f"{org}/{p}",
        "commit": commit,
        "digest": source_digest,
    }


def grant(issuer: str, repo: str = "ci", not_before: int = 0, not_after: int = 10_000):
    return {"issuer": issuer, "repo": repo, "not_before": not_before, "not_after": not_after}


def revocation(rid: str, declaration: dict, *, sequence: int, occurred_at: int):
    """撤销的 trace_issued_at 直接锚定被撤声明真实签发时间（可追溯）。"""
    return {
        "id": rid,
        "declaration_id": declaration["id"],
        "occurred_at": occurred_at,
        "sequence": sequence,
        "trace_issued_at": declaration["issued_at"],
    }


def make_case(
    case_id: str,
    root_alias: str,
    declarations: list[dict],
    *,
    issuers: list[str],
    trusted: Optional[list[dict]] = None,
    grants: Optional[list[dict]] = None,
    revocations: Optional[list[dict]] = None,
    audit_cutoff: int = 10_000,
    cutoff_sequence: Optional[int] = None,
):
    """组装一个完整用例；默认对每个签发者授予 ci 前缀的全时窗授权。"""
    if grants is None:
        grants = [grant(issuer) for issuer in issuers]
    return {
        "case_id": case_id,
        "issuers": [{"id": i} for i in issuers],
        "authorizations": grants,
        "trusted_sources": trusted or [],
        "declarations": declarations,
        "revocations": revocations or [],
        "query": {
            "root_artifact": digest(root_alias),
            "audit_cutoff": audit_cutoff,
            "cutoff_sequence": cutoff_sequence,
        },
    }
