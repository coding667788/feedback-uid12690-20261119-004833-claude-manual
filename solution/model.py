"""JSON 输入的数据模型、加载与全量校验。

时间统一使用非负整数（可视为 Unix 纪元秒），区间语义全部为左闭右开。
仓库路径以 ``/`` 切分为非空段序列；授权匹配使用“段前缀”规则。
产物身份为 64 位小写十六进制 SHA-256 摘要。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .errors import INVALID_INPUT, LIMIT_EXCEEDED, UNKNOWN_REFERENCE, VerifierInputError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_LIMITS = {"max_artifacts": 30, "max_declarations": 60, "max_issuers": 12}


def _is_int(value) -> bool:
    """时间/序号必须是整数；显式排除 bool（Python 中 bool 是 int 子类）。"""
    return isinstance(value, int) and not isinstance(value, bool)


def split_repo(repo: str) -> tuple[str, ...]:
    """仓库路径切分为段，空段（含首尾/重复斜杠）一律拒绝。"""
    if not isinstance(repo, str) or not repo:
        raise VerifierInputError(INVALID_INPUT, "仓库路径必须是非空字符串")
    segments = repo.split("/")
    if any(seg == "" for seg in segments):
        raise VerifierInputError(INVALID_INPUT, f"仓库路径存在空段: {repo!r}")
    return tuple(segments)


def _check_digest(digest: str, where: str) -> str:
    if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
        raise VerifierInputError(
            INVALID_INPUT, f"{where} 必须是 64 位小写十六进制 SHA-256 摘要"
        )
    return digest


def _check_time(value: int, where: str) -> int:
    if not _is_int(value) or value < 0:
        raise VerifierInputError(INVALID_INPUT, f"{where} 必须是非负整数时间戳")
    return value


@dataclass(frozen=True)
class SourceRef:
    """源码位置：仓库路径 + 提交哈希（字符串原样保留）。"""

    repo: str
    commit: str
    segments: tuple[str, ...] = field(compare=False)


@dataclass(frozen=True)
class Pin:
    """依赖锚点：被依赖产物摘要 + 该声明内使用的依赖摘要（规范排序键）。"""

    digest: str
    dep_summary: str


@dataclass(frozen=True)
class Authorization:
    """授权窗口：签发者对某仓库段前缀的左闭右开授权。"""

    issuer: str
    segments: tuple[str, ...]
    not_before: int
    not_after: int

    def covers(self, repo_segments: tuple[str, ...], issued_at: int) -> bool:
        if not (self.not_before <= issued_at < self.not_after):
            return False
        if len(repo_segments) < len(self.segments):
            return False
        return repo_segments[: len(self.segments)] == self.segments


@dataclass(frozen=True)
class TrustedSource:
    """外部预置的可信源码：叶子证明唯一允许的落点。"""

    repo: str
    commit: str
    digest: str
    segments: tuple[str, ...]


@dataclass(frozen=True)
class Declaration:
    """一条构建声明（attestation）。"""

    id: str
    artifact_digest: str
    builder: str
    issued_at: int
    source: SourceRef
    dependency_summary: str
    pins: tuple[Pin, ...]
    signature_valid: bool


@dataclass(frozen=True)
class Revocation:
    """历史撤销：发生时间 + 全局录入序号，并可追溯到被撤声明的签发时间。"""

    id: str
    declaration_id: str
    occurred_at: int
    sequence: int
    trace_issued_at: int


@dataclass(frozen=True)
class Query:
    root_artifact: str
    audit_cutoff: int
    cutoff_sequence: int | None


@dataclass(frozen=True)
class Case:
    case_id: str
    limits: dict
    issuers: frozenset[str]
    authorizations: tuple[Authorization, ...]
    trusted_sources: frozenset[tuple[str, str]]
    trusted_by_source: dict[tuple[str, str], TrustedSource]
    declarations: tuple[Declaration, ...]
    decl_by_id: dict[str, Declaration]
    revocations: tuple[Revocation, ...]
    query: Query
    artifact_digests: frozenset[str]

    def producers(self, digest: str) -> list[Declaration]:
        """产出指定产物的全部声明，按声明 ID 排序保证确定性。"""
        out = [d for d in self.declarations if d.artifact_digest == digest]
        out.sort(key=lambda d: d.id)
        return out


def _require(obj: dict, key: str, where: str):
    if not isinstance(obj, dict) or key not in obj:
        raise VerifierInputError(INVALID_INPUT, f"{where} 缺少必填字段 {key!r}")
    return obj[key]


def _parse_source(obj, where: str) -> SourceRef:
    if not isinstance(obj, dict):
        raise VerifierInputError(INVALID_INPUT, f"{where} 必须是对象")
    repo = _require(obj, "repo", where)
    commit = _require(obj, "commit", where)
    if not isinstance(commit, str) or not commit:
        raise VerifierInputError(INVALID_INPUT, f"{where}.commit 必须是非空字符串")
    segments = tuple(split_repo(repo))
    return SourceRef(repo=repo, commit=commit, segments=segments)


def load_case(raw: dict) -> Case:
    """校验并加载单个用例，任何结构/引用/规模问题都抛 :class:`VerifierInputError`。"""
    if not isinstance(raw, dict):
        raise VerifierInputError(INVALID_INPUT, "用例必须是 JSON 对象")
    case_id = _require(raw, "case_id", "用例")
    if not isinstance(case_id, str) or not case_id:
        raise VerifierInputError(INVALID_INPUT, "case_id 必须是非空字符串")

    limits = dict(DEFAULT_LIMITS)
    if "limits" in raw:
        if not isinstance(raw["limits"], dict):
            raise VerifierInputError(INVALID_INPUT, "limits 必须是对象")
        for key, default in DEFAULT_LIMITS.items():
            if key in raw["limits"]:
                value = raw["limits"][key]
                if not _is_int(value) or value <= 0:
                    raise VerifierInputError(INVALID_INPUT, f"limits.{key} 必须是正整数")
                limits[key] = value

    # ---- 签发者 ----
    issuer_rows = raw.get("issuers", [])
    if not isinstance(issuer_rows, list) or not issuer_rows:
        raise VerifierInputError(INVALID_INPUT, "issuers 必须是非空数组")
    issuers: set[str] = set()
    for row in issuer_rows:
        iid = _require(row, "id", "issuers[]")
        if not isinstance(iid, str) or not iid:
            raise VerifierInputError(INVALID_INPUT, "签发者 id 必须是非空字符串")
        if iid in issuers:
            raise VerifierInputError(INVALID_INPUT, f"签发者 id 重复: {iid}")
        issuers.add(iid)

    # ---- 授权 ----
    auth_rows = raw.get("authorizations", [])
    if not isinstance(auth_rows, list):
        raise VerifierInputError(INVALID_INPUT, "authorizations 必须是数组")
    authorizations: list[Authorization] = []
    for row in auth_rows:
        if not isinstance(row, dict):
            raise VerifierInputError(INVALID_INPUT, "authorizations[] 必须是对象")
        issuer = _require(row, "issuer", "authorizations[]")
        if issuer not in issuers:
            raise VerifierInputError(
                UNKNOWN_REFERENCE, f"授权引用了未定义签发者: {issuer}"
            )
        repo = _require(row, "repo", "authorizations[]")
        segments = tuple(split_repo(repo))
        not_before = _check_time(_require(row, "not_before", "authorizations[]"), "not_before")
        not_after = _check_time(_require(row, "not_after", "authorizations[]"), "not_after")
        if not_before > not_after:
            raise VerifierInputError(
                INVALID_INPUT, "授权窗口 not_before 不能晚于 not_after"
            )
        authorizations.append(
            Authorization(issuer, segments, not_before, not_after)
        )

    # ---- 可信源码（外部预置） ----
    ts_rows = raw.get("trusted_sources", [])
    if not isinstance(ts_rows, list):
        raise VerifierInputError(INVALID_INPUT, "trusted_sources 必须是数组")
    trusted_pairs: set[tuple[str, str]] = set()
    trusted_by_source: dict[tuple[str, str], TrustedSource] = {}
    trusted_digests: set[str] = set()
    for row in ts_rows:
        if not isinstance(row, dict):
            raise VerifierInputError(INVALID_INPUT, "trusted_sources[] 必须是对象")
        repo = _require(row, "repo", "trusted_sources[]")
        commit = _require(row, "commit", "trusted_sources[]")
        digest = _check_digest(_require(row, "digest", "trusted_sources[]"), "trusted_sources[].digest")
        if not isinstance(commit, str) or not commit:
            raise VerifierInputError(INVALID_INPUT, "trusted_sources[].commit 必须是非空字符串")
        segments = tuple(split_repo(repo))
        pair = (repo, commit)
        if pair in trusted_pairs:
            raise VerifierInputError(INVALID_INPUT, f"可信源码重复: {repo}@{commit}")
        if digest in trusted_digests:
            raise VerifierInputError(INVALID_INPUT, f"可信源码摘要重复: {digest}")
        trusted_pairs.add(pair)
        trusted_digests.add(digest)
        trusted_by_source[pair] = TrustedSource(repo, commit, digest, segments)

    # ---- 声明 ----
    decl_rows = raw.get("declarations", [])
    if not isinstance(decl_rows, list) or not decl_rows:
        raise VerifierInputError(INVALID_INPUT, "declarations 必须是非空数组")
    declarations: list[Declaration] = []
    decl_ids: set[str] = set()
    artifact_digests: set[str] = set()
    for row in decl_rows:
        if not isinstance(row, dict):
            raise VerifierInputError(INVALID_INPUT, "declarations[] 必须是对象")
        did = _require(row, "id", "declarations[]")
        if not isinstance(did, str) or not did:
            raise VerifierInputError(INVALID_INPUT, "声明 id 必须是非空字符串")
        if did in decl_ids:
            raise VerifierInputError(INVALID_INPUT, f"声明 id 重复: {did}")
        decl_ids.add(did)

        digest = _check_digest(
            _require(row, "artifact_digest", f"声明 {did}"), f"声明 {did}.artifact_digest"
        )
        builder = _require(row, "builder", f"声明 {did}")
        if builder not in issuers:
            raise VerifierInputError(
                UNKNOWN_REFERENCE, f"声明 {did} 引用了未定义签发者: {builder}"
            )
        issued_at = _check_time(_require(row, "issued_at", f"声明 {did}"), f"声明 {did}.issued_at")
        source = _parse_source(_require(row, "source", f"声明 {did}"), f"声明 {did}.source")

        dep_summary = _require(row, "dependency_summary", f"声明 {did}")
        if not isinstance(dep_summary, str) or not dep_summary:
            raise VerifierInputError(
                INVALID_INPUT, f"声明 {did}.dependency_summary 必须是非空字符串"
            )

        pin_rows = row.get("dependencies", [])
        if not isinstance(pin_rows, list):
            raise VerifierInputError(INVALID_INPUT, f"声明 {did}.dependencies 必须是数组")
        seen_pin: set[tuple[str, str]] = set()
        pins: list[Pin] = []
        for pr in pin_rows:
            if not isinstance(pr, dict):
                raise VerifierInputError(INVALID_INPUT, f"声明 {did}.dependencies[] 必须是对象")
            dep_digest = _check_digest(
                _require(pr, "digest", f"声明 {did}.dependencies[]"), "依赖 digest"
            )
            dep_sum = _require(pr, "dep_summary", f"声明 {did}.dependencies[]")
            if not isinstance(dep_sum, str) or not dep_sum:
                raise VerifierInputError(
                    INVALID_INPUT, f"声明 {did} 的依赖 dep_summary 必须是非空字符串"
                )
            # 同一产物可作为不同兄弟依赖重复出现（不同 dep_summary 区分），
            # 但完全相同的 (digest, dep_summary) 锚点重复登记无意义，拒绝。
            pin_key = (dep_digest, dep_sum)
            if pin_key in seen_pin:
                raise VerifierInputError(
                    INVALID_INPUT,
                    f"声明 {did} 依赖锚点重复: digest={dep_digest} dep_summary={dep_sum}",
                )
            seen_pin.add(pin_key)
            pins.append(Pin(dep_digest, dep_sum))

        sig = row.get("signature_valid", True)
        if not isinstance(sig, bool):
            raise VerifierInputError(INVALID_INPUT, f"声明 {did}.signature_valid 必须是布尔值")

        declarations.append(
            Declaration(
                id=did,
                artifact_digest=digest,
                builder=builder,
                issued_at=issued_at,
                source=source,
                dependency_summary=dep_summary,
                pins=tuple(pins),
                signature_valid=sig,
            )
        )
        artifact_digests.add(digest)

    # 可信源码摘要是“源码快照”自身摘要，与构建产物摘要属于不同身份空间，
    # 二者即使数值相同也不冲突；身份由 trusted_sources 的 (repo, commit) 决定。

    # ---- 撤销 ----
    rev_rows = raw.get("revocations", [])
    if not isinstance(rev_rows, list):
        raise VerifierInputError(INVALID_INPUT, "revocations 必须是数组")
    revocations: list[Revocation] = []
    rev_ids: set[str] = set()
    sequences: set[int] = set()
    for row in rev_rows:
        if not isinstance(row, dict):
            raise VerifierInputError(INVALID_INPUT, "revocations[] 必须是对象")
        rid = _require(row, "id", "revocations[]")
        if not isinstance(rid, str) or not rid or rid in rev_ids:
            raise VerifierInputError(INVALID_INPUT, f"撤销 id 非法或重复: {rid!r}")
        rev_ids.add(rid)
        target = _require(row, "declaration_id", f"撤销 {rid}")
        if target not in decl_ids:
            raise VerifierInputError(
                UNKNOWN_REFERENCE, f"撤销 {rid} 指向未定义声明: {target}"
            )
        occurred_at = _check_time(
            _require(row, "occurred_at", f"撤销 {rid}"), f"撤销 {rid}.occurred_at"
        )
        sequence = _require(row, "sequence", f"撤销 {rid}")
        if not _is_int(sequence) or sequence < 0:
            raise VerifierInputError(INVALID_INPUT, f"撤销 {rid}.sequence 必须是非负整数")
        if sequence in sequences:
            raise VerifierInputError(INVALID_INPUT, f"撤销录入序号重复: {sequence}")
        sequences.add(sequence)
        trace = _check_time(
            _require(row, "trace_issued_at", f"撤销 {rid}"), f"撤销 {rid}.trace_issued_at"
        )
        # 可追溯性：撤销必须锚定被撤声明真实的签发时间
        target_decl = next(d for d in declarations if d.id == target)
        if trace != target_decl.issued_at:
            raise VerifierInputError(
                INVALID_INPUT,
                f"撤销 {rid} 的 trace_issued_at={trace} 与声明 {target} 的"
                f"签发时间 {target_decl.issued_at} 不一致",
            )
        revocations.append(Revocation(rid, target, occurred_at, sequence, trace))

    # ---- 规模上限（在 query 引用检查之前，优先报告 LIMIT_EXCEEDED） ----
    if len(artifact_digests) > limits["max_artifacts"]:
        raise VerifierInputError(
            LIMIT_EXCEEDED,
            f"产物数 {len(artifact_digests)} 超过上限 {limits['max_artifacts']}",
        )
    if len(declarations) > limits["max_declarations"]:
        raise VerifierInputError(
            LIMIT_EXCEEDED,
            f"声明数 {len(declarations)} 超过上限 {limits['max_declarations']}",
        )
    if len(issuers) > limits["max_issuers"]:
        raise VerifierInputError(
            LIMIT_EXCEEDED,
            f"签发者数 {len(issuers)} 超过上限 {limits['max_issuers']}",
        )

    # ---- 查询 ----
    qrow = _require(raw, "query", "用例")
    if not isinstance(qrow, dict):
        raise VerifierInputError(INVALID_INPUT, "query 必须是对象")
    root = _check_digest(_require(qrow, "root_artifact", "query"), "query.root_artifact")
    if root not in artifact_digests:
        raise VerifierInputError(
            UNKNOWN_REFERENCE, f"查询根产物没有任何声明: {root}"
        )
    cutoff = _check_time(_require(qrow, "audit_cutoff", "query"), "query.audit_cutoff")
    cutoff_sequence = qrow.get("cutoff_sequence")
    if cutoff_sequence is not None:
        if not _is_int(cutoff_sequence) or cutoff_sequence < 0:
            raise VerifierInputError(
                INVALID_INPUT, "query.cutoff_sequence 必须是非负整数或 null"
            )

    return Case(
        case_id=case_id,
        limits=limits,
        issuers=frozenset(issuers),
        authorizations=tuple(authorizations),
        trusted_sources=frozenset(trusted_pairs),
        trusted_by_source=trusted_by_source,
        declarations=tuple(declarations),
        decl_by_id={d.id: d for d in declarations},
        revocations=tuple(revocations),
        query=Query(root, cutoff, cutoff_sequence),
        artifact_digests=frozenset(artifact_digests),
    )
