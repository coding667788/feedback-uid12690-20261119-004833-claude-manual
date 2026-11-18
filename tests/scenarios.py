"""手工设计的规范场景与独立推导的期望值。

期望值全部由人工在设计时枚举小图得到（见各函数 docstring 的推导说明），
不读取、不导入 solution.verifier 的任何计算结果。测试和 cases.json 生成脚本
共用本模块，保证“测试的用例”和“交付的用例”完全一致。
"""

from __future__ import annotations

from .builders import attestation, digest, grant, make_case, revocation, trust

# 签发者命名：b* = 非源码构建者；s* = 只出现在叶子（源码）声明的构建者。


# ---------------------------------------------------------------------------
# A. 局部最短组合无解，改选后成功（最优代价 4+3=7，而非最短树代价 3+3=6）
# ---------------------------------------------------------------------------
def case_a_local_shortest_dead_end():
    decls = [
        attestation("d1", "R", "b1", 100, [("X", "px")]),
        attestation("d2", "R", "b2", 100, [("X", "px")]),
        attestation("d3", "R", "b3", 100, [("Y", "py")]),
        attestation("x1", "X", "b1", 90, [("L", "pl")]),
        attestation("x2", "X", "b2", 90, [("L", "pl")]),
        attestation("y1", "Y", "b3", 90, [("L", "pl")]),
        attestation("l1", "L", "b3", 80),
    ]
    case = make_case(
        "A_local_shortest_dead_end",
        "R",
        decls,
        issuers=["b1", "b2", "b3"],
        trusted=[trust("L")],
    )
    # 完备根证明（叶子声明 l1 计出现次数，但其 b3 不计非源码签发者集合）：
    #   d1+x1+l1 非源码集合 {b1}；d2+x2+l1 非源码集合 {b2}
    #   d1+x2+l1 / d2+x1+l1 非源码集合 {b1,b2}；d3+y1+l1 非源码集合 {}
    # 互斥对中 DFS 字典序最小者：d1+x1+l1 {b1} 与 d2+x2+l1 {b2}，合计代价 6。
    expected = {
        "status": "ok",
        "total_occurrences": 6,
        "tree_costs": [3, 3],
        "tree_dfs": [["d1", "x1", "l1"], ["d2", "x2", "l1"]],
        "tree_issuers": [{"b1"}, {"b2"}],
    }
    return case, expected


def case_a2_local_shortest_dead_end_two_layer():
    """同一主题的严格版：最短根树全部代价 3 且构不成互斥对，改选代价 4 的分支。

    两条短链 d1/d2 都强制经过共享非叶子依赖 K（构建者 bk），因此任意短根树的
    非源码签发者集合都含 bk，短树两两不可能互斥；长链 d3 走独立的 Y/Z 通道，
    不含 bk，才能与短树组成独立对。
    """
    decls = [
        attestation("d1", "R", "b1", 100, [("K", "pk")]),
        attestation("d2", "R", "b2", 100, [("K", "pk")]),
        attestation("d3", "R", "b4", 100, [("Y", "py")]),
        attestation("k1", "K", "bk", 90, [("L", "pl")]),
        attestation("y1", "Y", "b4", 85, [("Z", "pz")]),
        attestation("z1", "Z", "b4", 82, [("L", "pl")]),
        attestation("l1", "L", "b9", 80),
    ]
    case = make_case(
        "A2_local_shortest_dead_end_two_layer",
        "R",
        decls,
        issuers=["b1", "b2", "b4", "bk", "b9"],
        trusted=[trust("L")],
    )
    # 短树（代价3）：d1+k1+l1 非源码集合 {b1,bk}；d2+k1+l1 {b2,bk}。
    # 二者共享 bk，不互斥；且 K 只有 k1 一条证明，短树无解。
    # 长树（代价4）：d3+y1+z1+l1 非源码集合 {b4}，与 {b1,bk} 互斥。
    # 最优 = DFS 最小短树 d1+k1+l1 + 长树，合计 3+4=7。
    expected = {
        "status": "ok",
        "total_occurrences": 7,
        "tree_costs": [3, 4],
        "tree_dfs": [["d1", "k1", "l1"], ["d3", "y1", "z1", "l1"]],
        "first_tree_issuers": {"b1", "bk"},
        "second_tree_issuers": {"b4"},
    }
    return case, expected


# ---------------------------------------------------------------------------
# B. 旁路打破循环：R->A->B->A 为环，A 的另一声明直接落到可信源码
# ---------------------------------------------------------------------------
def case_b_bypass_breaks_cycle():
    decls = [
        attestation("r1", "R", "b1", 100, [("A", "pa")]),
        attestation("r2", "R", "b2", 100, [("A", "pa")]),
        attestation("a1", "A", "b1", 90, [("B", "pb")]),
        attestation("a2", "A", "b3", 80),  # 旁路：叶子声明
        attestation("bb1", "B", "b2", 85, [("A", "pa")]),  # 指回 A，成环
    ]
    case = make_case(
        "B_bypass_breaks_cycle",
        "R",
        decls,
        issuers=["b1", "b2", "b3"],
        trusted=[trust("A")],
    )
    # 合法根树只有经过 a2 的：r1+a2（非源码集合 {b1}，代价2，a2 是叶子声明）、
    # r2+a2（{b2}，代价2）。沿 a1->bb1 再选 a1 即同路径重复 A，无效。
    # 互斥对：{b1} 与 {b2}，合计代价 4。
    expected = {
        "status": "ok",
        "total_occurrences": 4,
        "tree_costs": [2, 2],
        "tree_dfs": [["r1", "a2"], ["r2", "a2"]],
        "tree_issuers": [{"b1"}, {"b2"}],
    }
    return case, expected


def case_b2_pure_cycle_no_complete_proof():
    """无旁路版本：环不可消除，根产物没有任何完备证明。"""
    decls = [
        attestation("r1", "R", "b1", 100, [("A", "pa")]),
        attestation("a1", "A", "b1", 90, [("B", "pb")]),
        attestation("bb1", "B", "b2", 85, [("A", "pa")]),
    ]
    case = make_case(
        "B2_pure_cycle_no_complete_proof",
        "R",
        decls,
        issuers=["b1", "b2"],
        trusted=[],
    )
    expected = {"status": "fail", "error_code": "NO_COMPLETE_PROOF"}
    return case, expected


# ---------------------------------------------------------------------------
# C. 撤销追溯改变历史截点查询：同一用例两个查询截点，结论不同
# ---------------------------------------------------------------------------
def _case_c_decls():
    # X 的证明分两层：非叶子声明 x1/x2（构建者 b1/b2，进入互斥集合）依赖叶子 L；
    # 另有第三条独立链 x3（构建者 b3）。撤销 x 声明即可真正改变互斥结构。
    decls = [
        attestation("r1", "R", "b1", 100, [("X", "px")]),
        attestation("r2", "R", "b2", 100, [("X", "px")]),
        attestation("x1", "X", "b1", 90, [("L", "pl")]),
        attestation("x2", "X", "b2", 90, [("L", "pl")]),
        attestation("x3", "X", "b3", 90, [("L", "pl")]),
        attestation("l1", "L", "b9", 80),
    ]
    return decls, [trust("L")]


def case_c_early_cutoff():
    decls, trusted = _case_c_decls()
    rev = revocation("rv1", decls[2], sequence=1, occurred_at=500)  # 撤销 x3
    case = make_case(
        "C1_revocation_early_cutoff_pair_exists",
        "R",
        decls,
        issuers=["b1", "b2", "b3", "b9"],
        trusted=trusted,
        revocations=[rev],
        audit_cutoff=400,  # 撤销发生在 500，尚不可见
    )
    # 截点 400：x1/x2/x3 全部可见。每棵根树含 r 与 x 两个非叶子声明。
    # r1+x1 链非源码集合 {b1}，r2+x2 链 {b2}，二者互斥，DFS 最小且合计代价 6。
    expected = {
        "status": "ok",
        "total_occurrences": 6,
        "tree_dfs": [["r1", "x1", "l1"], ["r2", "x2", "l1"]],
        "visible_revocation_ids": [],
    }
    return case, expected


def case_c_late_cutoff_pair_destroyed():
    decls, trusted = _case_c_decls()
    # 先撤 x3（b3 链），再撤 x2（b2 链）；截点 600 时两条撤销均可见。
    rev = revocation("rv1", decls[2], sequence=1, occurred_at=500)
    rev2 = revocation("rv2", decls[3], sequence=2, occurred_at=550)
    case = make_case(
        "C2_revocation_late_cutoff_pair_destroyed",
        "R",
        decls,
        issuers=["b1", "b2", "b3", "b9"],
        trusted=trusted,
        revocations=[rev, rev2],
        audit_cutoff=600,
    )
    # 剩余可用 X 证明只有 x1（b1）。无论 r1 还是 r2，根树非源码集合都含 b1，
    # 任意两棵树共享 b1，互斥对消失 -> NO_INDEPENDENT_PAIR。
    expected = {
        "status": "fail",
        "error_code": "NO_INDEPENDENT_PAIR",
        "visible_revocation_ids": ["rv1", "rv2"],
    }
    return case, expected


def case_c_sequence_cutoff():
    """同发生时间、不同录入序号：cutoff_sequence 限制可见撤销。"""
    decls, trusted = _case_c_decls()
    rev1 = revocation("rv1", decls[2], sequence=1, occurred_at=500)
    rev2 = revocation("rv2", decls[3], sequence=2, occurred_at=500)
    case = make_case(
        "C3_revocation_sequence_cutoff",
        "R",
        decls,
        issuers=["b1", "b2", "b3", "b9"],
        trusted=trusted,
        revocations=[rev1, rev2],
        audit_cutoff=600,
        cutoff_sequence=1,  # rv2(序号2) 不可见，x2 仍可用
    )
    # rv1（序号1，撤 x1）可见 -> x1 失效；rv2（序号2，撤 x2）被序号截点挡掉 -> x2 可用。
    # 可用 X 证明为 x2（b2）、x3（b3）。r1 链 DFS 最小选 x3（{b1,b3}），
    # r2 链选 x2（{b2}），二者互斥，合计代价 6；可见撤销仅 rv1。
    expected = {
        "status": "ok",
        "total_occurrences": 6,
        "tree_dfs": [["r1", "x3", "l1"], ["r2", "x2", "l1"]],
        "visible_revocation_ids": ["rv1"],
    }
    return case, expected


# ---------------------------------------------------------------------------
# D. 共享依赖不重复伪造独立性：两分支共用同一子图，不产生虚假签发者
# ---------------------------------------------------------------------------
def case_d_shared_dependency():
    decls = [
        attestation("r1", "R", "b1", 100, [("X", "px"), ("Y", "py")]),
        attestation("r2", "R", "b2", 100, [("X", "px"), ("Y", "py")]),
        attestation("x1", "X", "b3", 90, [("Lx", "plx")]),
        attestation("y1", "Y", "b3", 88, [("Ly", "ply")]),
        attestation("lx", "Lx", "b9", 82),
        attestation("ly", "Ly", "b9", 81),
    ]
    case = make_case(
        "D_shared_dependency_not_double_counted",
        "R",
        decls,
        issuers=["b1", "b2", "b3", "b9"],
        trusted=[trust("Lx"), trust("Ly")],
    )
    # 每棵根树声明出现 5 次（r, x, y, 两个叶子声明；可信源码本身不计）。
    # 非源码集合都是 {b1或b2, b3}（叶子声明的 b9 不计）。两棵根树之间 b3 是
    # 真实共享的非源码签发者，不能因“各算各的子图”而伪造互斥独立性；
    # 且 X、Y 没有其他证明，故无法组成独立对。
    expected = {
        "status": "fail",
        "error_code": "NO_INDEPENDENT_PAIR",
        "single_tree_occurrences": 5,
        "single_tree_issuers_subset": {"b3"},
    }
    return case, expected


def case_d2_shared_source_allowed():
    """两个分支共用同一可信源码叶子是允许的（源码不在互斥集合内）。"""
    decls = [
        attestation("r1", "R", "b1", 100, [("X", "px")]),
        attestation("r2", "R", "b2", 100, [("Y", "py")]),
        attestation("x1", "X", "b1", 90),
        attestation("y1", "Y", "b2", 90),
    ]
    case = make_case(
        "D2_shared_trusted_source_allowed",
        "R",
        decls,
        issuers=["b1", "b2"],
        trusted=[trust("X"), trust("Y")],
    )
    # r1+x1 {b1} 代价2；r2+y1 {b2} 代价2（x1/y1 是叶子声明，构建者不计互斥集合）；
    # 互斥对成立，合计 4，两棵树共用可信源码身份空间是允许的。
    expected = {
        "status": "ok",
        "total_occurrences": 4,
        "tree_dfs": [["r1", "x1"], ["r2", "y1"]],
    }
    return case, expected


# ---------------------------------------------------------------------------
# E. 对“签发者集合较小却较长”的备选证明正确判断（代价优先，集合不参与排序）
# ---------------------------------------------------------------------------
def case_e_small_set_longer_proof():
    """对“签发者集合较小却较长”的备选证明正确判断。

    X 有两条非叶子证明链：短链 x2 引入额外签发者 b3（集合大、深度浅），
    长链 x1->m1 只使用 b1（集合小、深度深）。选择仅由代价与 DFS 决定，
    签发者集合大小不参与排序，只参与互斥可行性。
    """
    decls = [
        attestation("r1", "R", "b1", 100, [("X", "px")]),
        attestation("r2", "R", "b2", 100, [("X", "px")]),
        attestation("x1", "X", "b1", 90, [("M", "pm")]),  # 长链，只用 b1
        attestation("x2", "X", "b3", 90, [("Q", "pq")]),  # 短链（相对），引入 b3
        attestation("m1", "M", "b1", 85, [("L", "pl")]),
        attestation("q1", "Q", "b3", 84, [("L", "pl")]),
        attestation("l1", "L", "b9", 80),
    ]
    case = make_case(
        "E_small_set_but_longer_proof",
        "R",
        decls,
        issuers=["b1", "b2", "b3", "b9"],
        trusted=[trust("L")],
    )
    # 根证明（叶子声明 l1 计代价但 b9 不计互斥集合）：
    #   r1+x1+m1+l1 代价4 非源码集合 {b1}（长、集合小）
    #   r1+x2+q1+l1 代价4 非源码集合 {b1,b3}
    #   r2+x1+m1+l1 代价4 非源码集合 {b1,b2}
    #   r2+x2+q1+l1 代价4 非源码集合 {b2,b3}（短链）
    # 互斥对只有 {b1} ∩ {b2,b3}=空，即长链 r1 配短链 r2，合计 8；
    # 集合更小的长链不会因“集合小”而被优先或淘汰，只按规则参与代价/DFS 比较。
    expected = {
        "status": "ok",
        "total_occurrences": 8,
        "tree_costs": [4, 4],
        "tree_dfs": [["r1", "x1", "m1", "l1"], ["r2", "x2", "q1", "l1"]],
        "tree_issuers": [{"b1"}, {"b2", "b3"}],
    }
    return case, expected


# ---------------------------------------------------------------------------
# F. 授权窗口（左闭右开）与仓库段前缀匹配
# ---------------------------------------------------------------------------
def case_f_authorization_boundaries():
    decls = [
        attestation("r1", "R", "b1", 100),  # 命中窗口 [0,200)
        attestation("r2", "R", "b2", 200),  # 窗口 [0,200) 右端点开区间，失配
        attestation("r3", "R", "b3", 100, org="vendor", project="R"),  # 段前缀 ci 不匹配
    ]
    grants = [
        grant("b1", repo="ci", not_before=0, not_after=200),
        grant("b2", repo="ci", not_before=0, not_after=200),
        grant("b3", repo="ci", not_before=0, not_after=1000),
    ]
    case = make_case(
        "F_authorization_boundaries",
        "R",
        decls,
        issuers=["b1", "b2", "b3"],
        trusted=[trust("R"), trust("R", org="vendor")],
        grants=grants,
    )    # 仅 r1 合格；单棵证明无法凑成两份独立证明 -> NO_INDEPENDENT_PAIR。
    expected = {
        "status": "fail",
        "error_code": "NO_INDEPENDENT_PAIR",
        "eligible_ids": ["r1"],
    }
    return case, expected


# ---------------------------------------------------------------------------
# G. 模拟验签失败
# ---------------------------------------------------------------------------
def case_g_bad_signature():
    decls = [
        attestation("r1", "R", "b1", 100, [("L", "pl")]),
        attestation("r2", "R", "b2", 100, [("L", "pl")]),
        attestation("l1", "L", "b9", 80, signature_valid=False),
    ]
    case = make_case(
        "G_bad_signature_blocks_leaves",
        "R",
        decls,
        issuers=["b1", "b2", "b9"],
        trusted=[trust("L")],
    )
    # 唯一叶子声明验签失败，两条根链都无法闭合 -> NO_COMPLETE_PROOF。
    expected = {"status": "fail", "error_code": "NO_COMPLETE_PROOF"}
    return case, expected


# ---------------------------------------------------------------------------
# H. 只有外部预置可信源码可作叶子
# ---------------------------------------------------------------------------
def case_h_untrusted_leaf_rejected():
    decls = [
        attestation("r1", "R", "b1", 100, [("L", "pl")]),
        attestation("r2", "R", "b2", 100, [("L", "pl")]),
        attestation("l1", "L", "b9", 80),
    ]
    case = make_case(
        "H_untrusted_leaf_rejected",
        "R",
        decls,
        issuers=["b1", "b2", "b9"],
        trusted=[],  # 无任何外部预置可信源码
    )
    expected = {"status": "fail", "error_code": "NO_COMPLETE_PROOF"}
    return case, expected


# ---------------------------------------------------------------------------
# I. 同一产物在不同兄弟分支可选用不同声明
# ---------------------------------------------------------------------------
def case_i_sibling_choice_diversity():
    decls = [
        attestation(
            "r1", "R", "b1", 100, [("X", "pa"), ("Y", "pb")],
            dep_summary="sum-R",
        ),
        attestation("x1", "X", "b2", 90),
        attestation("y1", "Y", "b3", 90),
    ]
    case = make_case(
        "I_sibling_choice_diversity",
        "R",
        decls,
        issuers=["b1", "b2", "b3"],
        trusted=[trust("X"), trust("Y")],
    )
    # 只有一棵根树（r1+x1+y1：r1 为非叶子，x1/y1 为叶子声明，共 3 次出现），
    # 无法成对 -> NO_INDEPENDENT_PAIR，但穷举正常闭合，兄弟分支各自独立选声明。
    expected = {
        "status": "fail",
        "error_code": "NO_INDEPENDENT_PAIR",
        "root_proof_count": 1,
        "single_tree_dfs": ["r1", "x1", "y1"],
    }
    return case, expected


# ---------------------------------------------------------------------------
# J. 同一产物在不同兄弟分支可选用不同声明（重复 digest、不同 dep_summary）
# ---------------------------------------------------------------------------
def case_j_sibling_same_artifact_different_declarations():
    decls = [
        # R 通过两个不同兄弟锚点（sa/sb）两次依赖同一产物 X
        attestation(
            "r1", "R", "b1", 100, [("X", "sa"), ("X", "sb")],
            dep_summary="sum-R",
        ),
        attestation("x1", "X", "b2", 90),
        attestation("x2", "X", "b3", 90),
    ]
    case = make_case(
        "J_sibling_same_artifact_different_declarations",
        "R",
        decls,
        issuers=["b1", "b2", "b3"],
        trusted=[trust("X")],
    )
    # 穷举应得到 4 棵根树（x1/x2 在两个兄弟位置的笛卡尔积），DFS 分别为
    # r1,x1,x1 / r1,x1,x2 / r1,x2,x1 / r1,x2,x2；它们非源码集合都只有 {b1}
    # （x1/x2 是叶子声明），故只有一棵剪枝后根树，无法成对。
    expected = {
        "status": "fail",
        "error_code": "NO_INDEPENDENT_PAIR",
        "all_dfs_before_pruning": [
            ["r1", "x1", "x1"],
            ["r1", "x1", "x2"],
            ["r1", "x2", "x1"],
            ["r1", "x2", "x2"],
        ],
        "pruned_root_proof_count": 1,
    }
    return case, expected


def all_scenarios() -> list[tuple[dict, dict]]:
    builders = [
        case_a_local_shortest_dead_end,
        case_a2_local_shortest_dead_end_two_layer,
        case_b_bypass_breaks_cycle,
        case_b2_pure_cycle_no_complete_proof,
        case_c_early_cutoff,
        case_c_late_cutoff_pair_destroyed,
        case_c_sequence_cutoff,
        case_d_shared_dependency,
        case_d2_shared_source_allowed,
        case_e_small_set_longer_proof,
        case_f_authorization_boundaries,
        case_g_bad_signature,
        case_h_untrusted_leaf_rejected,
        case_i_sibling_choice_diversity,
        case_j_sibling_same_artifact_different_declarations,
    ]
    return [builder() for builder in builders]


def alias_digest_index() -> dict[str, str]:
    """场景中用到的全部别名 -> 摘要，供 README 生成可读对照表。"""
    aliases = ["R", "X", "Y", "Z", "L", "A", "B", "M"]
    return {alias: digest(alias) for alias in aliases}
