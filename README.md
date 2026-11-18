# 离线 CI 构建产物来源核验器

为离线（无网络、无第三方依赖）CI 环境实现的构建产物**来源证明核验器**。给定一组
构建声明、授权窗口、历史撤销与外部预置可信源码，判断某根产物能否展开出两份
**相互独立**的完备来源证明，并在所有可行方案中选出声明出现次数最少、规范 DFS
序列字典序最小的那一对。

- 运行环境：Windows 原生 Python 3.12，仅标准库、仅 CPU、完全离线
- 单案规模上限：**30 个产物、60 条声明、12 个签发者**
- 无随机性：用例与期望值全部确定性生成，可重复重放

---

## 1. 目录结构

```
.
├── solution/                # 被测实现（仅标准库）
│   ├── __init__.py          # 对外入口
│   ├── __main__.py          # python -m solution 命令行
│   ├── errors.py            # 错误码与输入异常
│   ├── model.py             # 数据模型、JSON 加载与全量输入校验
│   └── verifier.py          # 资格判定、证明穷举、双独立证明优选
├── tests/                   # 自动化测试（unittest）
│   ├── builders.py          # 用例构造工具（别名 -> 真实 SHA-256）
│   ├── scenarios.py         # 15 个手工场景 + 人工推导期望值
│   ├── oracle.py            # 独立穷举判定器（不 import solution.*）
│   ├── fuzzgen.py           # 固定种子随机小图生成器
│   ├── test_scenarios.py    # 规范场景：人工期望 + oracle 双断言
│   ├── test_oracle_equivalence.py
│   ├── test_validation.py   # 输入结构/引用/规模/错误码
│   └── test_cli.py          # 命令行端到端
├── tools/
│   ├── generate_cases.py    # 重新生成 cases.json
│   └── bruteforce_check.py  # 第二种独立暴力实现的最优性交叉核对
├── cases.json               # 可重放输入（15 个用例）
└── result.json              # 运行 python -m solution 的产出（已附样例）
```

---

## 2. 快速开始

```bash
# 核验（输入支持单用例对象，或 {"cases": [...]} 集合）
python -m solution --input cases.json --output result.json

# 自动化测试
python -m unittest discover -s tests -v

# 重新生成 cases.json（内容与测试场景完全一致，无随机源）
python -I tools/generate_cases.py

# 第二种独立暴力实现的最优性交叉核对（可选）
python -I tools/bruteforce_check.py
```

`python -m solution` 的退出码：

| 退出码 | 含义 |
| --- | --- |
| 0 | 输入合法；每个用例的成败见结果中的 `status`（业务失败不算进程失败） |
| 2 | 输入结构/引用/规模类错误，结果体含 `error_code` |

---

## 3. 输入结构（cases.json）

顶层为 `{"cases": [ <用例>, ... ]}`，单用例也可直接传一个用例对象。所有时间均为
**非负整数纪元秒**，所有时间窗口语义为**左闭右开 `[not_before, not_after)`**。

```json
{
  "case_id": "string",
  "limits": { "max_artifacts": 30, "max_declarations": 60, "max_issuers": 12 },
  "issuers": [ { "id": "b1" } ],
  "authorizations": [
    { "issuer": "b1", "repo": "ci", "not_before": 0, "not_after": 10000 }
  ],
  "trusted_sources": [
    { "repo": "ci/L", "commit": "c1",
      "digest": "<64 位小写十六进制 SHA-256，源码快照自身摘要>" }
  ],
  "declarations": [
    {
      "id": "d1",
      "artifact_digest": "<产物 SHA-256>",
      "builder": "b1",
      "issued_at": 100,
      "source": { "repo": "ci/R", "commit": "c1" },
      "dependency_summary": "sum-R-d1",
      "dependencies": [
        { "digest": "<被依赖产物 SHA-256>", "dep_summary": "pin 摘要，规范排序键" }
      ],
      "signature_valid": true
    }
  ],
  "revocations": [
    {
      "id": "rv1",
      "declaration_id": "d9",
      "occurred_at": 500,
      "sequence": 1,
      "trace_issued_at": 90
    }
  ],
  "query": {
    "root_artifact": "<根产物 SHA-256>",
    "audit_cutoff": 600,
    "cutoff_sequence": null
  }
}
```

### 3.1 字段语义与规则

- **产物身份**：64 位小写十六进制 SHA-256。测试用短别名（R/A/…）经
  `sha256("artifact:"+别名)` 确定性派生，便于人工阅读。
- **声明（attestation）**：绑定产物摘要、构建者（签发者）、签发时间、源码位置
  `(repo, commit)`、依赖摘要、依赖锚点列表与模拟验签结果。
- **依赖取交集语义**：一条声明的每个依赖都必须能在当前祖先集合下选出**至少一份**
  完备证明；同一依赖存在多份证明时任选其一即可（笛卡尔积枚举全部组合）。同一产物
  可作为不同兄弟依赖重复出现（用不同 `dep_summary` 区分），从而在两个兄弟分支选用
  不同声明；仅当 `(digest, dep_summary)` 锚点完全重复时才判 `INVALID_INPUT`。
- **授权匹配**：声明合格要求存在一条授权，满足
  1. `issuer == declaration.builder`；
  2. 授权 `repo` 切分出的段序列是声明 `source.repo` 段序列的**前缀**
     （段前缀匹配，例如授权 `ci` 覆盖 `ci/R`、`ci/R/sub`，不覆盖 `vendor/R`）；
  3. `not_before <= issued_at < not_after`（左闭右开，端点 `not_after` 失配）。
- **可信源码叶子**：没有依赖的声明称为**叶子声明**，其 `(repo, commit)` 必须命中
  外部预置 `trusted_sources` 中的某一项，否则不能作为叶子。**只有外部预置的可信
  源码可作叶子**。可信源码的 `digest` 是源码快照自身摘要，与构建产物摘要属于不同
  身份空间，二者数值相同也不冲突。
- **撤销**：每条撤销带 `occurred_at`（发生时间）与全局唯一 `sequence`（录入序号），
  并通过 `trace_issued_at` **追溯到被撤声明的真实签发时间**；输入校验要求二者相等，
  否则报 `INVALID_INPUT`。
- **审计截点**：撤销仅当 `occurred_at <= audit_cutoff` 且
  （`cutoff_sequence` 为 null 或 `sequence <= cutoff_sequence`）时对本次查询可见。
  改变截点会改变可见撤销集合，从而改变历史查询结论。

### 3.2 证明展开树的计数约定

- 每个**声明节点**对应一条声明的一次出现。叶子声明（无依赖）也是声明节点：
  **计入声明出现次数、进入规范 DFS 序列**。
- 叶子声明之下再挂一个**可信源码叶子**。可信源码不是声明：
  **不计出现次数、不进入 DFS 序列**。
- **非源码签发者集合**只收集“有依赖的非叶子声明”的构建者；叶子声明的构建者视为
  源码签发者，不参与互斥判定（两个分支共用源码不破坏独立性）。
- 沿任一依赖路径重复出现同一产物即构成**循环**，该展开无效；不同兄弟分支允许重复
  同一产物（共享子图），同一产物在不同兄弟分支也可选用不同声明。

### 3.3 双独立证明与优选

根产物需要**两份**可展开证明，且二者的**非源码签发者集合互斥**（两个分支可共用
源码）。优选规则按顺序为：

1. **最小化两棵展开树的声明出现次数合计**；
2. 合计相同则比较规范 DFS 的声明 ID 序列：依赖按 `(dep_summary, digest)` 排序，
   两棵树先各自按 DFS 字典序归一，再按
   `(总次数, 第一棵 DFS, 第二棵 DFS)` 字典序取最小。

签发者集合的大小**不参与排序**，只用于互斥可行性判断。穷举时对每个
`(出现次数, 非源码签发者集合)` 分组只保留 DFS 最小的树（无损剪枝，理由见
`solution/verifier.py` 的 `_prune`）。

---

## 4. 错误码

| 错误码 | 类别 | 触发条件 |
| --- | --- | --- |
| `INVALID_INPUT` | 输入错误（退出码 2） | JSON 结构非法、字段类型/取值非法、重复 ID、仓库空段、撤销追溯时间与声明签发时间不一致等 |
| `UNKNOWN_REFERENCE` | 输入错误（退出码 2） | 授权/声明引用未定义签发者、撤销指向未定义声明、查询根产物无任何声明 |
| `LIMIT_EXCEEDED` | 输入错误（退出码 2） | 产物 >30、声明 >60 或签发者 >12（可用 `limits` 收紧） |
| `NO_COMPLETE_PROOF` | 业务失败（退出码 0） | 根产物不存在任何能展开到可信源码的完备证明（含纯循环、叶子不可信、验签全失败等） |
| `NO_INDEPENDENT_PAIR` | 业务失败（退出码 0） | 存在完备证明，但任意两份的非源码签发者集合都不互斥 |
| `SEARCH_CAP_EXCEEDED` | 业务失败（退出码 0） | 穷举构造节点数超过内置安全上限 200000（题目规模下不会触及） |

---

## 5. 输出结构（result.json）

顶层汇总 `case_total / ok_total / fail_total / all_ok`，`results[]` 每个元素：

- 成功：`status="ok"`，含 `selected`（两棵树的嵌套 JSON）、`optimization`
  （总出现次数、各树次数、规范 DFS 序列）与 `review`（可复核计数）。
- 失败：`status="fail"`、`error_code`、`message` 与 `review`。

`review` 中的可复核计数包括：规模上限与实际产物/声明/签发者/可信源码数量、
合格声明 ID 与逐条不合格原因、撤销总数与截点内可见撤销（含追溯签发时间）、
剪枝后根证明数量、穷举构造的树节点数、每棵根证明的（次数, 非源码签发者, DFS）。

树节点 JSON：

```json
{
  "kind": "node",
  "declaration_id": "d1",
  "builder": "b1",
  "artifact_digest": "…",
  "declaration_occurrences_in_subtree": 3,
  "non_source_issuers_in_subtree": ["b1"],
  "canonical_dfs": ["d1", "x1", "l1"],
  "children": [
    { "kind": "leaf",
      "trusted_source": { "repo": "ci/L", "commit": "c1" },
      "artifact_digest": "…" }
  ]
}
```

---

## 6. 边界示例与场景索引（cases.json）

| case_id | 考点 | 期望结论 |
| --- | --- | --- |
| `A_local_shortest_dead_end` | 多备选举证与 DFS 归一 | ok，合计 6 |
| `A2_local_shortest_dead_end_two_layer` | **局部最短组合无解，改选更长路径后成功**（短树共享非叶子依赖 bk） | ok，合计 7（短树 3 + 长树 4） |
| `B_bypass_breaks_cycle` | **旁路声明打破 R→A→B→A 循环** | ok，合计 4 |
| `B2_pure_cycle_no_complete_proof` | 无旁路纯循环 | `NO_COMPLETE_PROOF` |
| `C1_revocation_early_cutoff_pair_exists` | 撤销发生在截点之后不可见 | ok，合计 6 |
| `C2_revocation_late_cutoff_pair_destroyed` | **撤销追溯改变历史截点查询，配对被破坏** | `NO_INDEPENDENT_PAIR` |
| `C3_revocation_sequence_cutoff` | 同发生时间、录入序号截点过滤 | ok，仅 rv1 可见，合计 6 |
| `D_shared_dependency_not_double_counted` | **共享依赖是真实共享，不能伪造独立性** | `NO_INDEPENDENT_PAIR` |
| `D2_shared_trusted_source_allowed` | 两个分支共用可信源码叶子允许 | ok，合计 4 |
| `E_small_set_but_longer_proof` | **对签发者集合较小却较长的备选证明正确判断**（集合大小不参与排序） | ok，合计 8 |
| `F_authorization_boundaries` | 左闭右开端点 + 仓库段前缀失配 | 仅 r1 合格，`NO_INDEPENDENT_PAIR` |
| `G_bad_signature_blocks_leaves` | 模拟验签失败导致无法闭合 | `NO_COMPLETE_PROOF` |
| `H_untrusted_leaf_rejected` | 无外部预置可信源码则叶子无效 | `NO_COMPLETE_PROOF` |
| `I_sibling_choice_diversity` | 兄弟分支各自独立选声明，单树无法成对 | `NO_INDEPENDENT_PAIR` |
| `J_sibling_same_artifact_different_declarations` | 同一产物在两个兄弟分支选不同声明（穷举 4 组合、剪枝合一） | `NO_INDEPENDENT_PAIR`（仅 1 棵根树） |

### 边界要点

- **左闭右开**：`issued_at == not_after` 时授权失配（见 `F` 的 r2）。
- **段前缀**：授权 `ci` 不覆盖 `vendor/R`（见 `F` 的 r3）。
- **循环与共享的区别**：同一路径重复产物无效；不同兄弟分支重复产物合法。
- **可信源码不计声明次数**：叶子声明计 1 次，其下可信源码叶子计 0 次。
- **撤销双维度可见性**：时间截点 + 录入序号截点同时生效（见 C3）。

---

## 7. 期望值的独立性说明（测试不从实现反推）

测试期望值来自两条相互独立的路径，被测实现的输出从不作为期望值来源：

1. **人工推导**：`tests/scenarios.py` 每个场景的 docstring 与 `expected` 字典记录了
   小图上的人工枚举过程（哪些根证明存在、各自代价与签发者集合、为何唯一互斥对成立）。
2. **独立判定器**：`tests/oracle.py` 不 import `solution` 任何模块，按题目规范重新
   实现资格判定、**无剪枝全量穷举**与最优对选择；`tools/bruteforce_check.py` 再用
   第三种写法（路径展开 + 笛卡尔积重组）复核最优代价与 DFS。
3. **随机等价**：`tests/fuzzgen.py` 用固定种子生成 30 个随机小图，逐图比对被测实现
   与独立 oracle 的状态、最优代价、DFS 序列及根证明全集；另做过 300 个种子的离线
   扫描，零分歧。

---

## 8. 实测结果（本机，Windows 11 + Python 3.12.8，仅 CPU）

```
$ python -m unittest discover -s tests -v
...
Ran 31 tests in 0.25s
OK
```

31 个测试方法覆盖：15 个规范场景（含人工期望 + oracle 双断言）、30 种子随机等价、
13 项输入校验/错误码、2 项 CLI 端到端。

```
$ python -m solution --input cases.json --output result.json
已处理 15 个用例：成功 7，失败 8，结果写入 result.json
```

```
$ python -I tools/bruteforce_check.py
（15 个场景）最优一致 / 失败结论一致，全部一致
```

性能（近规模上限的合成压力用例，29 产物 / 57 声明 / 12 签发者，双层候选）：
端到端约 **58 ms**，穷举构造 12250 个树节点、剪枝后 322 棵根证明，远低于
200000 的安全上限。

---

## 9. 设计取舍

- **memo 键含祖先集合**：循环防护要求“当前依赖路径上的产物集合”参与缓存键，
  `(digest, frozenset(ancestors))` 在 30 产物规模下状态数有限，实测内存与耗时可控。
- **组内无损剪枝**：同 `(代价, 非源码签发者集合)` 只留 DFS 最小树，被剪枝树在任何
  上层组合中都不可能更优或改变互斥结论，因此不损失全局最优性；已由独立暴力实现与
  300 种子随机扫描验证。
- **业务失败与输入错误分离**：结构问题抛异常/退出码 2，证明层面的失败走结果字段，
  便于 CI 在一次批处理中收集多个用例的结论。
