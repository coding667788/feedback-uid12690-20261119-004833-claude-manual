"""错误码定义。

所有错误均以稳定的字符串码对外暴露，README 的“错误码”章节与本表保持一致。
输入结构类问题抛出 :class:`VerifierInputError`；业务判定类失败通过结果中的
``status`` / ``error_code`` 字段表达，不抛异常。
"""

# 输入结构/约束类错误（CLI 以退出码 2 返回）
INVALID_INPUT = "INVALID_INPUT"
UNKNOWN_REFERENCE = "UNKNOWN_REFERENCE"
LIMIT_EXCEEDED = "LIMIT_EXCEEDED"

# 业务判定类错误（结果 status=fail）
NO_COMPLETE_PROOF = "NO_COMPLETE_PROOF"
NO_INDEPENDENT_PAIR = "NO_INDEPENDENT_PAIR"
SEARCH_CAP_EXCEEDED = "SEARCH_CAP_EXCEEDED"

#: 全部对外错误码及中文说明
ERROR_CODES = {
    INVALID_INPUT: "输入 JSON 结构非法或字段取值不合法",
    UNKNOWN_REFERENCE: "声明/撤销引用了未定义的签发者、产物或可信源码",
    LIMIT_EXCEEDED: "单案规模超过 30 产物 / 60 声明 / 12 签发者的约定上限",
    NO_COMPLETE_PROOF: "根产物不存在任何可展开到可信源码的完备证明",
    NO_INDEPENDENT_PAIR: "存在完备证明，但无法组成非源码签发者互斥的独立对",
    SEARCH_CAP_EXCEEDED: "证明穷举规模超过内置安全上限",
}


class VerifierInputError(Exception):
    """输入不满足 schema/引用/规模约束时抛出。"""

    def __init__(self, code: str, message: str):
        if code not in ERROR_CODES:
            raise ValueError(f"未知错误码: {code}")
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
