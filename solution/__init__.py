"""离线 CI 构建产物来源核验器。

模块划分：
- errors:   错误码与输入异常
- model:    JSON 数据模型、加载与全量输入校验
- verifier: 声明资格判定、证明树穷举与双独立证明优选

对外入口：``verify_case`` 与命令行 ``python -m solution``。
"""

from .errors import ERROR_CODES, VerifierInputError
from .model import load_case
from .verifier import verify_case

__all__ = ["ERROR_CODES", "VerifierInputError", "load_case", "verify_case"]
