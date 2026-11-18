"""生成可重放的 cases.json（无随机性：全部来自 tests/scenarios.py 的固定场景）。

用法（在项目根目录）：
    python tools/generate_cases.py
输出：cases.json，内容为 {"cases": [...]}，与测试使用的场景完全一致。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.scenarios import all_scenarios  # noqa: E402


def main() -> int:
    cases = [case for case, _expected in all_scenarios()]
    out = ROOT / "cases.json"
    out.write_text(
        json.dumps({"cases": cases}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"已写出 {len(cases)} 个用例到 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
