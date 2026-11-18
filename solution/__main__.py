"""命令行入口：python -m solution --input cases.json --output result.json

输入文件既可以是单个用例对象，也可以是 ``{"cases": [...]}`` 集合。
业务判定失败（NO_COMPLETE_PROOF / NO_INDEPENDENT_PAIR）仍以退出码 0 返回，
结果写入每个用例的 status 字段；只有输入结构类错误才以退出码 2 返回。
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from .errors import ERROR_CODES, VerifierInputError
from .verifier import verify_case


def _load_input(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise VerifierInputError("INVALID_INPUT", f"输入文件不存在: {path}")
    except json.JSONDecodeError as exc:
        raise VerifierInputError("INVALID_INPUT", f"输入不是合法 JSON: {exc}")

    if isinstance(data, dict) and isinstance(data.get("cases"), list):
        return data["cases"]
    if isinstance(data, dict):
        return [data]
    raise VerifierInputError("INVALID_INPUT", "顶层必须是用例对象或含 cases 数组的对象")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="离线 CI 构建产物来源核验器（标准库实现）"
    )
    parser.add_argument("--input", required=True, help="输入 JSON（单用例或 cases 集合）")
    parser.add_argument("--output", help="结果 JSON 输出路径；缺省输出到标准输出")
    args = parser.parse_args(argv)

    try:
        raw_cases = _load_input(args.input)
        if not raw_cases:
            raise VerifierInputError("INVALID_INPUT", "cases 数组为空")
        results = [verify_case(raw) for raw in raw_cases]
    except VerifierInputError as exc:
        payload = {
            "status": "error",
            "error_code": exc.code,
            "error_message": exc.message,
            "error_code_meaning": ERROR_CODES[exc.code],
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        else:
            print(text)
        return 2

    ok = all(r["status"] == "ok" for r in results)
    payload = {
        "generated_at_epoch": int(time.time()),
        "case_total": len(results),
        "ok_total": sum(1 for r in results if r["status"] == "ok"),
        "fail_total": sum(1 for r in results if r["status"] != "ok"),
        "all_ok": ok,
        "results": results,
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(
            f"已处理 {payload['case_total']} 个用例："
            f"成功 {payload['ok_total']}，失败 {payload['fail_total']}，结果写入 {args.output}"
        )
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
