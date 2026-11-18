"""命令行端到端冒烟测试：python -m solution --input ... --output ..."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.scenarios import all_scenarios  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class CliSmokeTests(unittest.TestCase):
    def _run_cli(self, in_path: Path, out_path: Path) -> subprocess.CompletedProcess:
        # -I 隔离模式会忽略 PYTHONPATH 且不导入当前目录；用 -c 先把项目根注入
        # sys.path，再以 runpy 运行 solution 包，保持隔离语义不变。
        launcher = (
            "import sys, runpy; "
            f"sys.path.insert(0, {str(ROOT)!r}); "
            "sys.argv=['solution','--input',%r,'--output',%r]; "
            "runpy.run_module('solution', run_name='__main__')"
            % (str(in_path), str(out_path))
        )
        return subprocess.run(
            [sys.executable, "-I", "-c", launcher],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        )

    def test_cli_batch_run_and_output_file(self):
        tmp_dir = ROOT / ".runtime-tmp" / "cli-smoke"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        in_path = tmp_dir / "cases.json"
        out_path = tmp_dir / "result.json"

        payload = {"cases": [case for case, _ in all_scenarios()]}
        in_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

        proc = self._run_cli(in_path, out_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(data["case_total"], len(payload["cases"]))
        self.assertEqual(
            data["ok_total"] + data["fail_total"], data["case_total"]
        )
        by_id = {r["case_id"]: r for r in data["results"]}
        self.assertEqual(
            by_id["A2_local_shortest_dead_end_two_layer"]["status"], "ok"
        )
        self.assertEqual(
            by_id["B2_pure_cycle_no_complete_proof"]["error_code"],
            "NO_COMPLETE_PROOF",
        )

    def test_cli_invalid_input_exit_code_two(self):
        tmp_dir = ROOT / ".runtime-tmp" / "cli-smoke"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        bad_path = tmp_dir / "bad.json"
        out_path = tmp_dir / "bad-result.json"
        bad_path.write_text("{not json", encoding="utf-8")

        proc = self._run_cli(bad_path, out_path)
        self.assertEqual(proc.returncode, 2)
        data = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(data["error_code"], "INVALID_INPUT")


if __name__ == "__main__":
    unittest.main()
