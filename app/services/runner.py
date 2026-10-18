import json
import shutil
import subprocess
from pathlib import Path

TIMEOUT_SECONDS = 120


def _is_semgrep_report(data):
    return isinstance(data, dict) and "results" in data


def _is_gitleaks_report(data):
    return isinstance(data, list)


def run_scanners(target_dir, output_dir):
    """Run Semgrep and Gitleaks on target_dir. Returns a result dict per tool."""
    target = Path(target_dir).resolve()
    out = Path(output_dir).resolve()

    if not target.is_dir():
        raise NotADirectoryError(f"Scan target is not a directory: {target}")
    out.mkdir(parents=True, exist_ok=True)

    semgrep_report = out / "semgrep_report.json"
    gitleaks_report = out / "gitleaks_report.json"

    # Delete old reports so a stale file can never pass as a fresh scan.
    for report in (semgrep_report, gitleaks_report):
        report.unlink(missing_ok=True)

    tools = {
        "semgrep": {
            "report": semgrep_report,
            "valid": _is_semgrep_report,
            "command": [
                "semgrep", "--config", "p/python", "--json",
                "-o", str(semgrep_report), str(target),
            ],
        },
        "gitleaks": {
            "report": gitleaks_report,
            "valid": _is_gitleaks_report,
            "command": [
                "gitleaks", "dir", str(target),
                "--report-format", "json",
                "--report-path", str(gitleaks_report),
            ],
        },
    }

    results = {}
    for name, tool in tools.items():
        report_path = tool["report"]

        if shutil.which(name) is None:
            results[name] = {"success": False, "error": f"{name} is not installed or not on PATH"}
            continue

        try:
            # List form, no shell=True: the path can't be used to inject commands.
            completed = subprocess.run(
                tool["command"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=TIMEOUT_SECONDS,
                check=False,
            )

            # A nonzero exit code can simply mean "findings detected"
            # (Gitleaks does this), so trust the report, not the exit code.
            if not report_path.exists():
                results[name] = {
                    "success": False,
                    "exit_code": completed.returncode,
                    "error": completed.stderr.strip() or "No report was produced",
                }
                continue

            with report_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            if not tool["valid"](data):
                results[name] = {"success": False, "error": "Report has an unexpected format"}
                continue

            results[name] = {
                "success": True,
                "exit_code": completed.returncode,
                "report_path": str(report_path),
            }

        except subprocess.TimeoutExpired:
            results[name] = {"success": False, "error": f"Timed out after {TIMEOUT_SECONDS}s"}
        except (OSError, json.JSONDecodeError) as exc:
            results[name] = {"success": False, "error": str(exc)}

    return results