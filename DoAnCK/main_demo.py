"""
main_demo.py
============
Điều phối toàn bộ luồng Seminar (localhost):

1) (Tuỳ chọn) Xóa CSDL cũ để demo sạch (--fresh)
2) Khởi động Flask ở chế độ DỄ BỊ TẤN CÔNG (SHOP_SECURE=0)
3) Chạy exploit_lab (SQLi + XSS + bypass login)
4) Chạy security_scanner (signature) trên payload mẫu
5) Dừng server, khởi động lại ở chế độ ĐÃ VÁ (SHOP_SECURE=1)
6) Kiểm tra lại: exploit không còn hiệu quả / XSS được escape khi hiển thị

Python: 3.10+
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

# Windows console thường dùng cp1252 — ép UTF-8 để in tiếng Việt khi chạy demo.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from exploit_lab import (
    ExploitReport,
    exploit_stored_xss,
    run_all_attacks,
    verify_sqli_mitigated,
    verify_xss_mitigated_display,
)
from security_scanner import SignatureScanner

ROOT = Path(__file__).resolve().parent
APP_PATH = ROOT / "app.py"
DB_PATH = ROOT / "shop.db"


def wait_for_server(base_url: str, timeout: float = 30.0) -> bool:
    """Chờ HTTP 200 từ trang chủ."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{base_url.rstrip('/')}/", timeout=2)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.25)
    return False


def start_flask_subprocess(*, secure: bool, port: int) -> subprocess.Popen:
    """
    Spawn tiến trình Flask riêng để có thể đổi biến môi trường SHOP_SECURE giữa các pha.
    """
    env = os.environ.copy()
    env["SHOP_SECURE"] = "1" if secure else "0"
    env["PORT"] = str(port)
    # Windows: không dùng preexec fork; Popen đủ.
    return subprocess.Popen(
        [sys.executable, str(APP_PATH)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop_process(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def print_report(title: str, reports: list[ExploitReport]) -> None:
    print(f"\n=== {title} ===")
    for rep in reports:
        status = "OK" if rep.ok else "FAIL"
        print(f"[{status}] {rep.name}: {rep.detail}")
        if rep.extra:
            # In ngắn gọn để không tràn terminal seminar.
            keys = list(rep.extra.keys())
            print(f"      extra keys: {keys}")


def run_scanner_demo(base_url: str) -> None:
    """
    Demo signature-based scanner: quét payload trước khi gửi lên server.
    """
    print("\n=== Signature Scanner (payload tĩnh) ===")
    scanner = SignatureScanner()
    demo_payload = {
        "q": "' OR 1=1 --",
        "comment": "<script>alert('XSS')</script>",
    }
    findings = scanner.scan_payload_dict(demo_payload)
    print(f"Số cảnh báo: {len(findings)}")
    for f in findings:
        print(f"  - [{f.attack_type}/{f.severity}] {f.matched_rule}: {f.reason} (field={f.field_name})")

    # Quét thực tế form trên trang chủ (gửi thử payload — chỉ lab).
    print("\n=== Signature Scanner (probe form /search) ===")
    try:
        forms = scanner.discover_forms(f"{base_url.rstrip('/')}/")
        print(f"Số form phát hiện: {len(forms)}")
        for i, form in enumerate(forms, start=1):
            print(f"  Form {i}: {form['method'].upper()} {form['action']} inputs={form['inputs']}")
    except requests.RequestException as exc:
        print(f"Không discover được form: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seminar demo: attack → scan → remediate → verify")
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Xóa shop.db trước khi chạy để dữ liệu lab đồng nhất.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "5000")),
        help="Cổng Flask (mặc định 5000).",
    )
    args = parser.parse_args()

    if args.fresh and DB_PATH.exists():
        DB_PATH.unlink()
        print("[*] Đã xóa CSDL cũ (shop.db) để demo sạch.")

    base_url = f"http://127.0.0.1:{args.port}"
    proc: subprocess.Popen | None = None

    print("\n" + "=" * 60)
    print("PHA 1 — Server DỄ BỊ TẤN CÔNG (SHOP_SECURE=0)")
    print("=" * 60)
    proc = start_flask_subprocess(secure=False, port=args.port)
    if not wait_for_server(base_url):
        print("[x] Không khởi động được server — kiểm tra cổng hoặc firewall.")
        stop_process(proc)
        return 1

    attacks = run_all_attacks(base_url)
    print_report("Kết quả tấn công (kỳ vọng: hầu hết OK)", attacks)

    run_scanner_demo(base_url)

    print("\n" + "=" * 60)
    print("PHA 2 — Khởi động lại với BẢO VỆ (SHOP_SECURE=1)")
    print("=" * 60)
    stop_process(proc)
    proc = None
    time.sleep(0.5)

    proc = start_flask_subprocess(secure=True, port=args.port)
    if not wait_for_server(base_url):
        print("[x] Không khởi động lại được server sau khi vá.")
        stop_process(proc)
        return 1

    # Gửi lại payload: lưu ý sau khi vá, comment mới sẽ bị escape trước khi lưu DB.
    sess = requests.Session()
    post_xss = exploit_stored_xss(
        base_url, product_id=1, session=sess, expect_raw_script=False
    )
    verify_sql = verify_sqli_mitigated(base_url, session=sess)
    verify_xss = verify_xss_mitigated_display(base_url, product_id=1, session=sess)

    print_report(
        "Kiểm tra sau khi vá (kỳ vọng: SQLi mitigated OK; XSS display OK)",
        [verify_sql, verify_xss, post_xss],
    )

    stop_process(proc)
    print("\n[+] Hoàn tất demo. Đã dừng server Flask.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
