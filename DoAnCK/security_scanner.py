"""
security_scanner.py
===================
Mô-đun quét bảo mật đầu vào (input fields) theo hướng Signature-based
cho bài Seminar về kiểm thử bảo mật tự động.

Mục tiêu:
- Phát hiện dấu hiệu SQL Injection (SQLi)
- Phát hiện dấu hiệu Cross-site Scripting (XSS)
- Hoạt động an toàn trong môi trường localhost phục vụ giáo dục

Python: 3.10+
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple
from urllib.parse import unquote_plus, urljoin

import requests
from bs4 import BeautifulSoup


@dataclass
class DetectionResult:
    """
    Đại diện cho một kết quả phát hiện bất thường.
    """

    field_name: str
    original_value: str
    normalized_value: str
    attack_type: str  # "SQLi" hoặc "XSS"
    severity: str     # "LOW" | "MEDIUM" | "HIGH"
    matched_rule: str
    reason: str


class SignatureScanner:
    """
    Bộ quét sử dụng chữ ký (regex/signature) để nhận diện payload độc hại.

    Lưu ý:
    - Đây không phải WAF production-grade.
    - Dùng để mô phỏng và minh họa nguyên lý phát hiện theo luật.
    """

    def __init__(self) -> None:
        # --- Bộ quy tắc SQL Injection ---
        # Các regex dưới đây cố ý bắt những mẫu phổ biến trong lab:
        #   ' OR 1=1 --
        #   " OR "1"="1
        #   UNION SELECT ...
        #   DROP TABLE ...
        #   ;-- / # / /*
        self.sqli_rules: List[Tuple[str, str, str, str]] = [
            (
                "SQLI-001",
                r"(?i)(?:'|\")\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
                "HIGH",
                "Mẫu điều kiện luôn đúng kiểu ' OR 1=1",
            ),
            (
                "SQLI-002",
                r"(?i)(?:'|\")\s*or\s+['\"]?[a-z0-9_]+['\"]?\s*=\s*['\"]?[a-z0-9_]+",
                "HIGH",
                "Mẫu so sánh logic bất thường sau toán tử OR",
            ),
            (
                "SQLI-003",
                r"(?i)\bunion\b\s+\bselect\b",
                "HIGH",
                "Phát hiện UNION SELECT thường dùng để trích xuất dữ liệu",
            ),
            (
                "SQLI-004",
                r"(?i)\b(select|insert|update|delete|drop|alter|truncate)\b.+\b(from|into|table)\b",
                "MEDIUM",
                "Chuỗi chứa từ khóa SQL nhạy cảm có cấu trúc đáng ngờ",
            ),
            (
                "SQLI-005",
                r"(?i)(--|#|/\*|\*/|;)\s*$",
                "MEDIUM",
                "Ký tự kết thúc/comment SQL bất thường ở cuối input",
            ),
            (
                "SQLI-006",
                r"(?i)\b(sleep|benchmark)\s*\(",
                "HIGH",
                "Dấu hiệu Time-based SQLi",
            ),
        ]

        # --- Bộ quy tắc XSS ---
        self.xss_rules: List[Tuple[str, str, str, str]] = [
            (
                "XSS-001",
                r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>",
                "HIGH",
                "Thẻ <script> trực tiếp",
            ),
            (
                "XSS-002",
                r"(?i)on\w+\s*=\s*['\"].*?['\"]",
                "HIGH",
                "Event handler inline (onclick, onerror, onload...)",
            ),
            (
                "XSS-003",
                r"(?i)javascript\s*:",
                "HIGH",
                "URI scheme javascript: có thể thực thi mã",
            ),
            (
                "XSS-004",
                r"(?i)<\s*(img|svg|iframe|object|embed)[^>]*>",
                "MEDIUM",
                "Tag HTML dễ bị lạm dụng để chèn mã",
            ),
            (
                "XSS-005",
                r"(?i)alert\s*\(",
                "LOW",
                "Payload demo phổ biến chứa alert()",
            ),
        ]

        # Thông điệp lỗi DB để phát hiện phản hồi bất thường khi fuzz input.
        self.db_error_signatures = [
            "sqlite error",
            "sql syntax",
            "unrecognized token",
            "operationalerror",
            "warning: mysql",
            "postgresql",
        ]

    @staticmethod
    def normalize_input(value: str) -> str:
        """
        Chuẩn hóa input trước khi quét:
        - URL decode (%27 -> ')
        - Hạ chữ thường
        - Loại khoảng trắng thừa
        """
        decoded = unquote_plus(value)
        lowered = decoded.lower()
        # Gom nhiều khoảng trắng liên tiếp thành 1 khoảng trắng để regex ổn định hơn.
        compact = re.sub(r"\s+", " ", lowered).strip()
        return compact

    def scan_value(self, field_name: str, value: str) -> List[DetectionResult]:
        """
        Quét một giá trị input đơn lẻ.
        """
        findings: List[DetectionResult] = []
        normalized = self.normalize_input(value)

        # Quét SQLi signatures
        for rule_id, pattern, severity, reason in self.sqli_rules:
            if re.search(pattern, normalized):
                findings.append(
                    DetectionResult(
                        field_name=field_name,
                        original_value=value,
                        normalized_value=normalized,
                        attack_type="SQLi",
                        severity=severity,
                        matched_rule=rule_id,
                        reason=reason,
                    )
                )

        # Quét XSS signatures
        for rule_id, pattern, severity, reason in self.xss_rules:
            if re.search(pattern, normalized):
                findings.append(
                    DetectionResult(
                        field_name=field_name,
                        original_value=value,
                        normalized_value=normalized,
                        attack_type="XSS",
                        severity=severity,
                        matched_rule=rule_id,
                        reason=reason,
                    )
                )

        return findings

    def scan_payload_dict(self, payload: Dict[str, str]) -> List[DetectionResult]:
        """
        Quét toàn bộ cặp {field_name: value}.
        """
        results: List[DetectionResult] = []
        for field_name, value in payload.items():
            if not isinstance(value, str):
                continue
            results.extend(self.scan_value(field_name, value))
        return results

    def discover_forms(self, target_url: str, timeout: int = 8) -> List[Dict]:
        """
        Tự động lấy danh sách form + input fields từ website.
        Dùng cho mô phỏng scanner quét bề mặt tấn công.
        """
        response = requests.get(target_url, timeout=timeout)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        discovered: List[Dict] = []

        for form in soup.find_all("form"):
            action = form.get("action", "").strip()
            method = form.get("method", "get").lower().strip()
            full_action = urljoin(target_url, action) if action else target_url

            input_names: List[str] = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if name:
                    input_names.append(name)

            discovered.append(
                {
                    "action": full_action,
                    "method": method,
                    "inputs": input_names,
                }
            )
        return discovered

    def scan_form_endpoint(
        self,
        action_url: str,
        method: str,
        input_names: List[str],
        test_payload: str,
        timeout: int = 8,
    ) -> Dict:
        """
        Gửi payload test vào tất cả input của một form rồi đánh giá:
        - Scanner signature có bắt được payload không?
        - Response có phản hồi lỗi SQL không?
        - Response có reflect payload XSS không?
        """
        data = {name: test_payload for name in input_names}
        input_findings = self.scan_payload_dict(data)

        if method == "post":
            resp = requests.post(action_url, data=data, timeout=timeout)
        else:
            resp = requests.get(action_url, params=data, timeout=timeout)

        body_lower = resp.text.lower()
        db_error_hit = any(err in body_lower for err in self.db_error_signatures)
        reflected = test_payload.lower() in body_lower

        return {
            "target": action_url,
            "method": method.upper(),
            "payload": test_payload,
            "status_code": resp.status_code,
            "scanner_findings": [asdict(f) for f in input_findings],
            "response_signals": {
                "db_error_hint": db_error_hit,
                "payload_reflected": reflected,
            },
        }


def print_findings(results: List[DetectionResult]) -> None:
    """
    In kết quả thân thiện cho demo seminar.
    """
    if not results:
        print("[-] Không phát hiện dấu hiệu SQLi/XSS trong payload đã cung cấp.")
        return

    print(f"[!] Phát hiện {len(results)} dấu hiệu đáng ngờ:")
    for idx, item in enumerate(results, start=1):
        print(f"\n  #{idx}")
        print(f"   - Field       : {item.field_name}")
        print(f"   - Attack type : {item.attack_type}")
        print(f"   - Severity    : {item.severity}")
        print(f"   - Rule        : {item.matched_rule}")
        print(f"   - Reason      : {item.reason}")
        print(f"   - Input       : {item.original_value}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Security Scanner (Signature-based) cho Seminar SQLi/XSS"
    )
    parser.add_argument(
        "--value",
        help="Chuỗi input đơn lẻ cần quét. Ví dụ: \"' OR 1=1 --\"",
        default="",
    )
    parser.add_argument(
        "--field",
        help="Tên field tương ứng khi dùng --value",
        default="q",
    )
    parser.add_argument(
        "--json-payload",
        help="Payload dạng JSON object. Ví dụ: '{\"q\":\"\\' OR 1=1 --\"}'",
        default="",
    )
    parser.add_argument(
        "--url",
        help="URL cần khám phá form để quét tự động (khuyến nghị localhost).",
        default="",
    )
    parser.add_argument(
        "--test-payload",
        help="Payload dùng khi quét form endpoint.",
        default="' OR 1=1 --",
    )
    return parser


def main() -> None:
    scanner = SignatureScanner()
    parser = build_arg_parser()
    args = parser.parse_args()

    # Chế độ 1: Quét một chuỗi đơn lẻ
    if args.value:
        findings = scanner.scan_value(args.field, args.value)
        print_findings(findings)
        return

    # Chế độ 2: Quét JSON payload gồm nhiều field
    if args.json_payload:
        try:
            payload = json.loads(args.json_payload)
            if not isinstance(payload, dict):
                raise ValueError("JSON payload phải là object.")
        except Exception as exc:
            print(f"[x] JSON không hợp lệ: {exc}")
            return

        findings = scanner.scan_payload_dict(payload)
        print_findings(findings)
        return

    # Chế độ 3: Quét form trên website
    if args.url:
        print(f"[*] Discovering forms from: {args.url}")
        forms = scanner.discover_forms(args.url)
        if not forms:
            print("[-] Không tìm thấy form nào để quét.")
            return

        print(f"[+] Tìm thấy {len(forms)} form.")
        for idx, form in enumerate(forms, start=1):
            print(
                f"\n[{idx}] {form['method'].upper()} {form['action']} | inputs={form['inputs']}"
            )
            if not form["inputs"]:
                print("    -> Bỏ qua vì form không có input name.")
                continue

            report = scanner.scan_form_endpoint(
                action_url=form["action"],
                method=form["method"],
                input_names=form["inputs"],
                test_payload=args.test_payload,
            )
            print(
                f"    -> status={report['status_code']}, "
                f"findings={len(report['scanner_findings'])}, "
                f"db_error_hint={report['response_signals']['db_error_hint']}, "
                f"payload_reflected={report['response_signals']['payload_reflected']}"
            )
        return

    # Mặc định: chạy demo nhanh với payload mẫu seminar
    print("[*] Demo mặc định với payload SQLi/XSS phổ biến")
    demo_payload = {
        "search": "' OR 1=1 --",
        "comment": "<script>alert('XSS')</script>",
    }
    findings = scanner.scan_payload_dict(demo_payload)
    print_findings(findings)


if __name__ == "__main__":
    main()
