"""
remediation.py
==============
Mô-đun "phòng thủ" cho Seminar: chuẩn hóa / làm sạch dữ liệu đầu vào
và cung cấp truy vấn SQL an toàn (parameterized) để vá SQL Injection.

Lưu ý giáo dục:
- Các hàm dưới đây minh họa nguyên tắc OWASP (input validation, output encoding,
  parameterized queries).
- Chỉ dùng trong môi trường lab localhost.
"""

from __future__ import annotations

import html
import re
from typing import Any, List, Tuple


def sanitize_user_comment(text: str) -> str:
    """
    Giảm thiểu Stored XSS: biến ký tự HTML thành thực thể (entity).
    Ví dụ: <script> -> &lt;script&gt; → trình duyệt hiển thị chuỗi, không thực thi.

    Tham khảo: OWASP - Output Encoding.
    """
    if text is None:
        return ""
    # strip() loại khoảng trắng đầu/cuối; quote=True mã hóa cả dấu nháy.
    return html.escape(text.strip(), quote=True)


def strip_null_bytes(text: str) -> str:
    """
    Một số payload chèn \\x00 để đánh lừa bộ lọc; loại bỏ byte null.
    """
    if not text:
        return ""
    return text.replace("\x00", "")


def normalize_search_query(raw: str) -> str:
    """
    Chuẩn hóa nhẹ cho ô tìm kiếm (không thay thế parameterized query).
    Giới hạn độ dài để tránh abuse trong lab.
    """
    s = strip_null_bytes(raw or "")
    s = s.strip()
    # Giới hạn độ dài hợp lý cho demo
    if len(s) > 200:
        s = s[:200]
    return s


def search_products_parameterized(
    cursor: Any, query: str
) -> List[Tuple[Any, ...]]:
    """
    Tìm kiếm sản phẩm an toàn: toàn bộ dữ liệu người dùng đưa vào placeholder '?'.
    Cách này ngăn kẻ tấn công "thoát" khỏi chuỗi SQL bằng dấu nháy.

    Lưu ý: sqlite3.Cursor.execute với tuple tham số = prepared statement.
    """
    q = normalize_search_query(query)
    like = f"%{q}%"
    cursor.execute(
        """
        SELECT id, name, price
        FROM products
        WHERE name LIKE ? COLLATE NOCASE
           OR description LIKE ? COLLATE NOCASE
        """,
        (like, like),
    )
    return cursor.fetchall()


# --- Bộ lọc bổ sung (defense-in-depth, signature đơn giản) ---

_SQLI_FRAGMENT = re.compile(
    r"(?i)(?:--|#|/\*|\*/|;|'|\"|\bor\b\s+\d+\s*=\s*\d+|\bunion\b\s+\bselect\b)"
)


def looks_like_sqli_payload(text: str) -> bool:
    """
    Heuristic nhanh (không thay WAF): trả về True nếu chuỗi có mảnh SQL đáng ngờ.
    Có thể dùng để chặn / log trong lab sau khi quét.
    """
    if not text:
        return False
    return bool(_SQLI_FRAGMENT.search(text))


_XSS_FRAGMENT = re.compile(
    r"(?i)(<\s*script|</\s*script|on\w+\s*=|javascript\s*:|<\s*iframe)"
)


def looks_like_xss_payload(text: str) -> bool:
    """
    Heuristic nhanh cho XSS — chủ yếu phục vụ log/cảnh báo trong seminar.
    """
    if not text:
        return False
    return bool(_XSS_FRAGMENT.search(text))
