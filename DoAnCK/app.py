"""
app.py
======
Ứng dụng web bán hàng demo (Flask + SQLite) cho Seminar kiểm thử bảo mật.

Cố tình yếu (chỉ localhost / giáo dục):
- SQL Injection: tham số tìm kiếm nối chuỗi trực tiếp vào câu lệnh SQL.
- Stored XSS: bình luận được lưu và hiển thị bằng filter `|safe` khi chế độ không vá.

Biến môi trường:
- SHOP_SECURE=1 : bật parameterized query + escape HTML (xem remediation.py).
- PORT : cổng lắng nghe (mặc định 5000).

Python: 3.10+
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for

from remediation import sanitize_user_comment, search_products_parameterized

# Đường dẫn CSDL trong thư mục dự án (dễ xóa khi reset lab)
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "shop.db"


def _is_secure_mode() -> bool:
    return os.environ.get("SHOP_SECURE", "0").strip().lower() in ("1", "true", "yes", "on")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    return conn


def init_database() -> None:
    """
    Khởi tạo bảng và dữ liệu mẫu (chạy idempotent).
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        """
    )
    cur.execute("SELECT COUNT(*) FROM products")
    if cur.fetchone()[0] == 0:
        demo_products = [
            ("Laptop ABC", 18_990_000, "Laptop văn phòng, phục vụ demo lab."),
            ("Điện thoại XYZ", 8_500_000, "Smartphone tầm trung."),
            ("Sách Python Security", 199_000, "Tài liệu tham khảo seminar."),
        ]
        cur.executemany(
            "INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
            demo_products,
        )
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [
                ("admin", "admin123"),
                ("user1", "pass1"),
            ],
        )
    cur.execute("SELECT COUNT(*) FROM comments")
    if cur.fetchone()[0] == 0:
        cur.execute(
            """
            INSERT INTO comments (product_id, username, body)
            VALUES (1, 'mod', 'Chào mừng đến với cửa hàng demo (bình luận hợp lệ).')
            """
        )
    conn.commit()
    conn.close()


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get(
        "FLASK_SECRET_KEY", "seminar-lab-secret-key-do-not-use-in-production"
    )
    app.config["SECURE_MODE"] = _is_secure_mode()

    init_database()

    @app.get("/")
    def index():
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, price FROM products ORDER BY id"
        )
        rows = cur.fetchall()
        conn.close()
        return render_template(
            "index.html",
            products=rows,
            query=None,
            secure_mode=app.config["SECURE_MODE"],
        )

    @app.get("/search")
    def search():
        q = request.args.get("q", "") or ""
        conn = get_connection()
        cur = conn.cursor()
        if app.config["SECURE_MODE"]:
            # ĐÃ VÁ: truy vấn tham số hóa — ngăn SQLi.
            rows = search_products_parameterized(cur, q)
        else:
            # DỄ BỊ TẤN CÔNG: nối chuỗi trực tiếp — minh họa SQLi (OR 1=1, UNION...).
            # Chỉ một điểm ghép chuỗi: nếu ghép hai lần (name + description) payload UNION
            # sẽ bị lặp và SQLite báo lỗi cú pháp — không phù hợp demo seminar.
            sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%' COLLATE NOCASE"
            cur.execute(sql)
            rows = cur.fetchall()
        conn.close()
        return render_template(
            "index.html",
            products=rows,
            query=q,
            secure_mode=app.config["SECURE_MODE"],
        )

    @app.get("/product/<int:product_id>")
    def product_detail(product_id: int):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, price, description FROM products WHERE id = ?",
            (product_id,),
        )
        product = cur.fetchone()
        cur.execute(
            "SELECT id, product_id, username, body FROM comments WHERE product_id = ? ORDER BY id",
            (product_id,),
        )
        comments = cur.fetchall()
        conn.close()
        if not product:
            return "Không tìm thấy sản phẩm", 404
        vulnerable_xss = not app.config["SECURE_MODE"]
        return render_template(
            "product.html",
            product=product,
            comments=comments,
            vulnerable_xss=vulnerable_xss,
            secure_mode=app.config["SECURE_MODE"],
        )

    @app.post("/product/<int:product_id>/comment")
    def add_comment(product_id: int):
        username = request.form.get("username", "khach") or "khach"
        body = request.form.get("body", "") or ""
        if app.config["SECURE_MODE"]:
            # ĐÃ VÁ: làm sạch để tránh thực thi HTML/JS khi hiển thị.
            username = sanitize_user_comment(username)
            body = sanitize_user_comment(body)
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO comments (product_id, username, body) VALUES (?, ?, ?)",
            (product_id, username, body),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("product_detail", product_id=product_id))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template(
                "login.html",
                error=None,
                user=session.get("username"),
                secure_mode=app.config["SECURE_MODE"],
            )
        u = request.form.get("username", "") or ""
        p = request.form.get("password", "") or ""
        conn = get_connection()
        cur = conn.cursor()
        if app.config["SECURE_MODE"]:
            cur.execute(
                "SELECT id, username FROM users WHERE username = ? AND password = ?",
                (u, p),
            )
        else:
            # DỄ BỊ TẤN CÔNG: đăng nhập SQLi (ví dụ admin'-- ).
            cur.execute(
                f"SELECT id, username FROM users WHERE username='{u}' AND password='{p}'"
            )
        row = cur.fetchone()
        conn.close()
        if row:
            session["username"] = row[1]
            return redirect(url_for("login"))
        return render_template(
            "login.html",
            error="Sai tên đăng nhập hoặc mật khẩu.",
            user=session.get("username"),
            secure_mode=app.config["SECURE_MODE"],
        )

    @app.get("/logout")
    def logout():
        session.pop("username", None)
        return redirect(url_for("login"))

    return app


# --- Tiện ích cho main_demo.py: tạo app mặc định ---
app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    # Chỉ lắng nghe localhost — giảm rủi ro khi quên tắt server sau seminar.
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
