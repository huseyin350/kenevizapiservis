from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
import re

app = Flask(__name__)
app.secret_key = "KENEViZ_SUPER_GiZLi_KEY"  # 🔐 değiştirmeyi unutma!

# Proxy arkasında çalışıyorsa doğru IP alması için
app.wsgi_app = ProxyFix(app.wsgi_app)

# Rate limit (DDoS önlem)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per minute"]  # 1 dakikada max 50 istek
)

# --- Güvenlik filtreleri ---
def secure_input(data: str) -> str:
    """
    Kullanıcı inputlarını temizle → SQL Injection / XSS engelle
    """
    if not data:
        return ""
    # SQL injection riskli keywordleri temizle
    blacklist = [
        "select", "union", "insert", "update", "delete",
        "drop", "alter", "--", ";", "/*", "*/", "@@", "@",
        "char", "nchar", "varchar", "nvarchar", "xp_"
    ]
    for word in blacklist:
        data = re.sub(word, "", data, flags=re.IGNORECASE)
    # XSS script temizle
    data = re.sub(r"<.*?>", "", data)
    return data.strip()


# --- Routing ---

@app.before_request
def block_without_verification():
    """
    Kullanıcı doğrulamadan (robot.html) başka sayfalara erişemesin
    """
    allowed_routes = ["robot", "static", "verify_robot"]
    if "verified" not in session and request.endpoint not in allowed_routes:
        return redirect(url_for("robot"))


@app.route("/robot")
def robot():
    return render_template("robot.html")


@app.route("/verify_robot", methods=["POST"])
def verify_robot():
    """
    Robot doğrulaması → Kullanıcı butona bastıysa verified=True
    """
    session["verified"] = True
    return redirect(url_for("index"))


@app.route("/")
@limiter.limit("20 per minute")  # anasayfaya ek rate limit
def index():
    return render_template("index.html")


# Örnek API endpoint
@app.route("/api/data", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def api_data():
    user_input = request.args.get("q", "")
    user_input = secure_input(user_input)

    if not user_input:
        return {"error": "Geçersiz istek"}, 400

    return {"status": "ok", "query": user_input}


# Error handler → DDoS vs yakala
@app.errorhandler(429)
def ratelimit_handler(e):
    return {"error": "YARRAM RATE LIMITI AŞDIN BEKLE 2DK."}, 429


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def error_handler(e):
    return {"error": "Erişim reddedildi veya hata oluştu."}, 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
