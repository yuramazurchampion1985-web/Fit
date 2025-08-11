import os git commit --allow-empty -m "Force redeploy"
git push origin main
import time
import logging
import hmac
import hashlib
import sqlite3
from flask import Flask, request, jsonify
from fpdf import FPDF
import telegram

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
SECRET_KEY = os.environ.get("WAYFORPAY_SECRET_KEY")
FONT_PATH = os.environ.get("PDF_FONT_PATH", "fonts/DejaVuSans.ttf")
DB_PATH = os.environ.get("DB_PATH", "processed_orders.db")
PORT = int(os.environ.get("PORT", 5000))

if not TOKEN or not SECRET_KEY:
    logger.error("Відсутній TELEGRAM_BOT_TOKEN або WAYFORPAY_SECRET_KEY.")
    raise SystemExit("Missing TELEGRAM_BOT_TOKEN or WAYFORPAY_SECRET_KEY")

bot = telegram.Bot(token=TOKEN)
app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS processed_orders (
        order_reference TEXT PRIMARY KEY,
        processed_at INTEGER
    )""")
    conn.commit()
    conn.close()

def mark_order_processed(order_reference):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO processed_orders (order_reference, processed_at) VALUES (?, ?)",
                 (order_reference, int(time.time())))
    conn.commit()
    conn.close()

def is_order_processed(order_reference):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("SELECT 1 FROM processed_orders WHERE order_reference = ? LIMIT 1", (order_reference,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists

def generate_pdf(name, path=None):
    if not path:
        path = f"/tmp/aishape_plan_{int(time.time())}.pdf"
    pdf = FPDF()
    pdf.add_page()
    try:
        pdf.add_font("DejaVuSans", "", FONT_PATH, uni=True)
        pdf.set_font("DejaVuSans", size=16)
    except Exception:
        pdf.set_font("Arial", size=16)
    pdf.cell(0, 10, f"AIShape: Персональний фітнес-план для {name}", ln=True)
    pdf.ln(8)
    pdf.set_font(size=12)
    pdf.multi_cell(0, 8, "🏋️ Тренування на 7 днів:\nПн: Присідання + Віджимання\nВт: Біг + Прес\nСр: Спина + Планка\nЧт: Ноги + Прес\nПт: Груди + Трицепс\nСб: Кардіо\nНд: Відпочинок\n\n🍽️ Харчування:\nСніданок: Яйця + авокадо\nОбід: Гречка + курка\nВечеря: Риба + овочі\n...")
    pdf.output(path)
    return path

def format_amount(amount):
    try:
        return "{:.2f}".format(float(amount))
    except Exception:
        return str(amount)

def compute_signature(payload, secret_key):
    fields = [
        "merchantAccount", "orderReference", "amount", "currency",
        "authCode", "cardPan", "transactionStatus", "reasonCode"
    ]
    parts = []
    for f in fields:
        v = payload.get(f, "")
        if f == "amount":
            v = format_amount(v)
        parts.append("" if v is None else str(v))
    base = ";".join(parts)
    return hmac.new(secret_key.encode(), base.encode(), hashlib.md5).hexdigest()

def verify_signature(payload, signature, secret_key):
    return hmac.compare_digest(compute_signature(payload, secret_key), signature)

@app.route("/wayforpay_webhook", methods=["POST"])
def wayforpay_webhook():
    payload = request.get_json(force=True)
    logger.info("Отримано webhook від WayForPay")
    order_ref = payload.get("orderReference", "")
    signature = payload.get("merchantSignature")
    if not signature:
        logger.error("Відсутній merchantSignature.")
        return jsonify({"reason": "Missing signature"}), 400
    if not verify_signature(payload, signature, SECRET_KEY):
        logger.error("Невірний підпис.")
        return jsonify({"reason": "Invalid signature"}), 403

    if payload.get("transactionStatus") == "Approved":
        if is_order_processed(order_ref):
            logger.info(f"Order {order_ref} вже оброблений")
        else:
            client_email = payload.get("clientEmail", "")
            telegram_id_str = client_email.replace("telegram_", "")
            if not telegram_id_str.isdigit():
                logger.error("Невірний Telegram ID.")
            else:
                name = payload.get("customerName", "Клієнт")
                try:
                    file_path = generate_pdf(name)
                    with open(file_path, "rb") as f:
                        bot.send_document(chat_id=int(telegram_id_str), document=f,
                                          filename="AIShape_ProPlan.pdf",
                                          caption="✅ Дякуємо за оплату! Ось ваш персональний план.")
                    mark_order_processed(order_ref)
                    logger.info(f"Відправлено PDF користувачу {telegram_id_str}")
                except Exception as e:
                    logger.error(f"Помилка при відправці PDF: {e}")
    return jsonify({"status": "accept"}), 200

if __name__ == "__main__":
    init_db()
    logger.info(f"Запуск на порту {PORT}")
    app.run(host="0.0.0.0", port=PORT)
