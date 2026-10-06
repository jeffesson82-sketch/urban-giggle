#!/usr/bin/env python3
"""Telegram-бот для продажи доступа к OpenVPN (python-telegram-bot 20.7)."""
import asyncio
import io
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    filters,
)

# ================= НАСТРОЙКИ (из .env) =================
load_dotenv(Path(__file__).with_name(".env"))

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_ID", "0") or 0)
PRICE_MONTHLY = int(os.getenv("PRICE_MONTHLY", "300"))
SUB_DAYS = int(os.getenv("SUB_DAYS", "30"))
DB_PATH = os.getenv("DB_PATH", "/opt/vpn_bot/vpn_service.db")
DISPLAY_TZ = ZoneInfo(os.getenv("DISPLAY_TZ", "Europe/Moscow"))
PAYMENT_INSTRUCTIONS = os.getenv(
    "PAYMENT_INSTRUCTIONS", "Реквизиты для оплаты уточните у администратора."
)

ISSUE_SCRIPT = "/usr/local/bin/vpn-issue.sh"
REVOKE_SCRIPT = "/usr/local/bin/vpn-revoke.sh"
REMIND_DAYS = 3          # за сколько дней напоминать о продлении
CHECK_INTERVAL = 600     # как часто проверять истёкшие подписки, сек
# =======================================================

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
# httpx на уровне INFO пишет в лог URL запроса вместе с токеном бота
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("vpnbot")

PKI_LOCK = asyncio.Lock()   # выпуск/отзыв сертификатов выполняются по одному
busy: set[int] = set()      # защита от двойных нажатий
last_alert: dict[str, float] = {}   # ключ алерта -> время последней отправки админу
ALERT_COOLDOWN = 3600       # не чаще раза в час на один и тот же алерт


# ---------------------------------------------------------------- время
def now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def from_iso(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


# ---------------------------------------------------------------- БД
@contextmanager
def tx():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:  # commit / rollback
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    with tx() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                telegram_id  INTEGER PRIMARY KEY,
                username     TEXT,
                sub_end      TEXT,                      -- UTC ISO, NULL = подписки не было
                cert_gen     INTEGER NOT NULL DEFAULT 1, -- поколение сертификата: vpn_<id>_<gen>
                cert_issued  INTEGER NOT NULL DEFAULT 0, -- 1 = сертификат текущего поколения выпущен
                reminded_for TEXT,                      -- для какой sub_end уже отправлено напоминание
                created_at   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS payments (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL,
                amount      INTEGER NOT NULL,
                days        INTEGER NOT NULL,
                provider    TEXT NOT NULL DEFAULT 'manual',  -- позже: 'yookassa'
                external_id TEXT,                            -- id платежа в платёжке
                status      TEXT NOT NULL DEFAULT 'pending', -- pending / paid / rejected
                claimed     INTEGER NOT NULL DEFAULT 0,      -- пользователь нажал «Я оплатил»
                created_at  TEXT NOT NULL,
                paid_at     TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_ext
                ON payments(provider, external_id) WHERE external_id IS NOT NULL;
            """
        )


def upsert_user(tid: int, username: str | None) -> None:
    with tx() as c:
        c.execute(
            "INSERT INTO users (telegram_id, username, created_at) VALUES (?, ?, ?) "
            "ON CONFLICT(telegram_id) DO UPDATE SET username = excluded.username",
            (tid, username, to_iso(now())),
        )


def get_user(tid: int):
    with tx() as c:
        return c.execute("SELECT * FROM users WHERE telegram_id = ?", (tid,)).fetchone()


def sub_active(user) -> bool:
    end = from_iso(user["sub_end"]) if user else None
    return bool(end and end > now())


def client_name(user) -> str:
    return f"vpn_{user['telegram_id']}_{user['cert_gen']}"


def set_cert_issued(tid: int, value: int) -> None:
    with tx() as c:
        c.execute("UPDATE users SET cert_issued = ? WHERE telegram_id = ?", (value, tid))


def bump_generation(tid: int) -> None:
    """После отзыва сертификата следующий будет выпущен под новым именем."""
    with tx() as c:
        c.execute(
            "UPDATE users SET cert_gen = cert_gen + 1, cert_issued = 0 WHERE telegram_id = ?",
            (tid,),
        )


def extend_subscription(c: sqlite3.Connection, tid: int, days: int) -> datetime:
    """Продлевает от даты окончания, если подписка ещё активна (дни не сгорают)."""
    row = c.execute("SELECT sub_end FROM users WHERE telegram_id = ?", (tid,)).fetchone()
    base = now()
    cur_end = from_iso(row["sub_end"]) if row else None
    if cur_end and cur_end > base:
        base = cur_end
    new_end = base + timedelta(days=days)
    c.execute("UPDATE users SET sub_end = ? WHERE telegram_id = ?", (to_iso(new_end), tid))
    return new_end


# ---------------------------------------------------------------- платежи
def get_or_create_pending(tid: int):
    with tx() as c:
        row = c.execute(
            "SELECT * FROM payments WHERE telegram_id = ? AND status = 'pending' "
            "ORDER BY id DESC LIMIT 1",
            (tid,),
        ).fetchone()
        if row:
            return row
        cur = c.execute(
            "INSERT INTO payments (telegram_id, amount, days, created_at) VALUES (?, ?, ?, ?)",
            (tid, PRICE_MONTHLY, SUB_DAYS, to_iso(now())),
        )
        return c.execute("SELECT * FROM payments WHERE id = ?", (cur.lastrowid,)).fetchone()


def process_successful_payment(payment_id: int, external_id: str | None = None):
    """Единая точка начисления подписки. Идемпотентна: платёж обрабатывается ровно один раз.

    Сейчас её вызывает админ кнопкой «Подтвердить».
    Позже ту же функцию будет вызывать вебхук ЮKassa (после проверки платежа через API).
    Возвращает (telegram_id, новая_дата_окончания) или None, если платёж уже обработан.
    """
    with tx() as c:
        cur = c.execute(
            "UPDATE payments SET status = 'paid', paid_at = ?, "
            "external_id = COALESCE(?, external_id) WHERE id = ? AND status = 'pending'",
            (to_iso(now()), external_id, payment_id),
        )
        if cur.rowcount == 0:
            return None
        pay = c.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
        new_end = extend_subscription(c, pay["telegram_id"], pay["days"])
        return pay["telegram_id"], new_end


# ---------------------------------------------------------------- скрипты VPN
async def run_script(script: str, name: str, timeout: int = 90) -> bytes | None:
    """Запускает root-скрипт через sudo без блокировки event loop."""
    proc = await asyncio.create_subprocess_exec(
        "sudo", "-n", script, name,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        logger.error("Таймаут %s %s", script, name)
        return None
    if proc.returncode != 0:
        logger.error("%s %s -> код %s: %s", script, name, proc.returncode, err.decode(errors="replace"))
        return None
    return out


# ---------------------------------------------------------------- интерфейс
HELP_TEXT = (
    "📖 Как подключиться\n\n"
    "1. Установите приложение OpenVPN Connect (App Store / Google Play / openvpn.net).\n"
    "2. Нажмите «Получить конфиг» и откройте полученный .ovpn файл в приложении.\n"
    "3. Нажмите Connect.\n\n"
    "Один ключ работает на одном устройстве одновременно. "
    "Если ключ попал не в те руки, нажмите «Сбросить ключ»."
)


def btn(text: str, data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text, callback_data=data)


def kb_back() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[btn("⬅️ В меню", "menu")]])


def kb_buy() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[btn("💳 Купить подписку", "buy")], [btn("⬅️ В меню", "menu")]])


def menu_view(user, is_admin: bool):
    rows = []
    if sub_active(user):
        end = from_iso(user["sub_end"])
        left = end - now()
        text = (
            "👤 Личный кабинет\n"
            f"📅 Подписка до: {end.astimezone(DISPLAY_TZ):%d.%m.%Y %H:%M}\n"
            f"⏳ Осталось: {left.days} дн. {left.seconds // 3600} ч."
        )
        rows += [
            [btn("🔑 Получить конфиг", "cfg")],
            [btn("♻️ Сбросить ключ", "reset")],
            [btn("💳 Продлить", "buy")],
        ]
    else:
        text = f"👋 Доступ к VPN: {PRICE_MONTHLY} ₽ за {SUB_DAYS} дн."
        if user and user["sub_end"]:
            text += "\n⚠️ Ваша подписка закончилась."
        rows.append([btn("💳 Купить подписку", "buy")])
    rows.append([btn("📖 Как подключиться", "help")])
    if is_admin:
        rows.append([btn("⚙️ Админ панель", "adm")])
    return text, InlineKeyboardMarkup(rows)


async def safe_edit(query, text: str, markup=None) -> None:
    try:
        await query.edit_message_text(text, reply_markup=markup)
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            raise


async def safe_send(bot, chat_id: int, text: str, markup=None) -> bool:
    try:
        await bot.send_message(chat_id, text, reply_markup=markup)
        return True
    except TelegramError as e:
        logger.warning("Не удалось отправить сообщение %s: %s", chat_id, e)
        return False


async def alert_admin(bot, key: str, text: str) -> None:
    """Уведомление админу не чаще ALERT_COOLDOWN секунд для одного и того же ключа."""
    t = asyncio.get_running_loop().time()
    if t - last_alert.get(key, -ALERT_COOLDOWN) < ALERT_COOLDOWN:
        return
    last_alert[key] = t
    await safe_send(bot, ADMIN_ID, text)


async def notify_paid(bot, tid: int) -> None:
    user = get_user(tid)
    text, kb = menu_view(user, tid == ADMIN_ID)
    await safe_send(bot, tid, "✅ Оплата получена, подписка активна!\n\n" + text, kb)


def is_admin(update: Update) -> bool:
    return update.effective_user is not None and update.effective_user.id == ADMIN_ID


# ---------------------------------------------------------------- обработчики
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    upsert_user(u.id, u.username)
    text, kb = menu_view(get_user(u.id), u.id == ADMIN_ID)
    await update.effective_message.reply_text(f"Привет, {u.first_name}!\n\n{text}", reply_markup=kb)


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.effective_message.reply_text(HELP_TEXT, reply_markup=kb_back())


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    u = update.effective_user
    upsert_user(u.id, u.username)
    text, kb = menu_view(get_user(u.id), u.id == ADMIN_ID)
    await update.effective_message.reply_text(text, reply_markup=kb)


async def cb_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    upsert_user(q.from_user.id, q.from_user.username)
    text, kb = menu_view(get_user(q.from_user.id), q.from_user.id == ADMIN_ID)
    await safe_edit(q, text, kb)


async def cb_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    await safe_edit(q, HELP_TEXT, kb_back())


async def cb_buy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    upsert_user(q.from_user.id, q.from_user.username)
    pay = get_or_create_pending(q.from_user.id)
    text = (
        f"💳 Заявка на оплату №{pay['id']}\n"
        f"Сумма: {pay['amount']} ₽ за {pay['days']} дн.\n\n"
        f"{PAYMENT_INSTRUCTIONS}\n\n"
        "После оплаты нажмите «Я оплатил»: подписка включится после подтверждения."
    )
    kb = InlineKeyboardMarkup(
        [[btn("✅ Я оплатил", f"claim:{pay['id']}")], [btn("⬅️ В меню", "menu")]]
    )
    await safe_edit(q, text, kb)


async def cb_claim(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    pid = int(q.data.split(":")[1])
    with tx() as c:
        pay = c.execute("SELECT * FROM payments WHERE id = ?", (pid,)).fetchone()
        if not pay or pay["telegram_id"] != q.from_user.id or pay["status"] != "pending":
            await q.answer("Эта заявка уже обработана.", show_alert=True)
            return
        if pay["claimed"]:
            await q.answer("Заявка уже отправлена, ожидайте подтверждения.", show_alert=True)
            return
        c.execute("UPDATE payments SET claimed = 1 WHERE id = ?", (pid,))
    await q.answer()

    uname = f"@{q.from_user.username}" if q.from_user.username else "без username"
    admin_kb = InlineKeyboardMarkup(
        [[btn(f"✅ Подтвердить №{pid}", f"ok:{pid}"), btn("❌ Отклонить", f"no:{pid}")]]
    )
    delivered = await safe_send(
        context.bot, ADMIN_ID,
        f"💰 Заявка №{pid}\nПользователь: {pay['telegram_id']} ({uname})\n"
        f"Сумма: {pay['amount']} ₽ / {pay['days']} дн.",
        admin_kb,
    )
    if not delivered:
        with tx() as c:
            c.execute("UPDATE payments SET claimed = 0 WHERE id = ?", (pid,))
        await safe_edit(q, "❌ Не удалось отправить заявку администратору. Попробуйте позже.", kb_back())
        return
    await safe_edit(q, "📨 Заявка отправлена администратору. Мы сообщим, когда оплата подтвердится.", kb_back())


async def cb_decision(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа.", show_alert=True)
        return
    action, pid = q.data.split(":")
    pid = int(pid)

    if action == "ok":
        result = process_successful_payment(pid)
        if result is None:
            await q.answer("Платёж уже обработан.", show_alert=True)
            return
        tid, new_end = result
        await q.answer("Подтверждено")
        await safe_edit(q, f"✅ Платёж №{pid} подтверждён (пользователь {tid}, до {new_end.astimezone(DISPLAY_TZ):%d.%m.%Y}).")
        await notify_paid(context.bot, tid)
    else:
        with tx() as c:
            cur = c.execute("UPDATE payments SET status = 'rejected' WHERE id = ? AND status = 'pending'", (pid,))
            row = c.execute("SELECT telegram_id FROM payments WHERE id = ?", (pid,)).fetchone()
        if cur.rowcount == 0:
            await q.answer("Платёж уже обработан.", show_alert=True)
            return
        await q.answer("Отклонено")
        await safe_edit(q, f"❌ Платёж №{pid} отклонён.")
        await safe_send(context.bot, row["telegram_id"],
                        "❌ Оплата не подтверждена. Если вы оплатили, свяжитесь с администратором.", kb_buy())


async def cb_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = q.from_user.id
    if uid in busy:
        await q.answer("Подождите, запрос обрабатывается…")
        return
    await q.answer()
    busy.add(uid)
    try:
        async with PKI_LOCK:
            user = get_user(uid)
            if not user or not sub_active(user):
                await safe_edit(q, "❌ Подписка не активна.", kb_buy())
                return
            name = client_name(user)
            was_issued = user["cert_issued"]
            set_cert_issued(uid, 1)  # ставим до выпуска: так сертификат точно будет отозван при окончании
            await safe_edit(q, "⏳ Готовлю конфиг…")
            out = await run_script(ISSUE_SCRIPT, name)
            if not (out and b"<ca>" in out):
                # сертификат не выпущен — не оставляем ложный флаг, иначе отзыв будет падать
                set_cert_issued(uid, was_issued)

        if out and b"<ca>" in out:
            await context.bot.send_document(
                chat_id=uid,
                document=io.BytesIO(out),
                filename=f"{name}.ovpn",
                caption="📎 Ваш конфиг. Откройте его в OpenVPN Connect.",
                protect_content=True,  # в файле приватный ключ — запрещаем пересылку
            )
            text, kb = menu_view(get_user(uid), uid == ADMIN_ID)
            await safe_edit(q, "✅ Конфиг отправлен файлом выше.\n\n" + text, kb)
        else:
            await safe_edit(q, "❌ Не удалось создать конфиг. Попробуйте позже или напишите администратору.", kb_back())
    finally:
        busy.discard(uid)


async def cb_reset(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    kb = InlineKeyboardMarkup([[btn("♻️ Да, сбросить", "reset_yes")], [btn("⬅️ Отмена", "menu")]])
    await safe_edit(q, "Старый ключ перестанет работать, а активное подключение будет разорвано. Продолжить?", kb)


async def cb_reset_yes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = q.from_user.id
    if uid in busy:
        await q.answer("Подождите, запрос обрабатывается…")
        return
    await q.answer()
    busy.add(uid)
    try:
        async with PKI_LOCK:
            user = get_user(uid)
            if not user or not user["cert_issued"]:
                await safe_edit(q, "Ключ ещё не выпускался, сбрасывать нечего.", kb_back())
                return
            if await run_script(REVOKE_SCRIPT, client_name(user)) is None:
                await safe_edit(q, "❌ Не удалось отозвать ключ. Попробуйте позже.", kb_back())
                return
            bump_generation(uid)
        await safe_edit(q, "✅ Старый ключ отозван. Нажмите «Получить конфиг», чтобы выпустить новый.", kb_back())
    finally:
        busy.discard(uid)


# ---------------------------------------------------------------- админка
async def cb_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа.", show_alert=True)
        return
    await q.answer()
    with tx() as c:
        total = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM users WHERE sub_end > ?", (to_iso(now()),)).fetchone()[0]
        pending = c.execute("SELECT COUNT(*) FROM payments WHERE status='pending' AND claimed=1").fetchone()[0]
    text = (
        "⚙️ Админ панель\n"
        f"Пользователей: {total}\nАктивных подписок: {active}\nЗаявок на оплату: {pending}\n\n"
        "Выдать подписку вручную: /grant <telegram_id> <дней>"
    )
    kb = InlineKeyboardMarkup([[btn("💰 Заявки на оплату", "adm_pending")], [btn("⬅️ В меню", "menu")]])
    await safe_edit(q, text, kb)


async def cb_admin_pending(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    if q.from_user.id != ADMIN_ID:
        await q.answer("Нет доступа.", show_alert=True)
        return
    await q.answer()
    with tx() as c:
        rows = c.execute(
            "SELECT p.*, u.username FROM payments p LEFT JOIN users u USING(telegram_id) "
            "WHERE p.status='pending' AND p.claimed=1 ORDER BY p.id LIMIT 10"
        ).fetchall()
    if not rows:
        await safe_edit(q, "Нет заявок, ожидающих подтверждения.", InlineKeyboardMarkup([[btn("⬅️ Назад", "adm")]]))
        return
    lines, kb = ["💰 Ожидают подтверждения:"], []
    for r in rows:
        lines.append(f"№{r['id']}: {r['telegram_id']} (@{r['username'] or '-'}), {r['amount']} ₽ / {r['days']} дн.")
        kb.append([btn(f"✅ №{r['id']}", f"ok:{r['id']}"), btn(f"❌ №{r['id']}", f"no:{r['id']}")])
    kb.append([btn("⬅️ Назад", "adm")])
    await safe_edit(q, "\n".join(lines), InlineKeyboardMarkup(kb))


async def cmd_grant(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return
    try:
        tid, days = int(context.args[0]), int(context.args[1])
        assert 1 <= days <= 3650
    except (IndexError, ValueError, AssertionError):
        await update.effective_message.reply_text("Использование: /grant <telegram_id> <дней 1-3650>")
        return
    if not get_user(tid):
        await update.effective_message.reply_text("Пользователь не найден (он должен нажать /start).")
        return
    with tx() as c:
        new_end = extend_subscription(c, tid, days)
    await update.effective_message.reply_text(f"Готово: подписка до {new_end.astimezone(DISPLAY_TZ):%d.%m.%Y %H:%M}.")
    await notify_paid(context.bot, tid)


# ---------------------------------------------------------------- фоновая проверка
async def check_subscriptions(context: ContextTypes.DEFAULT_TYPE):
    # 1. Истёкшие подписки: отзываем сертификат
    with tx() as c:
        expired = c.execute(
            "SELECT telegram_id FROM users WHERE cert_issued = 1 AND sub_end IS NOT NULL AND sub_end < ?",
            (to_iso(now()),),
        ).fetchall()
    for row in expired:
        tid = row["telegram_id"]
        async with PKI_LOCK:
            user = get_user(tid)
            if not user["cert_issued"] or sub_active(user):  # успели продлить
                continue
            if await run_script(REVOKE_SCRIPT, client_name(user)) is None:
                await alert_admin(context.bot, f"revoke:{tid}", f"⚠️ Не удалось отозвать сертификат пользователя {tid}")
                continue
            bump_generation(tid)
        await safe_send(context.bot, tid, "⛔ Подписка закончилась, доступ к VPN отключён.", kb_buy())

    # 2. Напоминания о скором окончании
    limit = now() + timedelta(days=REMIND_DAYS)
    with tx() as c:
        soon = c.execute(
            "SELECT telegram_id, sub_end FROM users WHERE sub_end > ? AND sub_end <= ? "
            "AND (reminded_for IS NULL OR reminded_for != sub_end)",
            (to_iso(now()), to_iso(limit)),
        ).fetchall()
    for row in soon:
        with tx() as c:
            c.execute("UPDATE users SET reminded_for = ? WHERE telegram_id = ?", (row["sub_end"], row["telegram_id"]))
        end = from_iso(row["sub_end"]).astimezone(DISPLAY_TZ)
        kb = InlineKeyboardMarkup([[btn("💳 Продлить", "buy")]])
        await safe_send(context.bot, row["telegram_id"], f"⏰ Подписка заканчивается {end:%d.%m.%Y %H:%M}. Продлите заранее.", kb)


async def on_error(update, context: ContextTypes.DEFAULT_TYPE):
    logger.error("Необработанная ошибка", exc_info=context.error)
    await alert_admin(context.bot, "error", f"⚠️ Ошибка в боте: {type(context.error).__name__}: {context.error}")


# ---------------------------------------------------------------- запуск
def main() -> None:
    if not BOT_TOKEN or not ADMIN_ID:
        raise SystemExit("Заполните BOT_TOKEN и ADMIN_ID в /opt/vpn_bot/.env")
    init_db()

    app = Application.builder().token(BOT_TOKEN).build()
    if app.job_queue is None:
        raise SystemExit('Установите: pip install "python-telegram-bot[job-queue]==20.7"')

    private = filters.ChatType.PRIVATE
    app.add_handler(CommandHandler("start", start, filters=private))
    app.add_handler(CommandHandler("help", cmd_help, filters=private))
    app.add_handler(CommandHandler("status", cmd_status, filters=private))
    app.add_handler(CommandHandler("grant", cmd_grant, filters=private))

    for pattern, handler in [
        (r"^menu$", cb_menu), (r"^help$", cb_help), (r"^buy$", cb_buy),
        (r"^claim:\d+$", cb_claim), (r"^(ok|no):\d+$", cb_decision),
        (r"^cfg$", cb_config), (r"^reset$", cb_reset), (r"^reset_yes$", cb_reset_yes),
        (r"^adm$", cb_admin), (r"^adm_pending$", cb_admin_pending),
    ]:
        app.add_handler(CallbackQueryHandler(handler, pattern=pattern))

    app.add_error_handler(on_error)
    app.job_queue.run_repeating(check_subscriptions, interval=CHECK_INTERVAL, first=30)

    logger.info("Бот запущен")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
