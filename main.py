import asyncio
import logging
import sqlite3
import re
import gc
import os
from datetime import datetime, timedelta
import aiohttp
from aiohttp import web
from bs4 import BeautifulSoup
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery

# ==================== НАЛАШТУВАННЯ ====================
BOT_TOKEN = "8644395827:AAGZVbmzNKmQzYaFUGmB2bu4WbNEaYSCSwg"
CHAT_ID = 5292289444
OLX_URL = "https://www.olx.ua/uk/elektronika/telefony-i-aksesuary/mobilnye-telefony-smartfony/q-iphone/?currency=UAH&search%5Border%5D=created_at:desc&search%5Bfilter_float_price:from%5D=500&search%5Bfilter_float_price:to%5D=8000"

CHECK_INTERVAL = 61
PORT = int(os.environ.get("PORT", 10000))
# =======================================================

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "uk-UA,uk;q=0.9,en-US;q=0.8,en;q=0.7"
}

STOP_WORDS = [
    "запчасті", "запчасти", "запчастини",
    "разборка", "розборка",
    "чохол", "чехол",
    "деталі", "детали",
    "копія", "копия"
]

SCAM_TRIGGER_WORDS = [
    "передоплата", "предоплата", "завдаток", "задатк", "вайбер", "viber", 
    "телеграм", "telegram", "тг ", "пишіть в", "пишите в", "переходьте", "переходите",
    "картк", "карту", "по частичній", "частичная", "только почтой", "тільки поштою"
]

session: aiohttp.ClientSession = None
IS_PAUSED = False

# Статистика
STATS = {
    "total_scanned": 0,
    "good_found": 0,
    "scams_blocked": 0,
    "start_time": datetime.now()
}


def parse_price(price_str: str) -> int:
    """Витягує числове значення ціни з тексту"""
    clean_price = re.sub(r'[^\d]', '', price_str)
    return int(clean_price) if clean_price else 0


async def fetch_ad_description(url: str) -> str:
    """Завантажує сторінку оголошення та повертає опис"""
    global session
    if session is None or session.closed:
        session = aiohttp.ClientSession(headers=HEADERS)

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                desc_tag = soup.find("div", {"data-m2id": "ad_description"}) or soup.find("div", {"class": re.compile(r'css-1m89803|css-bg1jh4')})
                if desc_tag:
                    return desc_tag.text.lower()
                desc_div = soup.find("div", class_=lambda c: c and "description" in c.lower())
                if desc_div:
                    return desc_div.text.lower()
    except Exception as e:
        logging.error(f"Помилка завантаження опису {url}: {e}")
    return ""


def check_scam_risk(title: str, description: str, price: int, target_price: int) -> list[str]:
    """Перевіряє оголошення на ризики шахрайства"""
    full_text = f"{title.lower()} {description.lower()}"
    warnings = []

    for word in SCAM_TRIGGER_WORDS:
        if word in full_text:
            warnings.append(f"Прохання передоплати / увід контактів у месенджери ('{word}')")
            break

    if target_price > 0 and price < (target_price * 0.45):
        warnings.append(f"Занадто низька ціна ({price} грн) — високий ризик скаму / фейку!")

    return warnings


def detect_defects(text: str) -> list[str]:
    """Сканує текст на наявність дефектів або нюансів"""
    defects = []
    
    if any(w in text for w in ["не працює face", "неробочий face", "без face", "без фейс", "face id не", "не фейс"]):
        defects.append("Не працює Face ID")
    if any(w in text for w in ["немає true tone", "без true tone", "трутон не"]):
        defects.append("Відсутній True Tone")
    if any(w in text for w in ["акб", "акумулятор", "батарея", "health"]):
        battery_match = re.search(r'(\d{2,3})\s*%', text)
        if battery_match:
            defects.append(f"АКБ: {battery_match.group(1)}%")
    if any(w in text for w in ["тріщин", "трещин", "розбитий", "разбит", "скол"]):
        defects.append("Є тріщини / сколи")
    if any(w in text for w in ["камера", "пляма", "пятно"]):
        defects.append("Нюанси з камерою / пляма")
    if any(w in text for w in ["вм'ятина", "вмятина", "погнутий", "потертий"]):
        defects.append("Косметичні дефекти корпусу")
        
    return defects


def analyze_deal(title: str, price_str: str, description: str = "") -> dict:
    """Аналіз викупу та розрахунок прибутку"""
    title_lower = title.lower()
    full_text = f"{title_lower} {description.lower()}"
    price = parse_price(price_str)

    result = {
        "is_good": False,
        "reason": "",
        "model": "",
        "defects": [],
        "scam_warnings": [],
        "target_price": 0,
        "market_sell_price": 0,
        "bargain_price": 0,
        "profit": 0
    }

    if price == 0:
        result["reason"] = "Не вдалося розпізнати ціну"
        return result

    for stop_word in STOP_WORDS:
        if stop_word in full_text:
            result["reason"] = f"Містить стоп-слово: {stop_word}"
            return result

    is_rsim = any(w in full_text for w in ["rsim", "r-sim", "r sim", "чип", "чіп", "операторний"])
    is_bypass = any(w in full_text for w in ["bypass", "байпас", "icloud", "іклауд", "заблокований", "блокований"])

    mult = 1.0
    status_note = ""
    if is_bypass:
        mult = 0.5
        status_note = "Bypass (-50%)"
        result["defects"].append("Заблокований (Bypass/iCloud)")
    elif is_rsim:
        mult = 0.7
        status_note = "R-Sim (-30%)"
        result["defects"].append("Працює через R-Sim / Чіп")

    result["defects"].extend(detect_defects(full_text))

    model_name = ""
    base_max = 0
    full_market_val = 0

    if "12 mini" in title_lower or "12 міні" in title_lower:
        model_name = "iPhone 12 Mini"
        base_max, full_market_val = 4500, 5150

    elif ("iphone 12" in title_lower or "айфон 12" in title_lower) and not any(x in title_lower for x in ["mini", "міні", "pro", "про", "max", "макс"]):
        model_name = "iPhone 12"
        base_max, full_market_val = 5000, 5550

    elif ("iphone 11" in title_lower or "айфон 11" in title_lower) and not any(x in title_lower for x in ["pro", "про", "max", "макс"]):
        model_name = "iPhone 11"
        base_max, full_market_val = 3500, 4150

    elif any(m in title_lower for m in ["xs max", "хс макс"]):
        model_name = "iPhone XS Max"
        base_max, full_market_val = 2600, 2950

    elif any(m in title_lower for m in ["iphone xs", "айфон хс", " xs"]):
        model_name = "iPhone XS"
        base_max, full_market_val = 2600, 2950

    elif any(m in title_lower for m in ["iphone xr", "айфон хр", " xr", " хр"]):
        model_name = "iPhone XR"
        base_max, full_market_val = 2600, 2950

    elif any(m in title_lower for m in ["iphone x", "айфон х", " x "]) and not any(x in title_lower for x in ["xr", "xs", "хр", "хс"]):
        model_name = "iPhone X"
        base_max, full_market_val = 2400, 2900

    else:
        is_se3 = any(x in title_lower for x in ["se 3", "se 2022", "se3", "se 2023"])
        is_se2 = any(x in title_lower for x in ["se 2", "se 2020", "se2", "se 2021"])

        if not is_se3 and not is_se2 and ("se" in title_lower.split() or "се" in title_lower.split()):
            if any(x in title_lower for x in ["2022", "2023", "3"]):
                is_se3 = True
            elif any(x in title_lower for x in ["2020", "2021", "2"]):
                is_se2 = True

        if is_se3:
            model_name = "iPhone SE 3 (2022)"
            base_max, full_market_val = 3500, 3850
        elif is_se2:
            model_name = "iPhone SE 2 (2020)"
            base_max, full_market_val = 2300, 2550

    if not model_name:
        result["reason"] = "Модель не підпадає під фільтри"
        return result

    max_price = int(base_max * mult)
    
    if 0 <= price <= max_price:
        result["is_good"] = True
        result["model"] = model_name
        result["target_price"] = max_price
        
        bargain_discount = min(300, int(price * 0.08))
        result["bargain_price"] = max(0, price - bargain_discount)

        result["market_sell_price"] = int(full_market_val * mult)
        result["profit"] = result["market_sell_price"] - result["bargain_price"]

        result["scam_warnings"] = check_scam_risk(title, description, price, max_price)
        if result["scam_warnings"]:
            STATS["scams_blocked"] += 1

        note_str = f" [{status_note}]" if status_note else ""
        result["reason"] = f"{model_name}{note_str} за {price} грн (Норма викупу: до {max_price} грн)"
    else:
        result["reason"] = f"Ціна {price} грн вища за ліміт {max_price} грн для {model_name}"

    return result


def adjust_time_in_text(text: str) -> str:
    match = re.search(r'(\d{1,2}):(\d{2})', text)
    if match:
        hours, minutes = map(int, match.groups())
        new_time = (datetime(2000, 1, 1, hours, minutes) + timedelta(hours=3)).time()
        formatted_time = new_time.strftime("%H:%M")
        return re.sub(r'\d{1,2}:\d{2}', formatted_time, text)
    return text


def init_db():
    conn = sqlite3.connect("olx_ads.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS seen_ads (
            ad_id TEXT PRIMARY KEY
        )
    """)
    conn.commit()
    conn.close()


def is_ad_seen(ad_id: str) -> bool:
    conn = sqlite3.connect("olx_ads.db")
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM seen_ads WHERE ad_id = ?", (ad_id,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def add_seen_ad(ad_id: str):
    conn = sqlite3.connect("olx_ads.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO seen_ads (ad_id) VALUES (?)", (ad_id,))
    conn.commit()
    conn.close()


async def fetch_olx_ads():
    global session
    if session is None or session.closed:
        session = aiohttp.ClientSession(headers=HEADERS)

    try:
        async with session.get(OLX_URL, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status != 200:
                logging.error(f"Помилка запиту до OLX: Статус {response.status}")
                return []

            html = await response.text()
            soup = BeautifulSoup(html, "html.parser")
            cards = soup.find_all("div", {"data-testid": "l-card"})
            parsed_ads = []

            for card in cards:
                link_tag = card.find("a", href=True)
                if not link_tag:
                    continue
                href = link_tag["href"]
                full_link = f"https://www.olx.ua{href}" if href.startswith("/") else href

                ad_id = card.get("id")
                if not ad_id:
                    ad_id = href.split("-ID")[-1].replace(".html", "") if "-ID" in href else href

                title = ""
                for tag in ["h6", "h3", "h4", "p"]:
                    found = card.find(tag)
                    if found and len(found.text.strip()) > 3 and not found.text.strip().startswith("грн"):
                        title = found.text.strip()
                        break

                if not title or title == "Без назви":
                    img_tag = card.find("img")
                    if img_tag:
                        title = img_tag.get("alt") or img_tag.get("title") or ""

                if not title:
                    clean_slug = href.split("/")[-1].replace(".html", "")
                    title = clean_slug.replace("-", " ").capitalize()

                price_tag = card.find("p", {"data-testid": "ad-price"}) or card.find("span", {"data-testid": "ad-price"})
                price = price_tag.text.strip() if price_tag else "Ціна не вказана"

                location_tag = card.find("p", {"data-testid": "location-date"})
                location = location_tag.text.strip() if location_tag else ""

                loc_lower = location.lower()
                is_today = "сьогодні" in loc_lower or "сегодня" in loc_lower or "today" in loc_lower

                if location and not is_today:
                    continue

                corrected_location = adjust_time_in_text(location) if location else "Сьогодні"

                parsed_ads.append({
                    "id": str(ad_id),
                    "title": title,
                    "price": price,
                    "location": corrected_location,
                    "link": full_link
                })

            soup.decompose()
            gc.collect()

            return parsed_ads
    except Exception as e:
        logging.error(f"Помилка під час парсингу: {e}")
        return []


async def olx_checker_loop(bot: Bot):
    is_first_run = True

    while True:
        try:
            if IS_PAUSED:
                await asyncio.sleep(5)
                continue

            ads = await fetch_olx_ads()

            if is_first_run:
                for ad in ads:
                    add_seen_ad(ad["id"])
                logging.info(f"Бот зафіксував {len(ads)} існуючих оголошень.")
                is_first_run = False
            else:
                for ad in reversed(ads):
                    if not is_ad_seen(ad["id"]):
                        add_seen_ad(ad["id"])
                        STATS["total_scanned"] += 1

                        description = await fetch_ad_description(ad["link"])
                        deal = analyze_deal(ad["title"], ad["price"], description)

                        if deal["is_good"]:
                            STATS["good_found"] += 1
                            defects_text = "\n".join([f"  • {d}" for d in deal["defects"]]) if deal["defects"] else "  • Виражених дефектів не виявлено"

                            scam_text = ""
                            if deal["scam_warnings"]:
                                warn_list = "\n".join([f"  ⚠️ {w}" for w in deal["scam_warnings"]])
                                scam_text = f"\n🚨 <b>УВАГА! РИЗИК СКАМУ:</b>\n{warn_list}\n"

                            text = (
                                f"🔥 <b>ТОП ВАРІАНТ ДЛЯ ВИКУПУ!</b>\n\n"
                                f"📌 <b>Заголовок:</b> {ad['title']}\n"
                                f"💰 <b>Ціна продавця:</b> {ad['price']}\n"
                                f"⏰ <b>Коли виставили:</b> {ad['location']}\n\n"
                                f"🛠 <b>Виявлені дефекти / нюанси:</b>\n{defects_text}\n"
                                f"{scam_text}\n"
                                f"📈 <b>ФІНАНСОВИЙ РОЗРАХУНОК:</b>\n"
                                f"📉 <i>Ціна з торгом (~5-8%):</i> <b>{deal['bargain_price']} грн</b>\n"
                                f"🏷 <i>Сер. ціна продажу:</i> <b>{deal['market_sell_price']} грн</b>\n"
                                f"💵 <b>Очікуваний ПЛЮС:</b> <code>+{deal['profit']} грн</code>"
                            )

                            keyboard = InlineKeyboardMarkup(inline_keyboard=[
                                [InlineKeyboardButton(text="🔗 Відкрити на OLX", url=ad["link"])],
                                [InlineKeyboardButton(text="🗑 Сховати сповіщення", callback_data="delete_msg")]
                            ])

                            await bot.send_message(
                                chat_id=CHAT_ID,
                                text=text,
                                parse_mode="HTML",
                                reply_markup=keyboard,
                                disable_web_page_preview=False
                            )
                            await asyncio.sleep(0.5)
                        else:
                            logging.info(f"Пропущено ({ad['title']} | {ad['price']}): {deal['reason']}")
        except Exception as e:
            logging.error(f"Помилка в циклі перевірки: {e}")

        await asyncio.sleep(CHECK_INTERVAL)


# ==================== КОМАНДИ ТЕЛЕГРАМ ====================
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()


@dp.message(Command("start", "help"))
async def start_handler(message: Message):
    help_text = (
        "🤖 <b>Панель керування OLX Снайпером</b>\n\n"
        "Доступні команди:\n"
        "📊 `/stats` — переглянути статистику сканування\n"
        "⏸ `/pause` — приостановити сканування OLX\n"
        "▶️ `/resume` — відновити пошук оголошень\n"
    )
    await message.answer(help_text, parse_mode="HTML")


@dp.message(Command("stats"))
async def stats_handler(message: Message):
    uptime = str(datetime.now() - STATS["start_time"]).split('.')[0]
    status_str = "⏸ НА ПАУЗІ" if IS_PAUSED else "🟢 АКТИВНИЙ"
    
    stats_text = (
        f"📊 <b>СТАТИСТИКА РОБОТИ БОТА:</b>\n\n"
        f"⚙️ <b>Статус:</b> {status_str}\n"
        f"⏱ <b>Час у мережі:</b> {uptime}\n"
        f"🔍 <b>Проскановано нових оголошень:</b> {STATS['total_scanned']}\n"
        f"🔥 <b>Знайдено топ-варіантів:</b> {STATS['good_found']}\n"
        f"🛡 <b>Попереджень про скам:</b> {STATS['scams_blocked']}"
    )
    await message.answer(stats_text, parse_mode="HTML")


@dp.message(Command("pause"))
async def pause_handler(message: Message):
    global IS_PAUSED
    IS_PAUSED = True
    await message.answer("⏸ <b>Сканування зупинено!</b> Бот не надсилатиме сповіщення, поки ви не введете `/resume`", parse_mode="HTML")


@dp.message(Command("resume"))
async def resume_handler(message: Message):
    global IS_PAUSED
    IS_PAUSED = False
    await message.answer("▶️ <b>Сканування відновлено!</b> Бот знову шукає вигідні варіанти.", parse_mode="HTML")


@dp.callback_query(F.data == "delete_msg")
async def delete_msg_callback(callback: CallbackQuery):
    try:
        await callback.message.delete()
    except Exception:
        await callback.answer("Не вдалося видалити повідомлення", show_alert=False)


# ==================== ВЕБ-СЕРВЕР ДЛЯ RENDER ====================
async def handle_ping(request):
    return web.Response(text="Bot is running 24/7!")

async def start_web_server():
    app = web.Application()
    app.router.add_get("/", handle_ping)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    logging.info(f"Міні веб-сервер запущено на порту {PORT}")


async def main():
    logging.basicConfig(level=logging.INFO)
    init_db()
    
    # Запуск веб-сервера
    await start_web_server()
    
    # Запуск фонового циклу перевірки OLX
    asyncio.create_task(olx_checker_loop(bot))
    
    # Запуск поллінгу Telegram
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
