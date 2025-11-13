# flex_manager_pro_unified_final_clean.py - الكود النهائي المدمج والمصحح

import os, sys, random, time, json, requests, re
from threading import Thread
from telebot import types, TeleBot
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from apscheduler.schedulers.background import BackgroundScheduler
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from datetime import datetime, timedelta 
import string
import traceback

# --- 1. الإعدادات والتهيئة ---
init(autoreset=True)
TELEGRAM_BOT_TOKEN = "8517679271:AAHIfaV1fRMI-0nBcJxuE8sj5ybdaGMz5uI" # ⚠️ يجب تغيير هذا التوكن
OWNER_ID = 1698026264 
TIMEZONE = 'Africa/Cairo' 

bot = TeleBot(TELEGRAM_BOT_TOKEN)
scheduler = BackgroundScheduler(daemon=True, timezone=TIMEZONE) 
scheduler.start()

# --- 2. إعداد قاعدة البيانات ونماذج البيانات ---
ENGINE = create_engine('sqlite:///flex_families_core.db')
Base = declarative_base()
Session = sessionmaker(bind=ENGINE)

class FlexFamily(Base):
    __tablename__ = 'families'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    name = Column(String)
    owner_number = Column(String)
    owner_password = Column(String)
    member1_number = Column(String)
    member2_number = Column(String)
    member2_password = Column(String)
    total_stages = Column(Integer)
    current_stage = Column(Integer, default=1)
    is_running = Column(Boolean, default=False)
    stop_requested = Column(Boolean, default=False)
    is_paused_429 = Column(Boolean, default=False)
    selected_algorithms = Column(String) 
    input_step = Column(String, default="none")
    input_data = Column(Text, default="{}") 

Base.metadata.create_all(ENGINE)

# --- 3. ثوابت الـ API ---
AUTH_URL = 'https://mobile.vodafone.com.eg/auth/realms/vf-realm/protocol/openid-connect/token'
FAMILY_API_URL = "https://web.vodafone.com.eg/services/dxl/cg/customerGroupAPI/customerGroup"
CLIENT_ID = 'ana-vodafone-app'
CLIENT_SECRET = '95fd95fb-7489-4958-8ae6-d31a525cd20a'
SUBDOMAINS = ["mobile.vodafone.com.eg","web.vodafone.com.eg"]
USER_AGENTS = ["Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X)", "Mozilla/5.0 (Windows NT 11.0; Win64; x64)"]

# --- 4. دوال الـ API والـ Helpers ---

def get_fresh_token(phone_number, password):
    url = AUTH_URL
    headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": random.choice(USER_AGENTS)}
    data = {"username": phone_number, "password": password, "grant_type": "password",
            "client_secret": CLIENT_SECRET, "client_id": CLIENT_ID}
    try:
        response = requests.post(url, headers=headers, data=data, timeout=20)
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        return None

def create_headers(access_token_val, subdomain, user_agent, owner_number):
    return {
        "Authorization": f"Bearer {access_token_val}", "msisdn": owner_number,
        "Accept": "application/json", "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": user_agent, "Origin": f"https://{subdomain}", "clientId": "WebsiteConsumer"
    }

def change_quota(access_token, owner_number, member_number, quota, user_agent, subdomain, proxy=None):
    url = FAMILY_API_URL
    headers = create_headers(access_token, subdomain, user_agent, owner_number)
    payload = {"category": [{"listHierarchyId": "TemplateID", "value": "47"}], "parts": {"characteristicsValue": {"characteristicsValue": [{"characteristicName": "quotaDist1", "type": "percentage", "value": quota}]}, "member": [{"id": [{"schemeName": "MSISDN", "value": owner_number}], "type": "Owner"}, {"id": [{"schemeName": "MSISDN", "value": member_number}], "type": "Member"}]}, "type": "QuotaRedistribution"}
    try:
        response = requests.patch(url, headers=headers, json=payload, timeout=30)
        if response.status_code in [200, 201]: return True, "تم تغيير الحصة بنجاح"
        return False, f"فشل تغيير الحصة: {response.status_code}"
    except Exception as e:
        return False, f"خطأ: {e}"

def add_family_member(access_token, owner_number, member_number, quota_value, user_agent, subdomain, max_retries=3, proxy=None):
    url = FAMILY_API_URL
    headers = create_headers(access_token, subdomain, user_agent, owner_number)
    payload = {"name": "FlexFamily", "type": "SendInvitation", "category": [{"value": "523", "listHierarchyId": "PackageID"}, {"value": "47", "listHierarchyId": "TemplateID"}], "parts": {"member": [{"id": [{"value": owner_number, "schemeName": "MSISDN"}], "type": "Owner"}, {"id": [{"value": member_number, "schemeName": "MSISDN"}], "type": "Member"}], "characteristicsValue": {"characteristicsValue": [{"characteristicName": "quotaDist1", "value": str(quota_value), "type": "percentage"}]}}}
    for attempt in range(max_retries):
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=45)
            if response.status_code in [200, 201, 204]: return True, "تم إرسال الدعوة بنجاح"
            if response.status_code == 429: return False, "LIMIT_429"
        except Exception as e: pass
        time.sleep(2)
    return False, "فشل إرسال الدعوة بعد عدة محاولات"

def accept_invitation(member_token, owner_number, member_number, user_agent, subdomain, proxy=None):
    url = FAMILY_API_URL
    headers = {"Authorization": f"Bearer {member_token}", "msisdn": member_number, "Accept": "application/json", "Content-Type": "application/json; charset=UTF-8", "User-Agent": user_agent, "Origin": f"https://{subdomain}", "clientId": "WebsiteConsumer"}
    payload = {"category": [{"listHierarchyId": "TemplateID", "value": "47"}], "name": "FlexFamily", "type": "AcceptInvitation", "parts": {"member": [{"id": [{"schemeName": "MSISDN", "value": owner_number}], "type": "Owner"}, {"id": [{"schemeName": "MSISDN", "value": member_number}], "type": "Member"}]}}
    try:
        response = requests.patch(url, headers=headers, json=payload, timeout=30)
        if response.status_code in [200, 201]: return True, "تم قبول الدعوة"
        return False, f"فشل قبول الدعوة: {response.status_code}"
    except Exception as e: return False, f"خطأ: {e}"

def remove_flex_family_member(access_token, owner_number, member_number, user_agent, subdomain, max_retries=3, proxy=None):
    url = FAMILY_API_URL
    headers = create_headers(access_token, subdomain, user_agent, owner_number)
    payload = {"name": "FlexFamily", "type": "FamilyRemoveMember", "category": [{"value": "47", "listHierarchyId": "TemplateID"}], "parts": {"member": [{"id": [{"value": owner_number, "schemeName": "MSISDN"}], "type": "Owner"}, {"id": [{"value": member_number, "schemeName": "MSISDN"}], "type": "Member"}]}}
    for attempt in range(max_retries):
        try:
            response = requests.patch(url, data=json.dumps(payload), headers=headers, timeout=30)
            if response.status_code in [200, 201]: return True, "تم حذف العضو بنجاح"
        except Exception as e: pass
        time.sleep(2)
    return False, "فشل حذف العضو بعد عدة محاولات"

def get_flex_amount(owner_number, owner_password):
    try:
        nonce = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
        with requests.Session() as session:
            base_url = 'https://web.vodafone.com.eg/auth/realms/vf-realm/protocol/openid-connect/auth'
            redirect_uri = 'https://web.vodafone.com.eg/ar/KClogin'
            url_action = f"{base_url}?client_id=website&redirect_uri={redirect_uri}&state=random_state&response_mode=query&response_type=code&scope=openid&nonce={nonce}&kc_locale=en"
            response_url_action = session.get(url_action)
            soup = BeautifulSoup(response_url_action.content, 'html.parser')
            form_action = soup.find('form').get('action')
            headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': random.choice(USER_AGENTS)}
            data = {'username': owner_number, 'password': owner_password}
            response_login = session.post(form_action, headers=headers, data=data, allow_redirects=False)

            if 'Location' in response_login.headers and 'code=' in response_login.headers['Location']:
                code = response_login.headers['Location'].split('code=')[1].split('&')[0]
                data_token = {'code': code, 'grant_type': 'authorization_code', 'client_id': 'website', 'redirect_uri': redirect_uri}
                token_response = session.post('https://web.vodafone.com.eg/auth/realms/vf-realm/protocol/openid-connect/token', headers=headers, data=data_token)
                token = token_response.json().get('access_token')

                if token:
                    url = f'https://web.vodafone.com.eg/services/dxl/usage/usageConsumptionReport?bucket.product.publicIdentifier={owner_number}&@type=aggregated'
                    headers = {'Authorization': f'Bearer {token}', 'msisdn': owner_number, 'User-Agent': random.choice(USER_AGENTS)}
                    response = requests.get(url, headers=headers)
                    pattern = r'"usageType":"limit","bucketBalance":\[\{"remainingValue":\{"amount":(.*?),"units":"FLEX"'
                    match = re.search(pattern, response.text)
                    if match:
                        return int(float(match.group(1)))
        return None
    except Exception as e:
        return None

def update_status_message(chat_id, message_id, progress, final_flex=None):
    new_text = "📋 تقرير المرحلة الحالية:\n" + "\n".join(progress)
    if final_flex is not None:
        new_text += f"\n\n📊 الفليكس الحالي: {final_flex}"
    try:
        bot.edit_message_text(new_text, chat_id, message_id)
    except Exception as e:
        print(f"⚠️ update_status_message error: {e}")

# --- دوال مساعدة لتعقب الإدخال في DB (الإصلاح الآمن لـ NoneType) ---
def update_user_input_data(uid, step=None, data={}):
    db_session = Session()
    user_record = db_session.query(FlexFamily).filter(FlexFamily.user_id == uid, FlexFamily.input_step != 'none').first()
    
    if not user_record:
        user_record = FlexFamily(user_id=uid, name="Input_Temp", input_step="none", input_data="{}") 
        db_session.add(user_record)
    
    input_data_safe = user_record.input_data if user_record.input_data else "{}" 
    current_data = json.loads(input_data_safe)
    current_data.update(data)
    
    if step: user_record.input_step = step
    user_record.input_data = json.dumps(current_data)
    db_session.commit()
    db_session.close()
    return user_record

def get_user_input_state(uid):
    db_session = Session()
    user_record = db_session.query(FlexFamily).filter(FlexFamily.user_id == uid, FlexFamily.input_step != 'none').first()
    db_session.close()
    if user_record:
        input_data_safe = user_record.input_data if user_record.input_data else "{}"
        return user_record.input_step, json.loads(input_data_safe)
    return "none", {}

def is_admin(user_id):
    return user_id == OWNER_ID

# --- 5. دوال الآليات ومنطق التزامن ---

def run_parallel_sync(member2_token, family, current_token):
    ok_accept = False
    ok_quota = False
    
    def accept_task():
        nonlocal ok_accept
        ok_accept = accept_invitation(member2_token, family.owner_number, family.member2_number, random.choice(USER_AGENTS), random.choice(SUBDOMAINS))[0]
    
    def quota_task():
        nonlocal ok_quota
        ok_quota = change_quota(current_token, family.owner_number, family.member1_number, "40", random.choice(USER_AGENTS), random.choice(SUBDOMAINS))[0]

    try:
        thread1 = Thread(target=accept_task, daemon=True)
        thread2 = Thread(target=quota_task, daemon=True)
        thread1.start(); thread2.start()
        thread1.join(); thread2.join()
        return ok_accept and ok_quota
    except:
        return False

# -----------------------------------------------------------
# الآلية 1: قبول 5200 (الثابت 1300) - (مع تطبيق الـ Delays)
# -----------------------------------------------------------
def run_algorithm_1(family, current_token):
    progress = ["1️⃣ تغيير الثابت لـ 10% (1300): ⏳", "2️⃣ انتظار 6 دقائق: ⏳", "3️⃣ دعوة الطائر بـ 40% (5200): ⏳", 
                "4️⃣ ثريد متوازي (قبول/رفع 40%): ⏳", "5️⃣ انتظار 30 ثانية: ⏳", "6️⃣ حذف الطائر: ⏳", "7️⃣ انتظار 10 ثواني: ⏳"]
    status_msg = bot.send_message(family.user_id, f"⚙️ بدء تنفيذ الآلية 1: قبول 5200 (الثابت 1300)...")
    def update(index, success, icon="✅", msg=""):
        # 🌟 استخدام أيقونات مختلفة
        icon = "🏆" if success else "❌"
        progress[index] = progress[index].replace("⏳", icon) + (f" ({msg})" if msg else "")
        update_status_message(family.user_id, status_msg.message_id, progress)

    ok1, msg1 = change_quota(current_token, family.owner_number, family.member1_number, "10", random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(0, ok1, "❌" if not ok1 else "✅", msg1)
    if not ok1: return False, msg1
    
    update(1, True, "💤")
    time.sleep(360) 
    update(1, True, "✅")

    ok3, msg3 = add_family_member(current_token, family.owner_number, family.member2_number, "40", random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(2, ok3, "❌" if not ok3 else "✅", msg3)
    if msg3 == "LIMIT_429": return False, "LIMIT_429"
    if not ok3: return False, msg3
    
    member2_token = get_fresh_token(family.member2_number, family.member2_password)
    ok4 = run_parallel_sync(member2_token, family, current_token)
    update(3, ok4, "❌" if not ok4 else "🏆")
    if not ok4: return False, "فشل التزامن/توكن الطائر"

    update(4, True, "💤")
    time.sleep(30)
    update(4, True, "✅")

    ok6, msg6 = remove_flex_family_member(current_token, family.owner_number, family.member2_number, random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(5, ok6, "❌" if not ok6 else "🏆", msg6)

    update(6, True, "💤")
    time.sleep(10)
    update(6, True, "✅")

    flex_count = get_flex_amount(family.owner_number, family.owner_password)
    final_flex_display = f"{flex_count} فليكس 💪" if flex_count is not None and flex_count < 30000 else "أكثر من 30 ألف 🚀"
    update_status_message(family.user_id, status_msg.message_id, progress, final_flex_display)
    
    return True, "تمت الآلية 1 بنجاح"


# -----------------------------------------------------------
# الآلية 2: قبول 1300 ثابت 2600 (مع تطبيق الـ Delays)
# -----------------------------------------------------------
def run_algorithm_2(family, current_token):
    progress = ["1️⃣ تغيير الثابت لـ 20% (2600): ⏳", "2️⃣ انتظار 6 دقائق: ⏳", "3️⃣ دعوة الطائر بـ 10% (1300): ⏳", 
                "4️⃣ ثريد متوازي (قبول/رفع 40%): ⏳", "5️⃣ انتظار 30 ثانية: ⏳", "6️⃣ حذف الطائر: ⏳", "7️⃣ انتظار 10 ثواني: ⏳"]
    status_msg = bot.send_message(family.user_id, f"⚙️ بدء تنفيذ الآلية 2: قبول 1300 ثابت 2600...")
    def update(index, success, icon="✅", msg=""):
        progress[index] = progress[index].replace("⏳", icon) + (f" ({msg})" if msg else "")
        update_status_message(family.user_id, status_msg.message_id, progress)
        
    ok1, msg1 = change_quota(current_token, family.owner_number, family.member1_number, "20", random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(0, ok1, "❌" if not ok1 else "✅", msg1)
    if not ok1: return False, msg1
    
    update(1, True, "💤")
    time.sleep(360)  
    update(1, True, "✅")
    
    ok3, msg3 = add_family_member(current_token, family.owner_number, family.member2_number, "10", random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(2, ok3, "❌" if not ok3 else "✅", msg3)
    if msg3 == "LIMIT_429": return False, "LIMIT_429"
    if not ok3: return False, msg3
    
    member2_token = get_fresh_token(family.member2_number, family.member2_password)
    ok4 = run_parallel_sync(member2_token, family, current_token)
    update(3, ok4, "❌" if not ok4 else "✅")
    if not ok4: return False, "فشل التزامن/توكن الطائر"

    update(4, True, "💤")
    time.sleep(30)
    update(4, True, "✅")

    ok6, msg6 = remove_flex_family_member(current_token, family.owner_number, family.member2_number, random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(5, ok6, "❌" if not ok6 else "✅", msg6)

    update(6, True, "💤")
    time.sleep(10)
    update(6, True, "✅")

    flex_count = get_flex_amount(family.owner_number, family.owner_password)
    update_status_message(family.user_id, status_msg.message_id, progress, f"{flex_count} فليكس 💪")
    
    return True, "تمت الآلية 2 بنجاح"

# -----------------------------------------------------------
# الآلية 3: قبول 1300 ثابت 1300 (مع تطبيق الـ Delays)
# -----------------------------------------------------------
def run_algorithm_3(family, current_token):
    progress = ["1️⃣ تغيير الثابت لـ 10% (1300): ⏳", "2️⃣ انتظار 6 دقائق: ⏳", "3️⃣ دعوة الطائر بـ 10% (1300): ⏳", 
                "4️⃣ ثريد متوازي (قبول/رفع 40%): ⏳", "5️⃣ انتظار 30 ثانية: ⏳", "6️⃣ حذف الطائر: ⏳", "7️⃣ انتظار 10 ثواني: ⏳"]
    status_msg = bot.send_message(family.user_id, f"⚙️ بدء تنفيذ الآلية 3: قبول 1300 ثابت 1300...")
    def update(index, success, icon="✅", msg=""):
        progress[index] = progress[index].replace("⏳", icon) + (f" ({msg})" if msg else "")
        update_status_message(family.user_id, status_msg.message_id, progress)
        
    ok1, msg1 = change_quota(current_token, family.owner_number, family.member1_number, "10", random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(0, ok1, "❌" if not ok1 else "✅", msg1)
    if not ok1: return False, msg1

    update(1, True, "💤")
    time.sleep(360) 
    update(1, True, "✅")
    
    ok3, msg3 = add_family_member(current_token, family.owner_number, family.member2_number, "10", random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(2, ok3, "❌" if not ok3 else "✅", msg3)
    if msg3 == "LIMIT_429": return False, "LIMIT_429"
    if not ok3: return False, msg3
    
    member2_token = get_fresh_token(family.member2_number, family.member2_password)
    ok4 = run_parallel_sync(member2_token, family, current_token)
    update(3, ok4, "❌" if not ok4 else "✅")
    if not ok4: return False, "فشل التزامن/توكن الطائر"

    update(4, True, "💤")
    time.sleep(30)
    update(4, True, "✅")

    ok6, msg6 = remove_flex_family_member(current_token, family.owner_number, family.member2_number, random.choice(USER_AGENTS), random.choice(SUBDOMAINS))
    update(5, ok6, "❌" if not ok6 else "✅", msg6)

    update(6, True, "💤")
    time.sleep(10)
    update(6, True, "✅")
    
    flex_count = get_flex_amount(family.owner_number, family.owner_password)
    update_status_message(family.user_id, status_msg.message_id, progress, f"{flex_count} فليكس 💪")
    
    return True, "تمت الآلية 3 بنجاح"

# --- 6. دالة الجدولة الرئيسية (المحرك) ---

def start_family_cycle(family_id):
    from datetime import datetime, timedelta 
    db_session = Session()
    family = db_session.query(FlexFamily).filter_by(id=family_id).first()
    
    if not family or family.stop_requested or family.is_paused_429:
        try: scheduler.remove_job(str(family_id))
        except: pass
        if family and family.stop_requested:
            bot.send_message(family.user_id, f"🛑 تم إيقاف دورة العائلة {family.name}.")
            family.is_running = False
            family.stop_requested = False
            db_session.commit()
        db_session.close(); return
        
    alg_map = {1: run_algorithm_1, 2: run_algorithm_2, 3: run_algorithm_3}
    alg_list = [int(a) for a in family.selected_algorithms.split(',')]
    alg_index = (family.current_stage - 1) % len(alg_list)
    current_alg_func = alg_map.get(alg_list[alg_index])
    
    current_token = get_fresh_token(family.owner_number, family.owner_password)
    if not current_token:
        bot.send_message(family.user_id, f"❌ فشل تسجيل الدخول للعائلة {family.name}. تم الإيقاف.")
        family.is_running = False
        db_session.commit()
        db_session.close(); return

    bot.send_message(family.user_id, f"🚀 بدء المرحلة {family.current_stage}/{family.total_stages} | الآلية: {alg_list[alg_index]}")
    success, msg = current_alg_func(family, current_token)

    if msg == "LIMIT_429":
        # 🌟 المنطق التفاعلي للـ 429 تم وضعه في Handlers منفصلة (handle_429_actions)
        family.is_running = False
        db_session.commit()
        db_session.close()

        kb = types.InlineKeyboardMarkup()
        kb.add(types.InlineKeyboardButton("✅ نعم، أكمل 4 فجراً", callback_data=f"resume_429:{family_id}"),
               types.InlineKeyboardButton("❌ لا، أوقف الآن", callback_data=f"stop_429_final:{family_id}")) # تم تغيير الكول باك لتجنب تداخل الأوامر

        bot.send_message(family.user_id, 
                         f"🛑 تم إيقاف العائلة **{family.name}** بسبب تجاوز الحد الأقصى (Code 429).\n"
                         f"هل تود جدولة الاستئناف التلقائي في الساعة 4:00 فجراً؟",
                         reply_markup=kb, parse_mode="Markdown")
        return
    
    family.current_stage += 1
    
    if family.current_stage > family.total_stages:
        bot.send_message(family.user_id, f"✅ تم الانتهاء من جميع مراحل العائلة {family.name}.")
        family.is_running = False
    else:
        # فاصل 5 دقائق قبل المرحلة التالية
        next_run_time = datetime.now() + timedelta(minutes=5)
        scheduler.add_job(start_family_cycle, 'date', run_date=next_run_time, id=str(family.id), args=[family.id])

    db_session.commit()
    db_session.close()

# -----------------------------------------------------------
# Part 3: Handlers الإدخال والتحكم (الواجهة الأساسية)
# -----------------------------------------------------------

def main_inline_keyboard(uid):
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
    markup.add(types.KeyboardButton("➕ إضافة عائلة جديدة"), types.KeyboardButton("⚙️ بدء/استئناف دورة"))
    markup.add(types.KeyboardButton("🛑 إيقاف دورة محددة"))
    
    if uid == OWNER_ID:
        markup.add(types.KeyboardButton("👑 لوحة الأدمن"))
        
    return markup

@bot.message_handler(commands=['start', 'help'])
def handle_start(message):
    bot.send_message(message.chat.id, "أهلاً بك في نظام إدارة الفليكسات المتطور. استخدم الأزرار بالأسفل.", reply_markup=main_inline_keyboard(message.from_user.id))

@bot.message_handler(func=lambda m: m.text == "➕ إضافة عائلة جديدة")
def step_start_add_family(message):
    uid = message.from_user.id
    update_user_input_data(uid, step="name", data={}) 
    bot.send_message(message.chat.id, "يرجى إدخال اسم العائلة (مثلاً: عائلة سارة):")

@bot.message_handler(func=lambda m: get_user_input_state(m.from_user.id)[0] == "name")
def step_owner_number(message):
    update_user_input_data(message.from_user.id, step="owner_number", data={"family_name": message.text.strip()})
    bot.send_message(message.chat.id, "أدخل رقم الأونر (المضيف):")

@bot.message_handler(func=lambda m: get_user_input_state(m.from_user.id)[0] == "owner_number")
def step_owner_pass(message):
    uid = message.from_user.id
    number = message.text.strip()
    if not number.isdigit() or len(number) != 11:
        return bot.reply_to(message, "⚠️ رقم غير صالح (11 رقم). أعد إدخال رقم الأونر:")
    update_user_input_data(uid, step="owner_password", data={"owner_number": number})
    bot.send_message(message.chat.id, "أدخل باسورد الأونر:")

@bot.message_handler(func=lambda m: get_user_input_state(m.from_user.id)[0] == "owner_password")
def step_member1_number(message):
    update_user_input_data(message.from_user.id, step="member1_number", data={"owner_password": message.text.strip()})
    bot.send_message(message.chat.id, "أدخل رقم الفرد الثابت (Member 1):")

@bot.message_handler(func=lambda m: get_user_input_state(m.from_user.id)[0] == "member1_number")
def step_member2_number(message):
    uid = message.from_user.id
    number = message.text.strip()
    if not number.isdigit() or len(number) != 11:
        return bot.reply_to(message, "⚠️ رقم غير صالح (11 رقم). أعد إدخال رقم الثابت:")
    update_user_input_data(uid, step="member2_number", data={"member1_number": number})
    bot.send_message(message.chat.id, "أدخل رقم الفرد الطائر (Member 2):")

@bot.message_handler(func=lambda m: get_user_input_state(m.from_user.id)[0] == "member2_number")
def step_member2_pass(message):
    uid = message.from_user.id
    number = message.text.strip()
    if not number.isdigit() or len(number) != 11:
        return bot.reply_to(message, "⚠️ رقم غير صالح (11 رقم). أعد إدخال رقم الطائر:")
    update_user_input_data(uid, step="member2_password", data={"member2_number": number})
    bot.send_message(message.chat.id, "أدخل باسورد الفرد الطائر:")

@bot.message_handler(func=lambda m: get_user_input_state(m.from_user.id)[0] == "member2_password")
def step_total_stages(message):
    update_user_input_data(message.from_user.id, step="total_stages", data={"member2_password": message.text.strip()})
    bot.send_message(message.chat.id, "أدخل العدد الكلي للدورات (Stages) لهذه العائلة:")

@bot.message_handler(func=lambda m: get_user_input_state(m.from_user.id)[0] == "total_stages")
def step_select_algorithms(message):
    uid = message.from_user.id
    try:
        stages = int(message.text.strip())
        if stages <= 0: raise ValueError
    except:
        return bot.reply_to(message, "⚠️ يجب إدخال رقم صحيح أكبر من صفر. أعد الإدخال:")
        
    update_user_input_data(uid, step="select_algorithms", data={"total_stages": stages, "selected_algorithms": []})

    # 🌟 هنا يتم تطبيق الشكل المطلوب من الصورة 🌟
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(types.InlineKeyboardButton("1. قبول 5200 (الثابت 1300)", callback_data="alg:1"))
    markup.add(types.InlineKeyboardButton("2. قبول 1300 ثابت 2600 (الثابت 1300)", callback_data="alg:2"))
    markup.add(types.InlineKeyboardButton("3. قبول 1300 ثابت 1300 (الثابت 1300)", callback_data="alg:3"))
    markup.add(types.InlineKeyboardButton("🔄 تشغيل الآليات الثلاث بالتناوب", callback_data="alg:1,2,3"))
    markup.add(types.InlineKeyboardButton("✅ حفظ واختيار", callback_data="alg:save"))

    bot.send_message(message.chat.id, "اختر آلية العمل أو مجموعة آليات (يمكنك اختيار أكثر من آلية لـ تشغيلها بالتناوب):", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("alg:"))
def save_new_family(call):
    uid = call.from_user.id
    action = call.data.split(":")[1]
    step, data = get_user_input_state(uid)
    if step != "select_algorithms": return bot.answer_callback_query(call.id, "⚠️ خطأ في التسلسل.")
    selected_algs = set(data.get("selected_algorithms", []))
    
    if action.isdigit():
        alg_num = int(action)
        if alg_num in selected_algs: selected_algs.remove(alg_num)
        else: selected_algs.add(alg_num)
        
        update_user_input_data(uid, step="select_algorithms", data={"selected_algorithms": list(selected_algs)})
        bot.answer_callback_query(call.id, f"تم اختيار: {sorted(list(selected_algs))}")
        
    elif action == "save":
        if not selected_algs: return bot.answer_callback_query(call.id, "⚠️ يجب اختيار آلية واحدة على الأقل.", show_alert=True)
            
        db_session = Session()
        temp_record = db_session.query(FlexFamily).filter(FlexFamily.user_id == uid, FlexFamily.input_step != 'none').first()

        new_family = FlexFamily(
            user_id=uid, name=data["family_name"], owner_number=data["owner_number"],
            owner_password=data["owner_password"], member1_number=data["member1_number"],
            member2_number=data["member2_number"], member2_password=data["member2_password"],
            total_stages=data["total_stages"], selected_algorithms=",".join(map(str, sorted(list(selected_algs)))),
            is_running=False, current_stage=1
        )
        db_session.add(new_family)
        if temp_record: db_session.delete(temp_record)
        db_session.commit()
        db_session.close()

        bot.send_message(uid, f"✅ تم حفظ العائلة '{data['family_name']}' بنجاح! الآن يمكنك بدء الدورة من زر 'بدء/استئناف دورة'.")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)

# --- 8. Handlers التشغيل والإيقاف (مباشر) ---

# 🌟 Handlers معالجة أزرار الـ Limit 429
@bot.callback_query_handler(func=lambda call: call.data.startswith("resume_429:") or call.data.startswith("stop_429_final:"))
def handle_429_actions(call):
    action, family_id = call.data.split(":")
    family_id = int(family_id)
    db_session = Session()
    family = db_session.query(FlexFamily).filter_by(id=family_id).first()

    if action == "resume_429":
        family.is_paused_429 = True # نعم، هي موقوفة مؤقتاً
        
        # جدولة الاستئناف التلقائي في 4 فجراً
        scheduler.add_job(start_family_cycle, 'cron', hour=4, minute=0, id=f"resume_{family_id}", args=[family_id], timezone=TIMEZONE)
        
        bot.edit_message_text(f"✅ تم جدولة استئناف العائلة **{family.name}** تلقائيًا في الساعة 4:00 فجراً.", 
                              call.message.chat.id, call.message.message_id, parse_mode="Markdown")

    elif action == "stop_429_final":
        family.is_paused_429 = False 
        family.is_running = False
        family.stop_requested = True
        
        bot.edit_message_text(f"🛑 تم إيقاف العائلة **{family.name}** نهائيًا.", 
                              call.message.chat.id, call.message.message_id, parse_mode="Markdown")
        try: scheduler.remove_job(f"resume_{family_id}")
        except: pass
        
    db_session.commit()
    db_session.close()
    bot.answer_callback_query(call.id)

@bot.message_handler(func=lambda m: m.text == "⚙️ بدء/استئناف دورة")
def start_cycle_selection(message):
    uid = message.from_user.id
    db_session = Session()
    families = db_session.query(FlexFamily).filter_by(user_id=uid).filter(FlexFamily.input_step == 'none').all()
    db_session.close()

    if not families: return bot.reply_to(message, "لا توجد عائلات مسجلة بعد.")
    
    markup = types.InlineKeyboardMarkup()
    for fam in families:
        status = " (تشغيل 🚀)" if fam.is_running else (" (مؤقت ⚠️)" if fam.is_paused_429 else (f" (استئناف من {fam.current_stage} ♻️)" if fam.current_stage > 1 and fam.current_stage <= fam.total_stages else " (جاهزة ✅)"))
        markup.add(types.InlineKeyboardButton(f"{fam.name}{status}", callback_data=f"select_start:{fam.id}"))
    
    bot.send_message(message.chat.id, "اختر العائلة لبدء الدورة أو استئنافها:", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("select_start:"))
def handle_family_start(call):
    family_id = int(call.data.split(":")[1])
    db_session = Session()
    family = db_session.query(FlexFamily).filter_by(id=family_id).first()
    
    if family and not family.is_running:
        family.is_running = True
        family.stop_requested = False
        family.is_paused_429 = False
        db_session.commit()
        
        scheduler.add_job(start_family_cycle, 'date', run_date=datetime.now(), id=str(family.id), args=[family.id])
        bot.send_message(family.user_id, f"✅ تم بدء/استئناف العائلة **{family.name}** من المرحلة **{family.current_stage}**.", parse_mode="Markdown")
        bot.answer_callback_query(call.id, "بدء التشغيل...")
        
    elif family and family.is_running:
         bot.answer_callback_query(call.id, "هذه العائلة تعمل بالفعل.", show_alert=True)
         
    db_session.close()

@bot.message_handler(func=lambda m: m.text == "🛑 إيقاف دورة محددة")
def stop_cycle_btn(message):
    uid = message.from_user.id
    db_session = Session()
    running_families = db_session.query(FlexFamily).filter_by(user_id=uid, is_running=True).all()
    db_session.close()
    
    if not running_families: return bot.reply_to(message, "لا توجد عائلات قيد التشغيل حالياً.")
    
    markup = types.InlineKeyboardMarkup()
    for fam in running_families:
        markup.add(types.InlineKeyboardButton(f"🛑 إيقاف {fam.name}", callback_data=f"stop_fam:{fam.id}"))
    
    bot.send_message(message.chat.id, "اختر العائلة التي تود إيقافها:", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("stop_fam:"))
def handle_stop_family(call):
    family_id = int(call.data.split(":")[1])
    db_session = Session()
    family = db_session.query(FlexFamily).filter_by(id=family_id).first()
    
    if family and family.is_running:
        family.stop_requested = True
        db_session.commit()
        bot.send_message(family.user_id, f"🛑 تم إرسال طلب إيقاف لدورة العائلة **{family.name}**. سيتم التوقف بعد إكمال الخطوة الحالية.", parse_mode="Markdown")
        
    db_session.close()
    bot.answer_callback_query(call.id, "تم إرسال طلب الإيقاف.")


@bot.message_handler(func=lambda m: m.text == "👑 لوحة الأدمن")
def admin_panel_btn(message):
    if not OWNER_ID or message.from_user.id != OWNER_ID: return 
    
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("📊 إحصائيات النظام", callback_data="admin_stats"))
    kb.add(types.InlineKeyboardButton("جلب فليكس الجميع", callback_data="admin_flex_all"))
    
    bot.reply_to(message, "اختر أمر الإدارة:", reply_markup=kb)

@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_"))
def admin_callbacks(call):
    if not OWNER_ID or call.from_user.id != OWNER_ID: return
    action = call.data.split("_")[1]
    
    if action == 'stats':
        db_session = Session()
        total_families = db_session.query(FlexFamily).filter(FlexFamily.input_step == 'none').count()
        running_families = db_session.query(FlexFamily).filter_by(is_running=True).count()
        total_users = db_session.query(FlexFamily.user_id).distinct().count()
        paused_429 = db_session.query(FlexFamily).filter_by(is_paused_429=True).count()
        db_session.close()

        response = (
            f"📊 إحصائيات النظام:\n\n"
            f"👥 إجمالي المستخدمين: {total_users}\n"
            f"🏠 إجمالي العائلات المسجلة: {total_families}\n"
            f"🚀 العائلات قيد التشغيل حاليًا: {running_families}\n"
            f"⚠️ عائلات موقوفة (Limit 429): {paused_429}"
        )
        bot.edit_message_text(response, call.message.chat.id, call.message.message_id, reply_markup=None)

    elif action == 'flex_all':
        bot.send_message(call.message.chat.id, "⏳ جاري جلب الفليكسات... قد تستغرق العملية وقتاً.")
        db_session = Session()
        families = db_session.query(FlexFamily).filter(FlexFamily.input_step == 'none').all()
        db_session.close()
        response_text = "📊 فليكسات العائلات:\n"
        
        for fam in families:
            flex = get_flex_amount(fam.owner_number, fam.owner_password)
            response_text += f"- {fam.name} ({fam.user_id}): {flex if flex else '❌ فشل'}\n"
            
        bot.send_message(call.message.chat.id, response_text)
    
    bot.answer_callback_query(call.id, "تم التنفيذ.")


if __name__ == "__main__":
    print("🤖 البوت يعمل...")
    bot.infinity_polling()
