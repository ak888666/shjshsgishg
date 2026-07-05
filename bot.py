# -*- coding: utf-8 -*-
import os
import logging
import json
import re
import base64
import time
import requests
import urllib.parse
from typing import Dict, Any
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)

# ---------- 日志 ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- 状态常量 ----------
NAME, IDCARD, PHONE, WAIT_SMS = range(4)

# ---------- 导入 ddddocr ----------
try:
    import ddddocr
    ocr = ddddocr.DdddOcr(show_ad=False)
except ImportError:
    logger.error("请安装 ddddocr: pip install ddddocr")
    ocr = None

# ---------- SM4 加密 ----------
SM4_KEY = "CatsPK0WWWRRhjkw"
SboxTable = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
]
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]

def rotl(x, n):
    left = (x << n) & 0xffffffff
    signed_x = x - 0x100000000 if (x & 0x80000000) else x
    right = (signed_x >> (32 - n)) & 0xffffffff
    return left | right

def sm4_sbox(a):
    return (SboxTable[(a >> 24) & 0xFF] << 24) | \
           (SboxTable[(a >> 16) & 0xFF] << 16) | \
           (SboxTable[(a >> 8) & 0xFF] << 8) | \
           SboxTable[a & 0xFF]

def sm4_lt(ka):
    bb = sm4_sbox(ka)
    return bb ^ rotl(bb, 2) ^ rotl(bb, 10) ^ rotl(bb, 18) ^ rotl(bb, 24)

def sm4_calci_rk(ka):
    bb = sm4_sbox(ka)
    return bb ^ rotl(bb, 13) ^ rotl(bb, 23)

def sm4_f(x0, x1, x2, x3, rk):
    return x0 ^ sm4_lt(x1 ^ x2 ^ x3 ^ rk)

def pkcs7_pad(data: bytes, block_size=16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def sm4_encrypt_ecb(plain_text: str) -> str:
    data = plain_text.encode('utf-8')
    padded = pkcs7_pad(data, 16)
    key_bytes = SM4_KEY.encode('utf-8')
    mk = [0] * 4
    for i in range(4):
        mk[i] = (key_bytes[i*4] << 24) | (key_bytes[i*4+1] << 16) | (key_bytes[i*4+2] << 8) | key_bytes[i*4+3]
    k = [0] * 36
    for i in range(4):
        k[i] = mk[i] ^ FK[i]
    sk = [0] * 32
    for i in range(32):
        k[i+4] = k[i] ^ sm4_calci_rk(k[i+1] ^ k[i+2] ^ k[i+3] ^ CK[i])
        sk[i] = k[i+4]
    result = bytearray()
    for offset in range(0, len(padded), 16):
        block = padded[offset:offset+16]
        x = [0] * 36
        for i in range(4):
            x[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3]
        for i in range(32):
            x[i+4] = sm4_f(x[i], x[i+1], x[i+2], x[i+3], sk[i])
        out = bytearray(16)
        for i in range(4):
            val = x[35-i]
            out[i*4] = (val >> 24) & 0xFF
            out[i*4+1] = (val >> 16) & 0xFF
            out[i*4+2] = (val >> 8) & 0xFF
            out[i*4+3] = val & 0xFF
        result.extend(out)
    return base64.b64encode(result).decode('utf-8')

# ---------- 全局配置 ----------
BASE_URL = "http://www.gxdlys.com"
PASSWORD = "268428."  # 固定密码
session = requests.Session()
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 14; Build/BP2A.250605.031.A3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.119 Mobile Safari/537.36",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive",
    "Referer": "http://www.gxdlys.com/Wechat/User/Regist",
}

# ==================== 工具函数 ====================
def get_captcha() -> tuple:
    """获取图形验证码并识别，返回 (code, uuid)"""
    try:
        url = f"{BASE_URL}/Wechat/FaceDetect/GetVerifyCode"
        resp = session.get(url, headers=HEADERS, timeout=10)
        if resp.status_code != 200:
            return None, None
        data = resp.json()
        if data.get("statusCode") != 200:
            return None, None
        img_b64 = data.get("data", {}).get("img")
        uuid = data.get("data", {}).get("uuid")
        if not img_b64 or not uuid:
            return None, None
        img_bytes = base64.b64decode(img_b64)
        if ocr:
            code = ocr.classification(img_bytes)
            if code:
                code = re.sub(r'[^A-Z0-9]', '', code.upper())
                if len(code) == 4:   # 验证码通常4位
                    return code, uuid
        return None, None
    except Exception as e:
        logger.error(f"获取验证码失败: {e}")
        return None, None

def send_sms(phone: str, captcha_code: str, uuid: str) -> bool:
    """请求发送短信验证码"""
    data = {
        "phoneId": phone,
        "type": "10001",
        "IsEncryptPhoneId": "false",
        "verifyCode": captcha_code,
        "uuid": uuid
    }
    try:
        r = session.post(
            f"{BASE_URL}/System/SmsService/PostVerifyCode",
            data=data,
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
            timeout=60
        )
        if r.status_code == 200:
            res = r.json()
            return res.get("statusCode") == 200
        return False
    except Exception as e:
        logger.error(f"发送短信失败: {e}")
        return False

def register(phone: str, sms_code: str, captcha_code: str, real_name: str, id_card: str) -> bool:
    """提交注册"""
    data = {
        "zipArea": "",
        "userType": "-1",
        "wechatUid": "",
        "realName": real_name,
        "iDCard": id_card,
        "loginName": id_card,
        "password": PASSWORD,
        "idcardImg1Url": "218,8a785f252c8518",
        "idcardImg2Url": "216,8a7860c46589f3",
        "idcardImg3Url": "214,8a78664776227f",
        "idcardImg4Url": "",
        "ownerId": "",
        "tel": phone,
        "isTelEncrypted": "false",
        "validCode": sms_code,
        "verifyCode": captcha_code
    }
    try:
        r = session.post(
            f"{BASE_URL}/Wechat/User/RegistAdd",
            data=data,
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
            timeout=60
        )
        if r.status_code == 200:
            res = r.json()
            return res.get("statusCode") == 200
        return False
    except Exception as e:
        logger.error(f"注册异常: {e}")
        return False

def login(id_card: str) -> bool:
    """登录"""
    encrypted_login_raw = sm4_encrypt_ecb(id_card)
    encrypted_pwd_raw = sm4_encrypt_ecb(PASSWORD)
    encrypted_login = urllib.parse.quote(encrypted_login_raw)
    encrypted_pwd = urllib.parse.quote(encrypted_pwd_raw)
    data = f"loginName={encrypted_login}&password={encrypted_pwd}&wechatUid="
    login_headers = {
        **HEADERS,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": "http://www.gxdlys.com/Wechat/Home/Login",
        "Host": "www.gxdlys.com"
    }
    try:
        r = session.post(
            "http://www.gxdlys.com/Wechat/Home/PostLogin",
            headers=login_headers,
            data=data,
            timeout=60
        )
        if r.status_code == 200:
            res = r.json()
            return res.get("statusCode") == 200
        return False
    except Exception as e:
        logger.error(f"登录异常: {e}")
        return False

def query_id_photo(name: str, id_card: str) -> Dict[str, Any]:
    """查询身份证照片信息"""
    encoded_name = urllib.parse.quote(name)
    url = f"{BASE_URL}/Wechat/FaceDetect/GetGAIDCardPhotoNew?idCard={id_card}&name={encoded_name}"
    query_headers = {
        **HEADERS,
        "Referer": "http://www.gxdlys.com/Wechat/EcertCert/ECertApply?OperateType=0&BnsAcceptId=&ObjectId=&BasicBnsId=46011&Params=%E7%BB%8F%E8%90%A5%E6%80%A7%E9%81%93%E8%B7%AF%E8%B4%A7%E7%89%A9%E8%BF%90%E8%BE%93%E9%A9%BE%E9%A9%B6%E5%91%98&Step=1",
        "Host": "www.gxdlys.com"
    }
    try:
        r = session.get(url, headers=query_headers, timeout=60)
        if r.status_code == 200:
            return r.json()
        return {}
    except Exception as e:
        logger.error(f"查询异常: {e}")
        return {}

def download_photo(file_id: str) -> bytes:
    """下载照片二进制数据"""
    url = f"{BASE_URL}/System/FileService/ShowFile?fileId={file_id}"
    try:
        r = session.get(url, timeout=60)
        if r.status_code == 200 and 'image' in r.headers.get('Content-Type', ''):
            return r.content
        return None
    except Exception as e:
        logger.error(f"下载照片异常: {e}")
        return None

# ==================== Telegram Bot 处理函数 ====================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 欢迎使用证件查询助手！\n请先输入您的 **姓名**："
    )
    return NAME

async def get_name(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data['real_name'] = update.message.text.strip()
    await update.message.reply_text("📇 请输入您的 **身份证号**：")
    return IDCARD

async def get_idcard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    id_card = update.message.text.strip()
    if not re.match(r'^\d{17}[\dXx]$', id_card):
        await update.message.reply_text("❌ 身份证号格式不正确，请重新输入（18位数字或末尾X）：")
        return IDCARD
    context.user_data['id_card'] = id_card.upper()
    await update.message.reply_text("📱 请输入您的 **手机号**：")
    return PHONE

async def get_phone(update: Update, context: ContextTypes.DEFAULT_TYPE):
    phone = update.message.text.strip()
    if not re.match(r'^1\d{10}$', phone):
        await update.message.reply_text("❌ 手机号格式不正确，请重新输入（11位数字）：")
        return PHONE
    context.user_data['phone'] = phone

    await update.message.reply_text("⏳ 正在获取图形验证码并识别...")
    captcha_code, uuid = get_captcha()
    if not captcha_code or not uuid:
        await update.message.reply_text("❌ 获取验证码失败，请稍后重试。")
        return ConversationHandler.END

    context.user_data['uuid'] = uuid
    context.user_data['captcha_code'] = captcha_code
    await update.message.reply_text(f"✅ 图形验证码已识别：`{captcha_code}`")

    await update.message.reply_text("📤 正在发送短信验证码...")
    if send_sms(phone, captcha_code, uuid):
        await update.message.reply_text("📨 短信已发送，请查看手机，输入6位短信验证码：")
        return WAIT_SMS
    else:
        await update.message.reply_text("❌ 短信发送失败，请检查手机号或稍后重试。")
        return ConversationHandler.END

async def get_sms_code(update: Update, context: ContextTypes.DEFAULT_TYPE):
    sms_code = update.message.text.strip()
    if not re.match(r'^\d{6}$', sms_code):
        await update.message.reply_text("❌ 验证码应为6位数字，请重新输入：")
        return WAIT_SMS

    real_name = context.user_data['real_name']
    id_card = context.user_data['id_card']
    phone = context.user_data['phone']
    captcha_code = context.user_data['captcha_code']

    await update.message.reply_text("⏳ 正在注册账户...")
    if register(phone, sms_code, captcha_code, real_name, id_card):
        await update.message.reply_text("✅ 注册成功！正在登录...")
        if login(id_card):
            await update.message.reply_text("✅ 登录成功，正在查询身份证信息...")
            result = query_id_photo(real_name, id_card)
            if result and result.get("statusCode") == 200:
                data = result.get("data", {})
                item2 = data.get("item2", {})
                if item2:
                    xm = item2.get("xm", "")
                    sfz = item2.get("gmsfhm", "")
                    mz = item2.get("mz", "").replace("族", "")
                    qfjg = item2.get("issueD_UNIT", "")
                    zz = item2.get("fulladdr", "")
                    yxqq = item2.get("uL_FROM_DATE", "").replace("-", ".")
                    yxqz = item2.get("uL_END_DATE", "").replace("-", ".")
                    info = (
                        f"👤 姓名：{xm}\n"
                        f"🆔 身份证：{sfz}\n"
                        f"🌏 民族：{mz}\n"
                        f"🏛️ 签发机关：{qfjg}\n"
                        f"📍 住址：{zz}\n"
                        f"📅 有效期：{yxqq} 至 {yxqz}"
                    )
                    await update.message.reply_text(f"📄 身份信息：\n{info}")
                file_id = data.get("item1")
                if file_id:
                    img_data = download_photo(file_id)
                    if img_data:
                        await update.message.reply_photo(
                            photo=img_data,
                            caption=f"{real_name} 的身份证照片"
                        )
                    else:
                        await update.message.reply_text("⚠️ 照片下载失败。")
                else:
                    await update.message.reply_text("⚠️ 未找到照片。")
            else:
                await update.message.reply_text("❌ 查询身份信息失败。")
        else:
            await update.message.reply_text("❌ 登录失败，可能密码错误或账户异常。")
    else:
        await update.message.reply_text("❌ 注册失败，请检查信息是否正确或稍后重试。")

    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🚫 操作已取消。")
    return ConversationHandler.END

# ==================== 主函数 ====================
def main():
    # 🔑 在这里直接填入你的 Bot Token（从 @BotFather 获取）
    BOT_TOKEN = "8751644845:AAFiFgl6Qub_JFUnx7vW66DYP65qbRLOVVA"   # ← 请替换为实际 Token

    if not BOT_TOKEN or BOT_TOKEN == "你的BOT_TOKEN":
        logger.error("请先在代码中填入正确的 BOT_TOKEN")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_name)],
            IDCARD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_idcard)],
            PHONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_phone)],
            WAIT_SMS: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_sms_code)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    app.add_handler(conv_handler)
    app.add_handler(CommandHandler("help", lambda u,c: u.message.reply_text("使用 /start 开始注册流程。")))

    logger.info("Bot 启动...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
