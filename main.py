"""
Discord Guardian - Backend + Bot + API (Render-ready)
- Discord Bot: channel delete auto-recovery, anti-spam, role/ban detect
- Firebase: firebase_config.log_security_event() -> security_logs
- FastAPI: keep-alive + Dashboard API (/health, /events)
Deploy: GitHub-এ backend/ ফোল্ডারের ভেতরের ফাইল push -> Render Web Service
"""

import asyncio
import base64
import json
import logging
import os
import time
import urllib.parse
from collections import defaultdict, deque
from pathlib import Path

import discord
from discord.ext import commands
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
import requests
import uvicorn
from dotenv import load_dotenv

from firebase_config import db, log_security_event

# ---------- Setup ----------
# .env সবসময় backend/ ফোল্ডার থেকে লোড হবে (root থেকে রান করলেও)
load_dotenv(Path(__file__).resolve().parent / ".env")
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("guardian")

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
PORT = int(os.getenv("PORT", "8000"))

# Discord OAuth (Dashboard login-এর জন্য)
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "")
# Render-এ এটা হবে: https://dcbot-w5ky.onrender.com/auth/callback
DISCORD_REDIRECT_URI = os.getenv(
    "DISCORD_REDIRECT_URI", "https://dcbot-w5ky.onrender.com/auth/callback"
)
# Login-এর পর কোথায় ফেরত যাবে (Netlify URL, না থাকলে backend root)
FRONTEND_URL = os.getenv("FRONTEND_URL", "").rstrip("/")
# কোন Discord ID-রা Admin (comma-separated), না দিলে সবাই login করতে পারবে
ADMIN_IDS = {
    x.strip() for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()
}

# Alert কোন চ্যানেলে পোস্ট হবে (Channel ID, ফাঁকা রাখলে শুধু Firebase-এ যাবে)
# Channel-এ Right Click > Copy Channel ID (Developer Mode ON করে)
LOG_CHANNEL_ID = os.getenv("LOG_CHANNEL_ID", "").strip()

# ---------- Anti-spam rules (সংখ্যা বদলাতে চাইলে এখানেই) ----------
SPAM_KEYWORDS = ("free-nitro", "free nitro", "@everyone", "@here", "discord.gg/")
FLOOD_COUNT_5S = 4      # ৫ সেকেন্ডে ৪টার বেশি মেসেজ = flood
FLOOD_WINDOW_5S = 5.0
FAST_COUNT_MIN = 10     # ১ মিনিটে ১০টার বেশি মেসেজ = fast spam
REPEAT_COUNT_MIN = 3    # ১ মিনিটে একই মেসেজ ৩বার = repeat spam
IMAGE_COUNT_5S = 2      # ৫ সেকেন্ডে ২টার বেশি ছবি/ফাইল = image spam
IMAGE_WINDOW_5S = 5.0
TIMEOUT_SECONDS = 60    # spam করলে কত সেকেন্ড timeout

# ---------- Stats + trackers (memory, restart হলে reset) ----------
STATS = {"messages_seen": 0, "spam_blocked": 0, "channels_recovered": 0}
START_TIME = time.time()
_msg_times: dict[int, deque] = defaultdict(deque)   # user_id -> timestamps
_img_times: dict[int, deque] = defaultdict(deque)   # user_id -> attachment times
_last_text: dict[int, tuple[str, int, float]] = {}   # user_id -> (text, repeat, window_start)


async def send_log_channel(text: str):
    """LOG_CHANNEL_ID থাকলে Discord চ্যানেলেও alert পাঠায়।"""
    if not LOG_CHANNEL_ID or not bot.is_ready():
        return
    try:
        ch = bot.get_channel(int(LOG_CHANNEL_ID))
        if ch is None:
            ch = await bot.fetch_channel(int(LOG_CHANNEL_ID))
        await ch.send(text[:1900])
    except Exception as e:
        print(f"Log channel send failed: {e}")


async def get_executor(guild: discord.Guild, action: discord.AuditLogAction) -> str:
    """কে কাজটা করলো (audit log থেকে)। Permission না থাকলে 'unknown'।"""
    try:
        async for entry in guild.audit_logs(limit=1, action=action):
            if time.time() - entry.created_at.timestamp() < 30:
                return f"{entry.user} (ID: {entry.user.id})"
    except discord.Forbidden:
        pass
    except Exception:
        pass
    return "unknown"

# ---------- Discord Bot ----------
# Developer Portal-এ ON করুন: Server Members Intent + Message Content Intent
intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.messages = True
intents.message_content = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"Security Guardian Logged in as {bot.user.name} (ID: {bot.user.id})")
    print("Security Guardian is active and watching...")
    # Deploy/restart-এর পর dashboard-এ অন্তত ১টা log দেখাবে (খালি লাগবে না)
    log_security_event(
        "GUARDIAN_ONLINE", f"{bot.user.name} is now watching {len(bot.guilds)} server(s)."
    )


@bot.event
async def on_guild_channel_delete(channel):
    guild = getattr(channel, "guild", None)
    guild_name = getattr(guild, "name", "unknown")
    print(f"Channel Deleted: {channel.name} in {guild_name}. Attempting recovery...")

    culprit = await get_executor(guild, discord.AuditLogAction.channel_delete) if guild else "unknown"
    desc = f"Channel #{channel.name} was deleted in {guild_name} by {culprit}."
    log_security_event("CHANNEL_DELETE", desc)
    await send_log_channel(f"⚠️ **Channel deleted:** #{channel.name} | by {culprit}")

    try:
        guild = channel.guild
        category = getattr(channel, "category", None)
        overwrites = getattr(channel, "overwrites", None)
        position = getattr(channel, "position", None)

        if isinstance(channel, discord.TextChannel):
            kwargs = {}
            if getattr(channel, "topic", None):
                kwargs["topic"] = channel.topic
            if getattr(channel, "slowmode_delay", 0):
                kwargs["slowmode_delay"] = channel.slowmode_delay
            if getattr(channel, "nsfw", False):
                kwargs["nsfw"] = True
            new_channel = await guild.create_text_channel(
                name=channel.name,
                category=category,
                overwrites=overwrites,
                position=position,
                reason="Guardian auto-recovery",
                **kwargs,
            )
        elif isinstance(channel, discord.VoiceChannel):
            new_channel = await guild.create_voice_channel(
                name=channel.name,
                category=category,
                overwrites=overwrites,
                position=position,
                reason="Guardian auto-recovery",
            )
        else:
            new_channel = await channel.clone(reason="Guardian auto-recovery")

        print(f"Channel #{new_channel.name} successfully recovered!")
        STATS["channels_recovered"] += 1
        await send_log_channel(f"✅ **Recovered:** #{new_channel.name} (auto-recreated)")
    except discord.Forbidden:
        print("Failed to recover channel: Missing Permissions (Manage Channels needed).")
    except Exception as e:
        print(f"Failed to recover channel: {e}")


@bot.event
async def on_guild_role_delete(role):
    print(f"Role deleted: {role.name} in {role.guild.name}")
    culprit = await get_executor(role.guild, discord.AuditLogAction.role_delete)
    desc = f"Role '{role.name}' was deleted in {role.guild.name} by {culprit}."
    log_security_event("ROLE_DELETE", desc)
    await send_log_channel(f"⚠️ **Role deleted:** {role.name} | by {culprit}")


@bot.event
async def on_member_ban(guild, user):
    print(f"Member banned: {user} in {guild.name}")
    culprit = await get_executor(guild, discord.AuditLogAction.ban)
    desc = f"{user} was banned in {guild.name} by {culprit}."
    log_security_event("MEMBER_BAN", desc)
    await send_log_channel(f"🔨 **Ban:** {user} | by {culprit}")


@bot.event
async def on_webhooks_update(channel):
    """হ্যাকাররা webhook বানিয়ে spam করে — এটা সেই early warning।"""
    guild_name = getattr(getattr(channel, "guild", None), "name", "unknown")
    desc = f"Webhooks updated in #{getattr(channel, 'name', '?')} ({guild_name}). Check audit log!"
    print(f"⚠️ {desc}")
    log_security_event("WEBHOOK_UPDATE", desc)
    await send_log_channel(f"🪝 **Webhook change:** {desc}")


def _check_rate_spam(user_id: int, text: str, has_attach: bool, now: float) -> str:
    """Sliding-window চেক। spam হলে কারণ string, না হলে ''।"""
    # ৫ সেকেন্ডে ৪টার বেশি মেসেজ
    q = _msg_times[user_id]
    q.append(now)
    while q and now - q[0] > FLOOD_WINDOW_5S:
        q.popleft()
    if len(q) > FLOOD_COUNT_5S:
        return f"flood ({len(q)} msgs / 5s)"

    # ১ মিনিটে অনেক মেসেজ (slow flood)
    if sum(1 for t in q if now - t <= 60) > FAST_COUNT_MIN:
        return "fast spam (10+ msgs / 1min)"

    # একই মেসেজ বারবার
    prev_text, prev_n, prev_start = _last_text.get(user_id, ("", 0, now))
    if text and text == prev_text and now - prev_start <= 60:
        n = prev_n + 1
    else:
        n = 1
        prev_start = now
    _last_text[user_id] = (text, n, prev_start)
    if text and n >= REPEAT_COUNT_MIN:
        return f"repeat spam (same msg x{n})"

    # ৫ সেকেন্ডে ২টার বেশি ছবি/ফাইল
    if has_attach:
        iq = _img_times[user_id]
        iq.append(now)
        while iq and now - iq[0] > IMAGE_WINDOW_5S:
            iq.popleft()
        if len(iq) > IMAGE_COUNT_5S:
            return f"image spam ({len(iq)} files / 5s)"

    return ""


async def _punish(message: discord.Message, reason: str):
    """Delete + timeout + Firebase log + log channel।"""
    author = message.author
    where = f"#{getattr(message.channel, 'name', 'DM')}"
    print(f"Spam [{reason}] from {author} in {where}")
    STATS["spam_blocked"] += 1
    desc = f"Spam [{reason}] from {author} deleted in {where}."
    log_security_event("SPAM_DETECTED", desc)
    await send_log_channel(f"🚨 **Spam blocked:** {author} in {where} | {reason}")

    try:
        await message.delete()
    except Exception:
        pass
    # ৬০ সেকেন্ড timeout (permission না থাকলে শুধু delete হবে)
    try:
        if message.guild:
            member = message.guild.get_member(author.id)
            if member:
                await member.timeout(
                    discord.utils.utcnow()
                    + __import__("datetime").timedelta(seconds=TIMEOUT_SECONDS),
                    reason=f"Guardian anti-spam: {reason}",
                )
    except discord.Forbidden:
        print("Timeout failed: Moderate Members permission needed.")
    except Exception as e:
        print(f"Timeout error: {e}")
    try:
        warn = await message.channel.send(
            f"⚠️ {author.mention}, spam detected ({reason}). {TIMEOUT_SECONDS}s timeout."
        )
        await asyncio.sleep(6)
        await warn.delete()
    except Exception:
        pass


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    now = time.time()
    content = (message.content or "").lower().strip()
    has_attach = bool(message.attachments)
    STATS["messages_seen"] += 1

    # --- DM (bot-এর inbox): শুধু bot-কে পাঠানো DM দেখা যায় ---
    if message.guild is None:
        bad_link = "http://" in content or "free-nitro" in content or "discord.gg/" in content
        q = _msg_times[message.author.id]
        q.append(now)
        while q and now - q[0] > 10:
            q.popleft()
        if bad_link or len(q) > 3:
            await _punish(message, "DM spam")
            try:
                await message.channel.send("This inbox is protected by Guardian.")
            except Exception:
                pass
        return

    # --- Server messages ---
    # Admin/Mod-দের skip (নিজের staff-কে punish করবে না)
    try:
        if isinstance(message.author, discord.Member) and message.author.guild_permissions.manage_messages:
            await bot.process_commands(message)
            return
    except Exception:
        pass

    # ১. Dangerous keyword/link
    keyword_hit = (
        "http://" in content
        or any(k in content for k in SPAM_KEYWORDS)
        or content.count("https://") >= 3
    )
    if keyword_hit:
        await _punish(message, "bad link/keyword")
        return

    # ২. Rate-limit rules (৫সে flood / ১মি fast / repeat / image)
    reason = _check_rate_spam(message.author.id, content, has_attach, now)
    if reason:
        await _punish(message, reason)
        return

    await bot.process_commands(message)


@bot.command(name="ping")
async def ping(ctx):
    await ctx.send(f"Pong! Guardian Online ({round(bot.latency * 1000)}ms)")


@bot.command(name="shield")
async def shield(ctx):
    await ctx.send("Guardian Shield: **ONLINE** — Server is being watched.")


@bot.command(name="lockdown")
@commands.has_guild_permissions(manage_guild=True)
async def lockdown(ctx):
    """হ্যাক সন্দেহ হলে সার্ভার freeze: @everyone মেসেজ বন্ধ।"""
    try:
        await ctx.channel.set_permissions(
            ctx.guild.default_role, send_messages=False, reason="Guardian lockdown"
        )
        log_security_event("LOCKDOWN", f"Lockdown by {ctx.author} in #{ctx.channel.name}.")
        await send_log_channel(f"🔒 **Lockdown:** #{ctx.channel.name} by {ctx.author}")
        await ctx.send("🔒 Channel locked by Guardian.")
    except discord.Forbidden:
        await ctx.send("❌ Need Manage Channels permission.")


@bot.command(name="unlock")
@commands.has_guild_permissions(manage_guild=True)
async def unlock(ctx):
    try:
        await ctx.channel.set_permissions(
            ctx.guild.default_role, send_messages=None, reason="Guardian unlock"
        )
        log_security_event("UNLOCK", f"Unlock by {ctx.author} in #{ctx.channel.name}.")
        await ctx.send("🔓 Channel unlocked.")
    except discord.Forbidden:
        await ctx.send("❌ Need Manage Channels permission.")


# ---------- FastAPI ----------
app = FastAPI(title="Discord Guardian")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    print("Guardian Backend is running 24/7!")
    return {"status": "Guardian System is Running 24/7", "shield": "Active"}


@app.get("/health")
def health():
    return {
        "bot_online": bot.is_ready(),
        "bot_user": str(bot.user) if bot.is_ready() else None,
        "guilds": len(bot.guilds) if bot.is_ready() else 0,
        "firebase": db is not None,
        "oauth_ready": bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET),
        "uptime_sec": int(time.time() - START_TIME),
        "messages_seen": STATS["messages_seen"],
        "spam_blocked": STATS["spam_blocked"],
        "channels_recovered": STATS["channels_recovered"],
        "log_channel": bool(LOG_CHANNEL_ID),
    }


# ---------- Discord OAuth Login ----------
@app.get("/auth/login")
def auth_login(frontend: str = ""):
    """Dashboard Login বাটন এখানে আসবে -> Discord-এ পাঠিয়ে দেবে।"""
    if not DISCORD_CLIENT_ID:
        return JSONResponse(
            {"error": "DISCORD_CLIENT_ID সেট নেই (Render env-এ বসান)"},
            status_code=500,
        )
    # frontend মনে রাখি যাতে callback-এর পর সেখানে ফেরত যেতে পারি
    state = base64.urlsafe_b64encode(
        json.dumps({"frontend": frontend or FRONTEND_URL}).encode()
    ).decode()
    params = urllib.parse.urlencode(
        {
            "client_id": DISCORD_CLIENT_ID,
            "redirect_uri": DISCORD_REDIRECT_URI,
            "response_type": "code",
            "scope": "identify guilds",
            "state": state,
        }
    )
    return RedirectResponse(f"https://discord.com/api/oauth2/authorize?{params}")


@app.get("/auth/callback")
def auth_callback(code: str = "", state: str = ""):
    """Discord থেকে ফেরত এসে token exchange + user info + frontend-এ redirect।"""
    if not code:
        return JSONResponse({"error": "code missing"}, status_code=400)
    if not (DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET):
        return JSONResponse({"error": "OAuth env সেট নেই"}, status_code=500)

    # frontend URL বের করি
    frontend = FRONTEND_URL
    try:
        if state:
            frontend = (
                json.loads(base64.urlsafe_b64decode(state.encode()).decode()).get(
                    "frontend"
                )
                or FRONTEND_URL
            )
    except Exception:
        pass

    # 1. code -> access_token
    try:
        token_res = requests.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        token_data = token_res.json()
        access_token = token_data.get("access_token", "")
        if not access_token:
            return JSONResponse(
                {"error": "token exchange failed", "detail": token_data},
                status_code=400,
            )
    except Exception as e:
        return JSONResponse({"error": f"token error: {e}"}, status_code=500)

    # 2. user info
    try:
        me = requests.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=15,
        ).json()
    except Exception as e:
        return JSONResponse({"error": f"user fetch failed: {e}"}, status_code=500)

    user_id = str(me.get("id", ""))
    is_admin = (not ADMIN_IDS) or (user_id in ADMIN_IDS)
    payload = {
        "id": user_id,
        "username": me.get("username", ""),
        "discriminator": me.get("discriminator", "0"),
        "avatar": me.get("avatar"),
        "is_admin": is_admin,
    }
    # avatar URL বানিয়ে দিই
    if payload["avatar"]:
        payload["avatar_url"] = (
            f"https://cdn.discordapp.com/avatars/{user_id}/{payload['avatar']}.png"
        )
    else:
        payload["avatar_url"] = (
            f"https://cdn.discordapp.com/embed/avatars/{int(me.get('discriminator','0')) % 5}.png"
        )

    # 3. frontend callback-এ পাঠাই (token backend-এ রাখি না — stateless)
    user_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    if frontend:
        return RedirectResponse(f"{frontend.rstrip('/')}/callback.html#user={user_b64}")
    return JSONResponse(payload)


@app.get("/events")
def recent_events(limit: int = 20):
    if db is None:
        return {"events": [], "note": "Firebase not connected yet"}
    try:
        docs = (
            db.collection("security_logs")
            .order_by("timestamp", direction="DESCENDING")
            .limit(limit)
            .stream()
        )
        events = []
        for d in docs:
            data = d.to_dict() or {}
            ts = data.get("timestamp")
            if hasattr(ts, "isoformat"):
                data["timestamp"] = ts.isoformat()
            events.append({"id": d.id, **data})
        return {"events": events}
    except Exception as e:
        log.error(f"/events failed: {e}")
        return {"events": [], "error": str(e)}


# ---------- Run both together ----------
async def main():
    if not DISCORD_TOKEN or DISCORD_TOKEN == "PASTE_YOUR_BOT_TOKEN_HERE":
        print("DISCORD_TOKEN missing! Set it in .env (local) or Render Environment.")
        print("API-only mode: uvicorn main:app --port 8000")
        config = uvicorn.Config(app, host="0.0.0.0", port=PORT)
        server = uvicorn.Server(config)
        await server.serve()
        return

    config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="info")
    server = uvicorn.Server(config)
    await asyncio.gather(
        server.serve(),
        bot.start(DISCORD_TOKEN),
    )


if __name__ == "__main__":
    asyncio.run(main())
