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
import urllib.parse

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
load_dotenv()
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


@bot.event
async def on_guild_channel_delete(channel):
    guild_name = getattr(getattr(channel, "guild", None), "name", "unknown")
    print(f"Channel Deleted: {channel.name} in {guild_name}. Attempting recovery...")

    log_security_event(
        "CHANNEL_DELETE", f"Channel #{channel.name} was deleted in {guild_name}."
    )

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
    except discord.Forbidden:
        print("Failed to recover channel: Missing Permissions (Manage Channels needed).")
    except Exception as e:
        print(f"Failed to recover channel: {e}")


@bot.event
async def on_guild_role_delete(role):
    print(f"Role deleted: {role.name} in {role.guild.name}")
    log_security_event(
        "ROLE_DELETE", f"Role '{role.name}' was deleted in {role.guild.name}."
    )


@bot.event
async def on_member_ban(guild, user):
    print(f"Member banned: {user} in {guild.name}")
    log_security_event("MEMBER_BAN", f"{user} was banned in {guild.name}.")


SPAM_KEYWORDS = ("free-nitro", "free nitro", "@everyone", "@here")

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    content = message.content.lower()
    is_spam = (
        "http://" in content
        or any(k in content for k in SPAM_KEYWORDS)
        or content.count("https://") >= 3
    )

    if is_spam:
        try:
            await message.delete()
            print(f"Spam detected and deleted from {message.author}")
            log_security_event(
                "SPAM_DETECTED",
                f"Spam message from {message.author} deleted in #{getattr(message.channel, 'name', 'DM')}.",
            )
            warn = await message.channel.send(
                f"{message.author.mention}, spam link auto-removed by Guardian."
            )
            await asyncio.sleep(5)
            await warn.delete()
        except discord.Forbidden:
            print("Spam delete failed: Manage Messages permission needed.")
        except Exception as e:
            print(f"Spam handler error: {e}")
        return

    await bot.process_commands(message)


@bot.command(name="ping")
async def ping(ctx):
    await ctx.send(f"Pong! Guardian Online ({round(bot.latency * 1000)}ms)")


@bot.command(name="shield")
async def shield(ctx):
    await ctx.send("Guardian Shield: **ONLINE** — Server is being watched.")


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
