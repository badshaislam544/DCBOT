"""
Discord Guardian - Backend + Bot + API (Render-ready)
- Discord Bot: channel delete auto-recovery, anti-spam, role/ban detect
- Firebase: firebase_config.log_security_event() -> security_logs
- FastAPI: keep-alive + Dashboard API (/health, /events)
Deploy: GitHub-এ backend/ ফোল্ডারের ভেতরের ফাইল push -> Render Web Service
"""

import asyncio
import logging
import os

import discord
from discord.ext import commands
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from dotenv import load_dotenv

from firebase_config import db, log_security_event

# ---------- Setup ----------
load_dotenv()
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("guardian")

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")
PORT = int(os.getenv("PORT", "8000"))

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
    }


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
