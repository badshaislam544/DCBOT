"""
firebase_config.py - Firebase Admin connection (Render-ready)
Priority:
1. FIREBASE_CRED_JSON env (Render best - full JSON as string)
2. FIREBASE_CRED_PATH env (local path)
3. serviceAccountKey.json (local file, NEVER push to GitHub)
"""

import json
import os
import logging
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
log = logging.getLogger("guardian.firebase")

db = None
_BASE_DIR = Path(__file__).resolve().parent

try:
    import firebase_admin
    from firebase_admin import credentials, firestore

    def _init():
        global db
        if firebase_admin._apps:
            db = firestore.client()
            return db

        cred_json = os.getenv("FIREBASE_CRED_JSON", "").strip()
        cred_path = os.getenv("FIREBASE_CRED_PATH", "").strip()

        if cred_json:
            cred_dict = json.loads(cred_json)
            firebase_admin.initialize_app(credentials.Certificate(cred_dict))
            db = firestore.client()
            log.info("Firebase connected via FIREBASE_CRED_JSON")
            return db

        # 2. Path from env (backend/.env-এ FIREBASE_CRED_PATH)
        if cred_path:
            p = Path(cred_path)
            if not p.is_absolute():
                p = _BASE_DIR / p
            if p.exists():
                firebase_admin.initialize_app(credentials.Certificate(str(p)))
                db = firestore.client()
                log.info(f"Firebase connected via {p}")
                return db

        # 3. Local file fallback (backend/ ফোল্ডারে serviceAccountKey.json)
        local_key = _BASE_DIR / "serviceAccountKey.json"
        if local_key.exists():
            firebase_admin.initialize_app(
                credentials.Certificate(str(local_key))
            )
            db = firestore.client()
            log.info("Firebase connected via serviceAccountKey.json")
            return db

        log.warning("Firebase cred not found - running without Firebase.")
        return None

    _init()

except Exception as e:
    log.warning(f"Firebase init skip: {e}")
    db = None


def get_db():
    return db


def log_security_event(event_type: str, description: str, status: str = "Blocked"):
    """Firestore security_logs-এ save. Firebase না থাকলে শুধু print."""
    print(f"[{event_type}] {description}")
    if db is None:
        return None
    try:
        from firebase_admin import firestore as fs

        doc_ref = db.collection("security_logs").document()
        doc_ref.set(
            {
                "type": event_type,
                "description": description,
                "timestamp": fs.SERVER_TIMESTAMP,
                "status": status,
            }
        )
        return doc_ref.id
    except Exception as e:
        log.error(f"Firestore save failed: {e}")
        return None
