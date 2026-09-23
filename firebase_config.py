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

from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("guardian.firebase")

db = None

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

        if cred_path and os.path.exists(cred_path):
            firebase_admin.initialize_app(credentials.Certificate(cred_path))
            db = firestore.client()
            log.info(f"Firebase connected via {cred_path}")
            return db

        if os.path.exists("serviceAccountKey.json"):
            firebase_admin.initialize_app(
                credentials.Certificate("serviceAccountKey.json")
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
