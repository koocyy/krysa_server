#the brain.
import base64
import hmac
import os
import secrets
import sqlite3
import string
import time

import rsa
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

from keys import gen_keys

api = FastAPI()
conn = sqlite3.connect("data.db", check_same_thread=False, timeout=10)
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("PRAGMA synchronous=NORMAL;")
conn.execute("PRAGMA busy_timeout=5000;")
cur = conn.cursor()

SESSION_TTL = 86400
LOGIN_CHALLENGE_TTL = 60
sessions = {}
login_challenges = {}


class CreateUser(BaseModel):
    nick: str
    key: str
    passw: str


class LoginStart(BaseModel):
    nick: str


class LoginFinish(BaseModel):
    nick: str
    challenge: str
    enc_password_b64: str


class UserInteract(BaseModel):
    nick: str
    session: str
    data: str


#CHECK if server keys are available/generated.
if os.path.exists("public.pem") and os.path.exists("private.pem"):
    print("----KEYS-OK----")
else:
    print("----KEYS-GENERATED----")
    gen_keys()

cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, nick TEXT NOT NULL UNIQUE, password TEXT NOT NULL, key TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);")
conn.commit()


def _new_challenge(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def _new_session(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


@api.post('/cr-usr/')
def create_user(user: CreateUser, request: Request):
    ip = request.client.host
    cur.execute("SELECT * FROM users WHERE ip = ?", (ip,))
    #zacina od 0 (0=1)
    acc_count = len(cur.fetchall())
    if acc_count >= 3:
        raise HTTPException(status_code=409, detail="Account count limit reached. (3)")
    else:
        try:
            cur.execute("INSERT INTO users (ip, nick, key, password) VALUES (?, ?, ?, ?)", (ip, user.nick, user.key, user.passw))
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Nick already taken")
        return {"status": "created", "nick": user.nick}


@api.post('/login/start')
def login_start(user: LoginStart):
    cur.execute("SELECT key FROM users WHERE nick = ?", (user.nick,))
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        user_public_key = rsa.PublicKey.load_pkcs1(row[0].encode("utf-8"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Stored user key is invalid")

    challenge = _new_challenge()
    login_challenges[user.nick] = {"value": challenge, "exp": time.time() + LOGIN_CHALLENGE_TTL}
    encrypted_challenge = rsa.encrypt(challenge.encode("utf-8"), user_public_key)

    return {"challenge_b64": base64.b64encode(encrypted_challenge).decode("ascii")}


@api.post('/login/finish')
def login_finish(user: LoginFinish):
    entry = login_challenges.pop(user.nick, None)
    if entry is None or entry["exp"] < time.time():
        raise HTTPException(status_code=401, detail="Challenge missing or expired")

    if not hmac.compare_digest(entry["value"], user.challenge):
        raise HTTPException(status_code=401, detail="Challenge invalid")

    try:
        with open("private.pem", "rb") as private_key_file:
            server_private_key = rsa.PrivateKey.load_pkcs1(private_key_file.read())

        encrypted_password = base64.b64decode(user.enc_password_b64)
        plaintext_password = rsa.decrypt(encrypted_password, server_private_key).decode("utf-8")
    except (ValueError, UnicodeDecodeError, rsa.pkcs1.CryptoError):
        raise HTTPException(status_code=400, detail="Encrypted password is invalid")

    cur.execute("SELECT password FROM users WHERE nick = ?", (user.nick,))
    row = cur.fetchone()
    if row is None or not hmac.compare_digest(row[0], plaintext_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session_id = _new_session()
    session_exp = time.time() + SESSION_TTL
    sessions[user.nick] = {"session_id": session_id, "exp": session_exp}

    return {"status": "ok", "session_id": session_id, "exp": session_exp}

@api.post('/message/send')
def send_message(user: UserInteract):
    session = sessions.get(user.nick)
    if session["session_id"]==user.session:
        return {"status": "ok"}

    elif user.session is None:
        raise HTTPException(status_code=401, detail="No session id supplied")

    else:
        raise HTTPException(status_code=401, detail="Invalid session id")




@api.get('/public-key')
def serve_public_key():
    with open("public.pem", "r") as p_key:
        public_key = p_key.read()
    return public_key


#jak git commit, timto se utvrduje update tabulkyy
#conn.commit()
#zavre pripojeni k db
#conn.close()
