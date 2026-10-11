#the brain.
import sqlite3
import rsa
import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from keys import gen_keys

api = FastAPI()
conn = sqlite3.connect("data.db", check_same_thread=False, timeout=10)
conn.execute("PRAGMA journal_mode=WAL;")
conn.execute("PRAGMA synchronous=NORMAL;")
conn.execute("PRAGMA busy_timeout=5000;")
cur = conn.cursor()

class CreateUser(BaseModel):
    nick: str
    key: str
    passw: str

class LoginUser(BaseModel):
    nick: str
    passw: str

#CHECK if server keys are available/generated.
if os.path.exists(f"public.pem") and os.path.exists(f"private.pem"):
    print("----KEYS-OK----")
else:
    print("----KEYS-GENERATED----")
    gen_keys()

cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, nick TEXT NOT NULL UNIQUE, password TEXT NOT NULL, key TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);")
conn.commit()

@api.post('/cr-usr/')
def create_user(user: CreateUser, request: Request):
    ip = request.client.host
    cur.execute("SELECT * FROM users WHERE ip = ?", (ip,))
    #zacina od 0 (0=1)
    acc_count = len(cur.fetchall())
    if acc_count>=3:
        raise HTTPException(status_code=409, detail="Account count limit reached. (3)")
    else:
        try:
            cur.execute("INSERT INTO users (ip, nick, key, password) VALUES (?, ?, ?, ?)", (ip, user.nick, user.key, user.passw))
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Nick already taken")
        return {"status": "created", "nick": user.nick}

@api.get('/login')
def login(user: LoginUser):
    cur.execute("SELECT key,password FROM users WHERE nick = ?", (user.nick,))
    row = cur.fetchone()
    usr_key, usr_pass = row



@api.get('/public-key')
def serve_public_key():
    with open(f"public.pem", "r") as p_key:
        public_key = p_key.read()
    return public_key






#jak git commit, timto se utvrduje update tabulkyy
#conn.commit()
#zavre pripojeni k db
#conn.close()