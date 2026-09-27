#the brain.
import sqlite3
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel

api = FastAPI()
conn = sqlite3.connect("data.db", check_same_thread=False)
cur = conn.cursor()

class CreateUser(BaseModel):
    nick: str
    key: str

cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, nick TEXT NOT NULL UNIQUE, key TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);")
conn.commit()

@api.post('/cr-usr/')
def create_user(user: CreateUser, request: Request):
    ip = request.client.host
    cur.execute("SELECT * FROM users WHERE ip == ?", (ip,))
    #zacina od 0 (0=1)
    acc_count = len(cur.fetchall())
    if acc_count>=3:
        raise HTTPException(status_code=409, detail="Account count limit reached. (3)")

    else:
        try:
            cur.execute("INSERT INTO users (ip, nick, key) VALUES (?, ?, ?)", (ip, user.nick, user.key))
            conn.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Nick already taken")
        return {"status": "created", "nick": user.nick}




#jak git commit, timto se utvrduje update tabulkyy
#conn.commit()
#zavre pripojeni k db
#conn.close()