#the brain.
import sqlite3

conn = sqlite3.connect("data.db")
cur = conn.cursor()


#jak git commit, timto se utvrduje update tabulky
conn.commit()
#zavre pripojeni k db
conn.close()