import os, json, base64, sqlite3, shutil, win32crypt
from Crypto.Cipher import AES

def getkey(localstate):
    with open(localstate, "r", encoding="utf-8") as f:
        key = base64.b64decode(json.load(f)["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decryptpw(pw, key):
    return AES.new(key, AES.MODE_GCM, pw[3:15]).decrypt(pw[15:])[:-16].decode(errors="ignore")

def getfilename(folder, base_name):
    os.makedirs(folder, exist_ok=True)
    filename, ext = os.path.splitext(base_name)
    counter = 1
    new_filename = os.path.join(folder, base_name)
    while os.path.exists(new_filename):
        new_filename = os.path.join(folder, f"{filename}{counter}{ext}")
        counter += 1
    return new_filename

def menu():
    os.system("color 1")
    os.system("cls")
    print("Works with most Chromium based browsers")
    print("1 - Password Decryptor")
    print("2 - History Decryptor")
    opt = input("> ")
    if opt == "1":
        os.system("cls")
        localstate = input("Path to Local State file: ").strip('"')
        logindata = input("Path to Login Data file: ").strip('"')
        os.system("cls")
        shutil.copyfile(logindata, "temp.db")
        key, conn = getkey(localstate), sqlite3.connect("temp.db")
        cur, data = conn.cursor(), []
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        for url, user, pw in cur.fetchall():
            data.append(f"{url} | {user} | {decryptpw(pw, key)}")
        filename = getfilename("passwords", "passwords.txt")
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(data))
        conn.close(), os.remove("temp.db")
        print(f"Passwords saved to {filename}")
        os.system(f"start {filename}")
        os.system("pause")
        menu()
    elif opt == "2":
        os.system("cls")
        historydb = input("Path to history file: ").strip('"')
        os.system("cls")
        shutil.copyfile(historydb, "temp.db")
        conn = sqlite3.connect("temp.db")
        cur = conn.cursor()
        cur.execute("SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') FROM urls")
        data = [f"{row[1]} | {row[0]} | Last Visited: {row[2]}" for row in cur.fetchall()]
        filename = getfilename("history", "history.txt")
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(data))
        conn.close(), os.remove("temp.db")
        print(f"History saved to {filename}")
        os.system(f"start {filename}")
        os.system("pause")
        menu()
    else:
        menu()
menu()
