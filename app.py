
import os
import json
import subprocess
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, render_template, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "ANKA_ULTRA_SUPER_KEY"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Klasörler
os.makedirs("uploads", exist_ok=True)
os.makedirs("veri", exist_ok=True)

KEYS_FILE = "veri/keys.json"
USERS_FILE = "veri/users.json"
SUPPORT_FILE = "veri/destek.json"
ACTIVITY_FILE = "veri/activity.json"

active_processes = {}

def load_json(p):
    if not os.path.exists(p):
        return {} if p != ACTIVITY_FILE else []
    with open(p, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return {} if p != ACTIVITY_FILE else []

def save_json(p, d):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)

def log_activity(entry):
    logs = load_json(ACTIVITY_FILE)
    if not isinstance(logs, list):
        logs = []
    logs.append({"time": datetime.now().isoformat(), **entry})
    save_json(ACTIVITY_FILE, logs)

def ensure_admin():
    keys = load_json(KEYS_FILE)
    admin_key = "panel key.90897867keykey"
    if admin_key not in keys:
        keys[admin_key] = {"rol":"admin","bitis":(datetime.now()+timedelta(days=365)).strftime("%Y-%m-%d"),"perms":["manage_keys","view_support","view_stats","manage_users"]}
        save_json(KEYS_FILE, keys)

def key_valid(k):
    keys = load_json(KEYS_FILE)
    info = keys.get(k)
    if not info:
        return False
    try:
        exp = datetime.strptime(info.get("bitis","1970-01-01"), "%Y-%m-%d")
        return datetime.now() <= exp
    except:
        return False

def is_admin(k):
    keys = load_json(KEYS_FILE)
    return keys.get(k, {}).get("rol") == "admin"

def has_perm(k, perm):
    keys = load_json(KEYS_FILE)
    info = keys.get(k, {})
    if info.get("rol") != "admin":
        return False
    return perm in info.get("perms", [])

def get_user_dir(k):
    path = os.path.join("uploads", k)
    os.makedirs(path, exist_ok=True)
    return path

def prune_processes():
    for k in list(active_processes.keys()):
        for fn in list(active_processes[k].keys()):
            proc = active_processes[k][fn]
            if proc.poll() is not None:
                del active_processes[k][fn]
        if not active_processes[k]:
            del active_processes[k]

def total_running():
    prune_processes()
    return sum(len(v) for v in active_processes.values())

# Başlangıç
ensure_admin()
for fp in [USERS_FILE, SUPPORT_FILE, ACTIVITY_FILE]:
    if not os.path.exists(fp):
        save_json(fp, {} if fp != ACTIVITY_FILE else [])

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        key = request.form.get("key","").strip()
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        users = load_json(USERS_FILE)
        if username and password:
            user = users.get(username)
            if user and check_password_hash(user.get("password",""), password):
                session["user"] = username
                session["key"] = user.get("key")
                log_activity({"action":"login_user","username":username})
                if is_admin(session["key"]):
                    return redirect("/admin")
                return redirect("/panel")
            flash("Kullanıcı/parola yanlış.","error")
        elif key:
            if key_valid(key):
                session["key"] = key
                # find user owning key
                users = load_json(USERS_FILE)
                for u, info in users.items():
                    if info.get("key") == key:
                        session["user"] = u
                        break
                log_activity({"action":"login_key","key":key})
                if is_admin(key):
                    return redirect("/admin")
                return redirect("/panel")
            flash("KEY geçersiz veya süresi dolmuş.","error")
        else:
            flash("Giriş bilgisi eksik.","error")
    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        if not username or not password:
            flash("Eksik alan.","error")
            return redirect("/register")
        users = load_json(USERS_FILE)
        if username in users:
            flash("Kullanıcı zaten var.","error")
            return redirect("/register")
        # oluştur KEY
        new_key = f"userkey.{secrets.token_hex(8)}"
        expiry = (datetime.now()+timedelta(days=30)).strftime("%Y-%m-%d")
        # kaydet key
        keys = load_json(KEYS_FILE)
        keys[new_key] = {"rol":"uye","bitis":expiry,"perms":[]}
        save_json(KEYS_FILE, keys)
        # kullanıcı
        users[username] = {"password":generate_password_hash(password), "key": new_key}
        save_json(USERS_FILE, users)
        flash(f"Kaydoldun. KEY’in: {new_key}","success")
        return redirect("/")
    return render_template("register.html")

@app.route("/panel")
def panel():
    if "key" not in session:
        return redirect("/")
    key = session["key"]
    if not key_valid(key):
        session.clear()
        return redirect("/")
    if is_admin(key):
        return redirect("/admin")
    user = session.get("user", key)
    user_dir = get_user_dir(key)
    dosyalar = [f for f in os.listdir(user_dir) if f.endswith(".py")]
    support_data = load_json(SUPPORT_FILE)
    user_supports = support_data.get(key, [])
    new_replies=[]
    for entry in user_supports:
        if entry.get("admin_seen") is False and entry.get("messages"):
            # if last message from admin and user hasn't seen
            last = entry["messages"][-1]
            if last["sender"]=="admin" and not entry.get("user_seen", False):
                new_replies.append({"konu":entry.get("konu"),"yanit":last["text"]})
                entry["user_seen"]=True
    support_data[key]=user_supports
    save_json(SUPPORT_FILE,support_data)
    return render_template("user_panel.html", dosyalar=dosyalar, user=user, destekler=user_supports, new_replies=new_replies)

@app.route("/upload", methods=["POST"])
def upload():
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if not key_valid(key):
        session.clear()
        return redirect("/")
    if 'dosya' not in request.files:
        flash("Dosya yok.","error"); return redirect("/panel")
    file=request.files["dosya"]
    if not file.filename.endswith(".py"):
        flash(".py yükle.","error"); return redirect("/panel")
    user_dir=get_user_dir(key)
    target=os.path.join(user_dir,file.filename)
    if os.path.exists(target):
        base,ext=os.path.splitext(file.filename)
        target=os.path.join(user_dir,f"{base}_{datetime.now().strftime('%H%M%S')}{ext}")
    file.save(target)
    log_activity({"action":"upload","key":key,"file":os.path.basename(target)})
    flash("Yüklendi.","success")
    return redirect("/panel")

@app.route("/run/<filename>")
def run_file(filename):
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if not key_valid(key):
        session.clear()
        return redirect("/")
    if total_running()>=30:
        flash("Limit dolu.","error"); return redirect("/panel")
    user_dir=get_user_dir(key)
    filepath=os.path.join(user_dir,filename)
    if not os.path.exists(filepath):
        flash("Yok.","error"); return redirect("/panel")
    logpath=os.path.join(user_dir,f"{filename}.log")
    proc=subprocess.Popen(["python3",filepath], stdout=open(logpath,"w"), stderr=subprocess.STDOUT)
    active_processes.setdefault(key,{})[filename]=proc
    log_activity({"action":"run","key":key,"file":filename})
    flash("Çalıştırıldı.","success")
    return redirect("/panel")

@app.route("/stop/<filename>")
def stop_file(filename):
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if key in active_processes and filename in active_processes.get(key,{}):
        proc=active_processes[key][filename]
        proc.terminate()
        log_activity({"action":"stop","key":key,"file":filename})
        flash("Durduruldu.","success")
    else:
        flash("Yok.","error")
    return redirect("/panel")

@app.route("/log/<filename>")
def view_log(filename):
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    user_dir=get_user_dir(key)
    logpath=os.path.join(user_dir,f"{filename}.log")
    if not os.path.exists(logpath):
        log_content="Yok."
    else:
        with open(logpath,"r",encoding="utf-8",errors="ignore") as f:
            log_content=f.read()
    return render_template("log.html", log=log_content, filename=filename)

@app.route("/destek", methods=["GET","POST"])
def destek():
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if request.method=="POST":
        konu=request.form.get("konu","Genel")
        mesaj=request.form.get("mesaj","")
        support_data=load_json(SUPPORT_FILE)
        ticket_id = secrets.token_hex(6)
        entry={"id":ticket_id,"konu":konu,"created":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),"status":"open","messages":[{"sender":"user","text":mesaj,"tarih":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}],"user_seen":False}
        support_data.setdefault(key,[]).append(entry)
        save_json(SUPPORT_FILE,support_data)
        log_activity({"action":"new_ticket","key":key,"ticket_id":ticket_id})
        socketio.emit("new_support", {"kullanici":key,"konu":konu}, broadcast=True)
        flash("Yeni talep oluşturuldu.","success")
        return redirect("/destek")
    support_data=load_json(SUPPORT_FILE)
    user_supports=support_data.get(session.get("key"),[])
    return render_template("destek.html", destekler=user_supports)

@app.route("/admin/create_user", methods=["POST"])
def create_user():
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if not key_valid(key) or not is_admin(key) or not has_perm(key,"manage_users"):
        flash("Yetkin yok.","error"); return redirect("/admin")
    username=request.form.get("username","").strip()
    password=request.form.get("password","")
    gun=int(request.form.get("gun","30"))
    if not username or not password:
        flash("Eksik.","error"); return redirect("/admin")
    users=load_json(USERS_FILE)
    if username in users:
        flash("Zaten var.","error"); return redirect("/admin")
    new_key=f"userkey.{secrets.token_hex(8)}"
    expiry=(datetime.now()+timedelta(days=gun)).strftime("%Y-%m-%d")
    keys=load_json(KEYS_FILE)
    keys[new_key]={"rol":"uye","bitis":expiry,"perms":[]}
    save_json(KEYS_FILE, keys)
    users[username]={"password":generate_password_hash(password),"key":new_key}
    save_json(USERS_FILE, users)
    log_activity({"action":"create_user","by":key,"user":username})
    flash(f"Kullanıcı {username} oluşturuldu. KEY: {new_key}","success")
    return redirect("/admin")

@app.route("/admin", methods=["GET","POST"])
def admin_panel():
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if not key_valid(key) or not is_admin(key):
        return redirect("/")
    keys=load_json(KEYS_FILE)
    destek_data=load_json(SUPPORT_FILE)
    # KEY oluştur
    if request.method=="POST":
        if not has_perm(key,"manage_keys"):
            flash("İznin yok.","error"); return redirect("/admin")
        yeni_key=request.form.get("yeni_key","").strip()
        rol=request.form.get("rol","uye")
        gun=int(request.form.get("gun","30"))
        bitis=(datetime.now()+timedelta(days=gun)).strftime("%Y-%m-%d")
        perms=[]
        if rol=="admin":
            if request.form.get("perm_manage_keys"):
                perms.append("manage_keys")
            if request.form.get("perm_view_support"):
                perms.append("view_support")
            if request.form.get("perm_view_stats"):
                perms.append("view_stats")
            if request.form.get("perm_manage_users"):
                perms.append("manage_users")
        keys[yeni_key]={"rol":rol,"bitis":bitis,"perms":perms}
        save_json(KEYS_FILE, keys)
        log_activity({"action":"create_key","by":key,"target":yeni_key})
        flash("KEY oluşturuldu.","success")
        return redirect("/admin")
    return render_template("admin_panel.html", keys=keys, destek=destek_data)

@app.route("/admin/edit_key/<target_key>", methods=["POST"])
def edit_key(target_key):
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if not key_valid(key) or not is_admin(key) or not has_perm(key,"manage_keys"):
        flash("Yetkin yok.","error"); return redirect("/admin")
    keys=load_json(KEYS_FILE)
    if target_key not in keys:
        flash("Yok.","error"); return redirect("/admin")
    rol=request.form.get("rol","uye")
    gun=int(request.form.get("gun","30"))
    bitis=(datetime.now()+timedelta(days=gun)).strftime("%Y-%m-%d")
    perms=[]
    if rol=="admin":
        if request.form.get("perm_manage_keys"):
            perms.append("manage_keys")
        if request.form.get("perm_view_support"):
            perms.append("view_support")
        if request.form.get("perm_view_stats"):
            perms.append("view_stats")
        if request.form.get("perm_manage_users"):
            perms.append("manage_users")
    keys[target_key]["rol"]=rol
    keys[target_key]["bitis"]=bitis
    keys[target_key]["perms"]=perms
    save_json(KEYS_FILE, keys)
    log_activity({"action":"edit_key","by":key,"target":target_key})
    flash("Güncellendi.","success")
    return redirect("/admin")

@app.route("/admin/delete_key/<target_key>", methods=["POST"])
def delete_key(target_key):
    if "key" not in session:
        return redirect("/")
    key=session["key"]
    if not key_valid(key) or not is_admin(key) or not has_perm(key,"manage_keys"):
        flash("Yetkin yok.","error"); return redirect("/admin")
    keys=load_json(KEYS_FILE)
    if target_key in keys:
        del keys[target_key]
        save_json(KEYS_FILE, keys)
        log_activity({"action":"delete_key","by":key,"target":target_key})
        flash("Silindi.","success")
    else:
        flash("Yok.","error")
    return redirect("/admin")

@socketio.on("chat_message")
def on_chat_message(data):
    ticket_id = data.get("ticket_id")
    text = data.get("text","")
    key=session.get("key")
    if not key or not key_valid(key):
        return
    # kullanıcıysa gönder adminlere ve kaydet
    support_data=load_json(SUPPORT_FILE)
    user_tickets=support_data.get(key,[])
    for t in user_tickets:
        if t["id"]==ticket_id:
            t["messages"].append({"sender":"user","text":text,"tarih":datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            save_json(SUPPORT_FILE,support_data)
            emit("chat_message", {"ticket_id":ticket_id,"sender":"user","text":text,"tarih":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, broadcast=True)
            return
    # admin side: allow replying in same event
    # if admin is sending, we need to specify target ticket owner
    # Simplified: admin message must include target_user
    target_user = data.get("target_user")
    if is_admin(key) and target_user:
        support_data=load_json(SUPPORT_FILE)
        tickets=support_data.get(target_user,[])
        for t in tickets:
            if t["id"]==ticket_id:
                t["messages"].append({"sender":"admin","text":text,"tarih":datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                t["admin_seen"] = True
                t["user_seen"] = False
                save_json(SUPPORT_FILE,support_data)
                emit("chat_message", {"ticket_id":ticket_id,"sender":"admin","text":text,"tarih":datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, broadcast=True)
                return

@app.route("/cikis")
def cikis():
    session.clear()
    return redirect("/")

@app.errorhandler(404)
def notfound(e):
    return "<h2>Sayfa bulunamadı</h2>",404

if __name__=="__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
