#!/usr/bin/env python3
"""勤務表ページの埋め込みデータ（pdata）を作り直す。

使い方: python3 build.py <DBの書き出しフォルダ> <HTML> [<HTML> ...]
DBの書き出しフォルダには doctors/ shifts/ absences/ closures/ の JSON（1件1ファイル）を置く。
時給・帰った時間・超過などは読み込まない（公開ページに入れない）。
応援医（publicHidden）の勤務は本人のアクセスコード（doctors.secretCode）で、
院長・副院長用の全員分は meta/codes の director・vice のコードで、それぞれ暗号化して入れる。
"""
import base64, datetime, glob, hashlib, json, os, re, sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # 自動更新の環境に無ければ入れる
    os.system(f"{sys.executable} -m pip install -q --break-system-packages cryptography")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 200000
EDIT_URL = "https://claude.ai/artifact/8QZeU1BT5pbi8eQe1JJrLR"
SLOT_ORDER = {"AM": 0, "PM": 1, "TUE_EVE": 2}


def load(db, col):
    out = []
    for f in sorted(glob.glob(os.path.join(db, col, "*.json"))):
        x = json.load(open(f, encoding="utf-8"))
        out.append(x.get("data", x) if isinstance(x, dict) else x)
    return out


def b64(b):
    return base64.b64encode(b).decode()


def encrypt(code, obj, doc_id):
    pt = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    salt = hashlib.sha256(("salt|" + doc_id + "|" + code).encode()).digest()[:16]
    key = hashlib.pbkdf2_hmac("sha256", code.encode(), salt, ITER, 32)
    iv = hashlib.sha256(("iv|" + code).encode() + pt).digest()[:12]  # 同じ内容なら同じ暗号文（変更判定のため）
    return {"s": b64(salt), "i": b64(iv), "c": b64(AESGCM(key).encrypt(iv, pt, None))}


def build(db):
    jst = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).date()
    first = jst.replace(day=1)
    base = (first - datetime.timedelta(days=1)).replace(day=1).isoformat()  # 前の月の1日

    docs = {d["id"]: d for d in load(db, "doctors")}
    shifts = [s for s in load(db, "shifts") if s.get("date", "") >= base and s.get("doctorId") in docs
              and s.get("slot") in SLOT_ORDER]
    shifts.sort(key=lambda s: (s["date"], SLOT_ORDER[s["slot"]]))
    hidden = lambda d: bool(d.get("publicHidden"))

    pub = [s for s in shifts if not s.get("hidden") and not hidden(docs[s["doctorId"]])]
    used = {s["doctorId"] for s in pub}
    ordered = sorted(docs.values(), key=lambda d: (d.get("order", 0), d.get("name", "")))
    doctors = [{"id": d["id"], "name": d["name"], "color": d.get("color") or "#2F6F62"}
               for d in ordered if not hidden(d) and (d.get("active", True) is not False or d["id"] in used)]

    absences = []
    for a in sorted(load(db, "absences"), key=lambda x: x.get("date", "")):
        if a.get("date", "") < base:
            continue
        for w in ("director", "vice", "viceExtra"):
            for p in a.get(w) or []:
                absences.append([a["date"], w, p])
    closed = [[c["date"], c.get("note") or "休診"] for c in sorted(load(db, "closures"), key=lambda x: x.get("date", ""))
              if c.get("date", "") >= base]

    secret = []
    pubd = lambda d: {"id": d["id"], "name": d["name"], "color": d.get("color") or "#2F6F62"}
    hid_docs = [d for d in ordered if hidden(d)]
    # 応援医本人：自分の勤務だけ
    for d in hid_docs:
        code = str(d.get("secretCode") or "").strip().upper()
        if not code:
            continue
        mine = [[s["date"], s["slot"], d["id"]] for s in shifts if s["doctorId"] == d["id"]]
        secret.append(encrypt(code, {"kind": "doctor", "doctors": [pubd(d)], "shifts": mine}, d["id"]))
    # 院長・副院長：非常勤に隠している勤務（応援医＋日ごとの非公開）をすべて
    meta = {}
    for m in load(db, "meta"):
        if m.get("id") == "codes" or "director" in m or "vice" in m:
            meta.update(m)
    staff_shifts = [[s["date"], s["slot"], s["doctorId"]] for s in shifts
                    if hidden(docs[s["doctorId"]]) or s.get("hidden")]
    for key, label in (("director", "院長"), ("vice", "副院長")):
        code = str(meta.get(key) or "").strip().upper()
        if code:
            blob = {"kind": "staff", "label": label, "doctors": [pubd(d) for d in hid_docs], "shifts": staff_shifts}
            if key == "director":  # 院長だけ、時給・入力用の院長アプリへのボタンを出す（院長のログインが必要なページ）
                blob["edit"] = EDIT_URL
            secret.append(encrypt(code, blob, "staff-" + key))

    return {"app": "doctor-shift-public", "doctors": doctors,
            "shifts": sorted([[s["date"], s["slot"], s["doctorId"]] + ([s["startTime"]] if s.get("startTime") else []) for s in pub] +
                             [[s["date"], s["slot"], "_support"] for s in shifts if s not in pub],  # 応援医・非公開は名前なし
                             key=lambda x: (x[0], SLOT_ORDER[x[1]])),
            "absences": absences, "closed": closed, "secret": secret}


PDATA = re.compile(r'(<script type="application/json" id="pdata">)(.*?)(</script>)', re.S)


def main():
    db, files = sys.argv[1], sys.argv[2:]
    new = build(db)
    for path in files:
        html = open(path, encoding="utf-8").read()
        m = PDATA.search(html)
        old = json.loads(m.group(2)) if m else {}
        same = all(old.get(k, []) == new[k] for k in ("doctors", "shifts", "absences", "closed", "secret"))
        if same:
            print(f"NOCHANGE {path}")
            continue
        data = dict(new, updatedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
        js = json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")
        open(path, "w", encoding="utf-8").write(PDATA.sub(lambda m: m.group(1) + js + m.group(3), html, count=1))
        print(f"CHANGED {path} shifts={len(new['shifts'])} secret={len(new['secret'])}")


if __name__ == "__main__":
    main()
