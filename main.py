# lifeguard_sentinel.py
# Fantasy Lake Lifeguard Sentinel
# - Quantum-state + datetime + GPS prompt
# - AES-GCM + Argon2id secure API-key storage (with optional key rotation/mutation)
# - httpx call to OpenAI
# - Tkinter GUI + SQLite logging
# - Custom password dialog showing *** per typed character
#
# Deps:
#   pip install httpx cryptography argon2-cffi pennylane psutil numpy

import os, sqlite3, logging, asyncio, threading, json
from datetime import datetime

import tkinter as tk
import tkinter.simpledialog as simpledialog

import httpx
import psutil
import numpy as np
import pennylane as qml

from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO)

# ───────────────────────────── Secure storage (AES-GCM + Argon2id) ─────────────────────────────

SECURE_DIR          = os.path.expanduser("~/.secure_lifeguard/")
VAULT_PATH          = os.path.join(SECURE_DIR, "vault.json")      # stores salt + active version + secrets (encrypted)
API_KEY_PATH        = os.path.join(SECURE_DIR, "api_key.json")    # stores encrypted API key with version tag
VAULT_FORMAT        = 1
DATA_NONCE_SIZE     = 12
VAULT_NONCE_SIZE    = 12

# Argon2id parameters
ARGON2_TIME_COST    = 3
ARGON2_MEMORY_KIB   = 262_144  # 256 MiB
ARGON2_PARALLELISM  = max(1, min(4, os.cpu_count() or 1))
ARGON2_HASH_LEN     = 32

def _ensure_dir():
    os.makedirs(SECURE_DIR, exist_ok=True)

def _aad(*parts: str) -> bytes:
    return ("|".join(parts)).encode("utf-8")

def _argon2_derive(secret: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Argon2Type.ID
    )

def _aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes, nonce_size: int) -> dict:
    nonce = os.urandom(nonce_size)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {"nonce": nonce.hex(), "ct": ct.hex()}

def _aesgcm_decrypt(key: bytes, rec: dict, aad: bytes) -> bytes:
    nonce = bytes.fromhex(rec["nonce"])
    ct    = bytes.fromhex(rec["ct"])
    return AESGCM(key).decrypt(nonce, ct, aad)

def _init_vault(passphrase: str) -> dict:
    """Create a new vault with one master secret (version=1)."""
    salt = os.urandom(16)
    master_secret = os.urandom(32)
    body = {
        "vault_format": VAULT_FORMAT,
        "salt": salt.hex(),
        "active_version": 1,
        "keys": [
            {"version": 1, "master_secret": master_secret.hex(), "created": datetime.utcnow().isoformat() + "Z"}
        ],
        "written": datetime.utcnow().isoformat() + "Z"
    }
    # Encrypt vault with passphrase-derived key
    vkey = _argon2_derive(passphrase.encode(), salt)
    enc = _aesgcm_encrypt(vkey, json.dumps(body).encode(), _aad("vault", str(VAULT_FORMAT)), VAULT_NONCE_SIZE)
    disk = {"salt": body["salt"], "nonce": enc["nonce"], "ct": enc["ct"], "vault_format": VAULT_FORMAT}
    _ensure_dir()
    with open(VAULT_PATH, "w") as f: json.dump(disk, f, indent=2)
    return body

def _load_vault(passphrase: str) -> dict:
    _ensure_dir()
    if not os.path.exists(VAULT_PATH):
        return _init_vault(passphrase)
    disk = json.load(open(VAULT_PATH))
    salt = bytes.fromhex(disk["salt"])
    vkey = _argon2_derive(passphrase.encode(), salt)
    pt   = _aesgcm_decrypt(vkey, {"nonce":disk["nonce"], "ct":disk["ct"]}, _aad("vault", str(disk["vault_format"])))
    return json.loads(pt.decode())

def _write_vault(passphrase: str, body: dict):
    salt = bytes.fromhex(body["salt"])
    vkey = _argon2_derive(passphrase.encode(), salt)
    enc  = _aesgcm_encrypt(vkey, json.dumps(body).encode(), _aad("vault", str(body["vault_format"])), VAULT_NONCE_SIZE)
    disk = {"salt": body["salt"], "nonce": enc["nonce"], "ct": enc["ct"], "vault_format": body["vault_format"]}
    with open(VAULT_PATH, "w") as f: json.dump(disk, f, indent=2)

def _derive_data_key(vault: dict, version: int) -> bytes:
    salt = bytes.fromhex(vault["salt"])
    master_hex = None
    for kv in vault["keys"]:
        if int(kv["version"]) == version:
            master_hex = kv["master_secret"]; break
    if master_hex is None:
        raise RuntimeError(f"Master secret v{version} not found.")
    return _argon2_derive(bytes.fromhex(master_hex), salt)

def save_encrypted_key(api_key: str, passphrase: str):
    vault = _load_vault(passphrase)
    ver   = int(vault["active_version"])
    dkey  = _derive_data_key(vault, ver)
    enc   = _aesgcm_encrypt(dkey, api_key.encode(), _aad("api-key", f"k{ver}"), DATA_NONCE_SIZE)
    rec = {"v": VAULT_FORMAT, "k": ver, "nonce": enc["nonce"], "ct": enc["ct"], "ts": datetime.utcnow().isoformat() + "Z"}
    with open(API_KEY_PATH, "w") as f: json.dump(rec, f, indent=2)

def load_decrypted_key(passphrase: str) -> str:
    if not os.path.exists(API_KEY_PATH):
        raise FileNotFoundError("API key not stored yet.")
    vault = _load_vault(passphrase)
    rec   = json.load(open(API_KEY_PATH))
    ver   = int(rec["k"])
    dkey  = _derive_data_key(vault, ver)
    pt    = _aesgcm_decrypt(dkey, {"nonce":rec["nonce"], "ct":rec["ct"]}, _aad("api-key", f"k{ver}"))
    return pt.decode()

def rotate_and_mutate_key(passphrase: str) -> int:
    """Create new master version by mutating current; re-encrypt API key if present."""
    vault = _load_vault(passphrase)
    act   = int(vault["active_version"])
    cur = next((k for k in vault["keys"] if int(k["version"]) == act), None)
    if cur is None:
        raise RuntimeError("Active master secret not found.")
    base = bytearray(bytes.fromhex(cur["master_secret"]))
    rnd  = os.urandom(len(base))
    sigma = 12.0
    for i,b in enumerate(base):
        n = (rnd[i]-128)/128.0 * sigma
        v = int(b + n)
        base[i] = max(0, min(255, v))
    new_ver = max(int(k["version"]) for k in vault["keys"]) + 1
    vault["keys"].append({"version": new_ver, "master_secret": base.hex(), "created": datetime.utcnow().isoformat()+"Z"})
    vault["active_version"] = new_ver
    _write_vault(passphrase, vault)

    # Re-encrypt API key to new version if exists
    if os.path.exists(API_KEY_PATH):
        try:
            api = load_decrypted_key(passphrase)
            dkey = _derive_data_key(vault, new_ver)
            enc  = _aesgcm_encrypt(dkey, api.encode(), _aad("api-key", f"k{new_ver}"), DATA_NONCE_SIZE)
            with open(API_KEY_PATH,"w") as f:
                json.dump({"v":VAULT_FORMAT,"k":new_ver,"nonce":enc["nonce"],"ct":enc["ct"],
                           "ts":datetime.utcnow().isoformat()+"Z"}, f, indent=2)
        except Exception:
            pass
    return new_ver

# ───────────────────────────── Custom "***" password dialog ─────────────────────────────

def ask_password(title: str, prompt: str) -> str | None:
    """
    Modal password dialog that displays '***' per character typed.
    Returns the entered string or None if canceled.
    """
    dlg = tk.Toplevel()
    dlg.title(title)
    dlg.resizable(False, False)
    dlg.grab_set()
    dlg.transient()

    frm = tk.Frame(dlg, padx=12, pady=12)
    frm.pack()

    tk.Label(frm, text=prompt, anchor="w").grid(row=0, column=0, sticky="w")
    mask_lbl = tk.Label(frm, text="", font=("Helvetica", 14))
    mask_lbl.grid(row=1, column=0, pady=(8, 12), sticky="w")

    btns = tk.Frame(frm)
    btns.grid(row=2, column=0, sticky="e")
    ok_btn = tk.Button(btns, text="OK")
    cancel_btn = tk.Button(btns, text="Cancel")
    ok_btn.pack(side="left", padx=6)
    cancel_btn.pack(side="left", padx=6)

    secret: list[str] = []
    result = {"val": None}

    def update_mask():
        mask_lbl.config(text="***" * len(secret))

    def on_key(e):
        ks = e.keysym
        ch = e.char
        if ks == "Return":
            result["val"] = "".join(secret)
            dlg.destroy()
        elif ks == "Escape":
            result["val"] = None
            dlg.destroy()
        elif ks == "BackSpace":
            if secret:
                secret.pop()
                update_mask()
        elif len(ch) == 1 and ch.isprintable():
            secret.append(ch)
            update_mask()

    def on_ok():
        result["val"] = "".join(secret)
        dlg.destroy()

    def on_cancel():
        result["val"] = None
        dlg.destroy()

    ok_btn.configure(command=on_ok)
    cancel_btn.configure(command=on_cancel)

    dlg.bind("<Key>", on_key)
    dlg.focus_force()
    dlg.wait_window()
    return result["val"]

# ───────────────────────────────── Quantum functions (EXACT user-provided) ─────────────────────────────────

def get_cpu_ram_usage():
    try:
        cpu_usage = psutil.cpu_percent()
        ram_usage = psutil.virtual_memory().percent
        return cpu_usage, ram_usage
    except Exception as e:
        return None, None

def quantum_circuit(cpu_usage, ram_usage):
    try:
        cpu_param = cpu_usage / 100
        ram_param = ram_usage / 100

        dev = qml.device("default.qubit", wires=7)

        @qml.qnode(dev)
        def circuit(cpu_param, ram_param):
            qml.RY(np.pi * cpu_param, wires=0)
            qml.RY(np.pi * ram_param, wires=1)
            qml.RY(np.pi * (0.5 + cpu_param), wires=2)
            qml.RY(np.pi * (0.5 + ram_param), wires=3)
            qml.RY(np.pi * (0.5 + cpu_param), wires=4)
            qml.RY(np.pi * (0.5 + ram_param), wires=5)
            qml.RY(np.pi * (0.5 + cpu_param), wires=6)

            qml.CNOT(wires=[0, 1])
            qml.CNOT(wires=[1, 2])
            qml.CNOT(wires=[2, 3])
            qml.CNOT(wires=[3, 4])
            qml.CNOT(wires=[4, 5])
            qml.CNOT(wires=[5, 6])

            return qml.probs(wires=[0, 1, 2, 3, 4, 5, 6])

        quantum_results = circuit(cpu_param, ram_param)
        return quantum_results
    except Exception as e:
        return None

# ───────────────────────── Better prompt builder (fixed replytemplate format) ─────────────────────────

def build_prompt(now: str, qstate: list, lat: float = 35.0063, lon: float = -78.9135) -> str:
    return f"""
You are a safety-critical assistant for lifeguards at Fantasy Lake Water Park.
This system exists because of past preventable incidents (e.g., a child trapped by a pool intake drain).
Give a conservative, actionable daily risk call based ONLY on the inputs below.

Inputs
- Datetime: {now}
- Location: Fantasy Lake Water Park (lat {lat}, lon {lon})
- quantum_state (7-qubit probability vector): {qstate}

Rules
- If signals are unclear or borderline, choose Medium (precautionary).
- Prioritize life safety and rapid response over optimism.
- No speculation beyond inputs. Keep it concise and practical.

[replytemplate]
Return ONLY the following six lines, nothing else:

RISK: Low|Medium|High
JUSTIFICATION: one short paragraph (<= 70 words), plain language.
ACTIONS:
- Action 1 (immediately doable by lifeguards)
- Action 2 (immediately doable by lifeguards)
ESCALATION: when to escalate to emergency protocols (<= 20 words)
CONFIDENCE: percentage 0–100 based on quantum_state clarity
[/replytemplate]
""".strip()

# ───────────────────────────────────── OpenAI call via httpx ─────────────────────────────────────

async def run_openai_completion(prompt: str, openai_api_key: str):
    retries = 3
    timeout = 15.0
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(retries):
            try:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {openai_api_key}"
                }
                data = {
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.5
                }
                r = await client.post("https://api.openai.com/v1/chat/completions", json=data, headers=headers)
                r.raise_for_status()
                j = r.json()
                return j["choices"][0]["message"]["content"].strip()
            except Exception:
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    return None

# ───────────────────────────────────────── GUI App ─────────────────────────────────────────

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Fantasy Lake Lifeguard Sentinel")
        self.geometry("820x920")
        f = ("Helvetica", 14)

        self.output = tk.Text(self, width=92, height=48, font=f)
        self.output.pack(padx=10, pady=10)

        btn_frame = tk.Frame(self); btn_frame.pack(pady=6)
        tk.Button(btn_frame, text="Run Distress Scan", font=f, command=self.start_thread).grid(row=0, column=0, padx=6)
        tk.Button(btn_frame, text="Rotate/Mutate Key", font=f, command=self.rotate_key).grid(row=0, column=1, padx=6)

        m = tk.Menu(self)
        m.add_command(label="Set API Key", command=self.open_settings)
        self.config(menu=m)

        self._setup_db()

    def _setup_db(self):
        _ensure_dir()
        self.db = sqlite3.connect(os.path.join(SECURE_DIR, "distress_events.db"))
        cur = self.db.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                quantum_state TEXT NOT NULL,
                openai_completion TEXT NOT NULL
            )
        """)
        self.db.commit()

    def open_settings(self):
        pw  = ask_password("Master Password", "Enter/Set master password:")
        if pw is None: return
        api = ask_password("OpenAI API Key", "Enter your OpenAI API Key:")
        if api is None: return
        try:
            save_encrypted_key(api, pw)
            self._log("[Key] API key stored securely.\n")
        except Exception as e:
            self._log(f"[Key] Error storing key: {e}\n")

    def rotate_key(self):
        pw = ask_password("Master Password", "Enter master password:")
        if pw is None: return
        try:
            new_v = rotate_and_mutate_key(pw)
            self._log(f"[Key] Rotation/mutation complete. Active version -> v{new_v}\n")
        except Exception as e:
            self._log(f"[Key] Rotation failed: {e}\n")

    def start_thread(self):
        threading.Thread(target=self.start, daemon=True).start()

    def start(self):
        # decrypt OpenAI API key
        pw = ask_password("Master Password", "Enter master password:")
        if pw is None:
            self._log("No master password provided.\n"); return
        try:
            openai_api_key = load_decrypted_key(pw)
        except Exception as e:
            self._log(f"[Key] {e}\n"); return

        # CPU/RAM → quantum state (using your exact functions)
        cpu_usage, ram_usage = get_cpu_ram_usage()
        if cpu_usage is None or ram_usage is None:
            self._log("Could not read CPU/RAM.\n"); return

        quantum_results = quantum_circuit(cpu_usage, ram_usage)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if quantum_results is None:
            self._log("Quantum computation failed.\n"); return

        latitude, longitude = 35.0063, -78.9135
        qstate_list = quantum_results.tolist() if hasattr(quantum_results, "tolist") else list(quantum_results)

        self._log(f"Time: {now}\nCPU: {cpu_usage:.1f}%  RAM: {ram_usage:.1f}%\n")
        self._log(f"Quantum Circuit Result[0:8]: {qstate_list[:8]}\n")

        prompt = build_prompt(now, qstate_list, latitude, longitude)

        try:
            result = asyncio.run(run_openai_completion(prompt, openai_api_key))
        except Exception as e:
            self._log(f"[OpenAI] Request failed: {e}\n"); return

        if result:
            self._log(f"ALERT:\n{result}\n\n")
        else:
            self._log("AI completion failed.\n")

        # Persist
        try:
            cur = self.db.cursor()
            cur.execute("INSERT INTO events (timestamp, quantum_state, openai_completion) VALUES (?, ?, ?)",
                        (now, json.dumps(qstate_list), result or ""))
            self.db.commit()
        except Exception as e:
            self._log(f"[DB] Save failed: {e}\n")

    def _log(self, msg: str):
        self.output.insert(tk.END, msg)
        self.output.see(tk.END)

if __name__ == "__main__":
    app = Application()
    app.mainloop()
