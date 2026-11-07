import getpass
import hashlib
import hmac
import io
import json
import math
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import wave
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import numpy as np
import sounddevice as sd
import soundfile as sf
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk, simpledialog

import pyotp
from cryptography.fernet import Fernet, MultiFernet
from docx import Document as DocxDocument
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from openai import OpenAI
from pypdf import PdfReader
from pystray import Icon as TrayIcon
from pystray import Menu as TrayMenu
from pystray import MenuItem as TrayMenuItem
from pyzipper import AESZipFile, WZ_AES, ZIP_LZMA
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from PIL import Image

BOT_NAME = "TW1N"
DEFAULT_MODEL = "openai/gpt-oss-120b"
FAST_MODEL = "openai/gpt-oss-20b"

STT_MODEL = "whisper-large-v3-turbo"
TTS_MODEL = "canopylabs/orpheus-v1-english"
TTS_VOICE = "autumn"

SAMPLE_RATE = 16000
RECORD_SECONDS = 6
MAX_HISTORY = 20
TOP_K = 4

CHAT_FILE = Path(__file__).resolve().parent / "tw1n_chat.json"
TOR_CHECK_URL = "https://check.torproject.org/api/ip"
TOR_PORTS = [9050, 9150]
TOR_CHECK_INTERVAL_MS = 30000

TOR_CONTROL_HOST = "127.0.0.1"
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = ""

TOR_COOKIE_PATHS = [
    Path.home() / "Library/Application Support/Tor/control_auth_cookie",
    Path("/var/run/tor/control.authcookie"),
    Path("/run/tor/control.authcookie"),
    Path.home() / ".tor/control_auth_cookie",
]

DNS_CHECK_URL = "https://dns.google/resolve?name=example.com"
WEB_CHECK_URL = "https://check.torproject.org/api/ip"
SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1000000"

TOR_SERVER_HASH_LABEL = (
    "Tor safe cookie authentication server-to-controller hash"
)

TOR_CLIENT_HASH_LABEL = (
    "Tor safe cookie authentication controller-to-server hash"
)

SYSTEM_PROMPT = (
    f"Your name is {BOT_NAME}. You are a friendly, helpful assistant. "
    "Answer clearly and concisely. "
    "When context from the user's documents is provided, use it and say "
    "when the answer is based on those documents."
)

DARK_COLORS = {
    "background": "#0f1115",
    "surface": "#161a22",
    "surface_alt": "#1c2130",
    "text": "#e6e6e6",
    "muted": "#9aa4b2",
    "accent": "#4cc9f0",
    "success": "#7ee787",
    "warning": "#ffd166",
    "danger": "#ff6b6b",
}

LIGHT_COLORS = {
    "background": "#f5f5f5",
    "surface": "#ffffff",
    "surface_alt": "#e0e0e0",
    "text": "#1a1a1a",
    "muted": "#555555",
    "accent": "#0078d7",
    "success": "#28a745",
    "warning": "#ffc107",
    "danger": "#dc3545",
}


class RagIndex:
    """Local TF-IDF retrieval over TXT, Markdown, PDF and DOCX files."""

    def __init__(self):
        self.chunks = []
        self.documents = []

    def clear(self):
        self.chunks.clear()
        self.documents.clear()

    def add_file(self, path):
        path = Path(path)
        suffix = path.suffix.lower()

        if suffix == ".pdf":
            text = self.read_pdf(path)
        elif suffix == ".docx":
            text = self.read_docx(path)
        elif suffix in (".txt", ".md"):
            text = path.read_text(encoding="utf-8", errors="ignore")
        else:
            raise ValueError(
                "Supported file types: .txt, .md, .pdf, .docx"
            )

        if not text.strip():
            raise ValueError(
                "No readable text found. "
                "Scanned PDFs may require OCR."
            )

        self.add_chunks(text, path.name)

    def read_pdf(self, path):
        reader = PdfReader(path)
        pages = []

        for page in reader.pages:
            pages.append(page.extract_text() or "")

        return "\n\n".join(pages)

    def read_docx(self, path):
        document = DocxDocument(path)

        paragraphs = [
            paragraph.text
            for paragraph in document.paragraphs
            if paragraph.text.strip()
        ]

        return "\n\n".join(paragraphs)

    def add_chunks(self, text, document_name):
        parts = [
            part.strip()
            for part in re.split(r"\n\s*\n", text)
            if part.strip()
        ]

        for part in parts:
            if len(part) > 1200:
                words = part.split()

                for start in range(0, len(words), 250):
                    chunk = " ".join(words[start:start + 250])
                    self.chunks.append(chunk)
                    self.documents.append(document_name)
            else:
                self.chunks.append(part)
                self.documents.append(document_name)

    def search(self, query, top_k=TOP_K):
        if not self.chunks:
            return []

        stopwords = {
            "the", "a", "an", "and", "or", "but", "if", "then", "else",
            "for", "to", "of", "in", "on", "at", "by", "with", "from",
            "is", "are", "was", "were", "be", "been", "this", "that",
        }

        def tokenize(text):
            return [
                word.lower()
                for word in re.findall(r"[a-zA-Zа-яА-ЯёЁ0-9]+", text)
                if word.lower() not in stopwords and len(word) > 1
            ]

        query_terms = tokenize(query)

        if not query_terms:
            return []

        chunk_tokens = [tokenize(chunk) for chunk in self.chunks]
        document_frequency = Counter()

        for tokens in chunk_tokens:
            for term in set(tokens):
                document_frequency[term] += 1

        scores = []

        for index, tokens in enumerate(chunk_tokens):
            term_frequency = Counter(tokens)
            score = 0.0

            for term in query_terms:
                if term not in term_frequency:
                    continue

                idf = math.log(
                    (len(self.chunks) + 1)
                    / (document_frequency[term] + 1)
                ) + 1

                score += term_frequency[term] * idf

            if score > 0:
                scores.append((score, index))

        scores.sort(reverse=True)

        results = []

        for score, index in scores[:top_k]:
            results.append(
                {
                    "source": self.documents[index],
                    "text": self.chunks[index],
                    "score": score,
                }
            )

        return results


class TW1NApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title(f"{BOT_NAME} — Private AI Assistant")
        self.geometry("1300x820")
        self.minsize(1100, 700)

        self.api_key = self.get_api_key()
        self.use_tor = False
        self.tor_proxy_url = None
        self.tor_check_job = None
        self.ip_rotate_job = None
        self.traffic_monitor_job = None
        self.cleanup_job = None
        self.theme = "dark"
        self.pin_code = None
        self.encryption_key = None
        self.totp_secret = None

        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]

        self.current_model = DEFAULT_MODEL
        self.temperature = 0.7
        self.speak_answers = tk.BooleanVar(value=False)
        self.private_mode = tk.BooleanVar(value=False)
        self.use_tor_var = tk.BooleanVar(value=False)
        self.rag = RagIndex()

        self.tor_details = {}
        self.tor_log_lines = []
        self.last_tor_status = None
        self.ip_rotate_interval = tk.IntVar(value=300)
        self.ip_history = []
        self.traffic_stats = {
            "requests": 0,
            "bytes": 0,
            "errors": 0,
        }

        self.client = self.create_client(use_tor=False)
        self.available_models = self.load_models()

        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.populate_models()

    def get_api_key(self):
        key = os.environ.get("GROQ_API_KEY", "").strip()

        if key:
            return key

        if sys.platform == "darwin":
            try:
                result = subprocess.run(
                    [
                        "security",
                        "find-generic-password",
                        "-a",
                        getpass.getuser(),
                        "-s",
                        "GROQ_API_KEY",
                        "-w",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                if result.returncode == 0 and result.stdout.strip():
                    return result.stdout.strip()

            except (OSError, subprocess.TimeoutExpired):
                pass

        messagebox.showerror(
            BOT_NAME,
            "GROQ_API_KEY is not set.\n\n"
            "Set it in Terminal:\n\n"
            "export GROQ_API_KEY='your_key'"
        )

        raise SystemExit(1)

    def create_client(self, use_tor, proxy_url=None):
        if use_tor and proxy_url:
            http_client = httpx.Client(
                proxy=proxy_url,
                timeout=60.0,
            )
        else:
            http_client = httpx.Client(
                timeout=60.0,
            )

        return OpenAI(
            api_key=self.api_key,
            base_url="https://api.groq.com/openai/v1",
            http_client=http_client,
        )

    def rebuild_client(self, proxy_url=None):
        old_client = self.client

        self.client = self.create_client(
            use_tor=self.use_tor_var.get(),
            proxy_url=proxy_url,
        )

        try:
            old_client.close()
        except Exception:
            pass

    def load_models(self):
        try:
            response = self.client.models.list()
            model_ids = [model.id for model in response.data]
            return sorted(model_ids)
        except Exception:
            return [DEFAULT_MODEL, FAST_MODEL]

    def populate_models(self):
        if not self.available_models:
            self.available_models = [DEFAULT_MODEL, FAST_MODEL]

        self.model_box["values"] = self.available_models

        if self.current_model not in self.available_models:
            self.current_model = self.available_models[0]
            self.model_var.set(self.current_model)

    def build_ui(self):
        self.configure(bg=DARK_COLORS["background"])

        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "TFrame",
            background=DARK_COLORS["background"],
        )

        style.configure(
            "TLabel",
            background=DARK_COLORS["background"],
            foreground=DARK_COLORS["text"],
        )

        style.configure(
            "TButton",
            background=DARK_COLORS["surface_alt"],
            foreground=DARK_COLORS["text"],
            borderwidth=0,
            focusthickness=0,
        )

        style.map(
            "TButton",
            background=[
                ("active", "#2a3140"),
                ("pressed", "#333c4d"),
            ],
        )

        style.configure(
            "TCheckbutton",
            background=DARK_COLORS["background"],
            foreground=DARK_COLORS["text"],
        )

        style.map(
            "TCheckbutton",
            background=[
                ("active", DARK_COLORS["background"]),
            ],
        )

        style.configure(
            "TCombobox",
            fieldbackground=DARK_COLORS["surface"],
            background=DARK_COLORS["surface_alt"],
            foreground=DARK_COLORS["text"],
            arrowcolor=DARK_COLORS["text"],
        )

        main = ttk.Frame(self, padding=12)
        main.pack(fill="both", expand=True)

        controls = ttk.Frame(main)
        controls.pack(fill="x", pady=(0, 10))

        self.model_var = tk.StringVar(value=self.current_model)

        self.model_box = ttk.Combobox(
            controls,
            textvariable=self.model_var,
            width=34,
            state="readonly",
        )
        self.model_box.pack(side="left", padx=(0, 10))
        self.model_box.bind(
            "<<ComboboxSelected>>",
            self.change_model,
        )

        ttk.Label(
            controls,
            text="Temperature:",
        ).pack(side="left")

        self.temperature_var = tk.DoubleVar(value=0.7)

        ttk.Scale(
            controls,
            from_=0.0,
            to=2.0,
            variable=self.temperature_var,
            length=150,
        ).pack(side="left", padx=6)

        self.temperature_label = ttk.Label(
            controls,
            text="0.7",
        )
        self.temperature_label.pack(side="left")

        ttk.Checkbutton(
            controls,
            text="Speak answers",
            variable=self.speak_answers,
        ).pack(side="left", padx=12)

        ttk.Checkbutton(
            controls,
            text="Private mode",
            variable=self.private_mode,
        ).pack(side="left", padx=12)

        ttk.Checkbutton(
            controls,
            text="Use Tor proxy",
            variable=self.use_tor_var,
            command=self.toggle_tor,
        ).pack(side="left", padx=12)

        self.tor_status_label = ttk.Label(
            controls,
            text="Tor: OFF",
            foreground=DARK_COLORS["warning"],
            cursor="hand2",
        )
        self.tor_status_label.pack(side="left", padx=12)
        self.tor_status_label.bind(
            "<Button-1>",
            self.on_tor_status_click,
        )

        ttk.Button(
            controls,
            text="Tor details",
            command=self.show_tor_details,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Tor Diagnostics",
            command=self.show_tor_diagnostics,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Tor log",
            command=self.open_tor_log,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Security dashboard",
            command=self.open_security_dashboard,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Export dashboard",
            command=self.export_dashboard,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Export logs",
            command=self.export_security_logs,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Switch theme",
            command=self.switch_theme,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Key manager",
            command=self.open_key_manager,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Backup logs",
            command=self.backup_security_logs,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="First run wizard",
            command=self.open_first_run_wizard,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Verify logs",
            command=self.verify_security_logs,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Set PIN",
            command=self.set_pin_code,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Enable 2FA",
            command=self.enable_2fa,
        ).pack(side="left", padx=8)

        ttk.Button(
            controls,
            text="Audit log",
            command=self.open_audit_log,
        ).pack(side="left", padx=8)

        rag_frame = ttk.Frame(main)
        rag_frame.pack(fill="x", pady=8)

        ttk.Button(
            rag_frame,
            text="Add files",
            command=self.add_knowledge_files,
        ).pack(side="left")

        ttk.Button(
            rag_frame,
            text="Clear knowledge",
            command=self.clear_knowledge,
        ).pack(side="left", padx=8)

        ttk.Button(
            rag_frame,
            text="Save chat",
            command=self.save_chat,
        ).pack(side="left", padx=8)

        ttk.Button(
            rag_frame,
            text="Clear chat",
            command=self.clear_chat,
        ).pack(side="left")

        ttk.Button(
            rag_frame,
            text="New private chat",
            command=self.new_private_chat,
        ).pack(side="left", padx=8)

        self.knowledge_label = ttk.Label(
            rag_frame,
            text="Knowledge: 0 chunks",
        )
        self.knowledge_label.pack(side="left", padx=8)

        tor_frame = ttk.Frame(main)
        tor_frame.pack(fill="x", pady=8)

        ttk.Button(
            tor_frame,
            text="Rotate IP",
            command=self.rotate_tor_ip,
        ).pack(side="left")

        ttk.Button(
            tor_frame,
            text="DNS check",
            command=self.check_dns_leak,
        ).pack(side="left", padx=8)

        ttk.Button(
            tor_frame,
            text="Web check",
            command=self.check_web_through_tor,
        ).pack(side="left", padx=8)

        ttk.Button(
            tor_frame,
            text="Speed test",
            command=self.run_speed_test,
        ).pack(side="left", padx=8)

        ttk.Button(
            tor_frame,
            text="Traffic monitor",
            command=self.open_traffic_monitor,
        ).pack(side="left", padx=8)

        ttk.Label(
            tor_frame,
            text="Rotate every:",
        ).pack(side="left", padx=(12, 4))

        self.ip_rotate_entry = ttk.Entry(
            tor_frame,
            textvariable=self.ip_rotate_interval,
            width=6,
        )
        self.ip_rotate_entry.pack(side="left")

        ttk.Label(
            tor_frame,
            text="sec",
        ).pack(side="left", padx=(4, 8))

        ttk.Button(
            tor_frame,
            text="Start timer",
            command=self.start_ip_rotation_timer,
        ).pack(side="left")

        ttk.Button(
            tor_frame,
            text="Stop timer",
            command=self.stop_ip_rotation_timer,
        ).pack(side="left", padx=6)

        ttk.Label(
            tor_frame,
            text="Custom port:",
        ).pack(side="left", padx=(12, 4))

        self.tor_custom_port = tk.StringVar(value="")

        self.custom_port_entry = ttk.Entry(
            tor_frame,
            textvariable=self.tor_custom_port,
            width=8,
        )
        self.custom_port_entry.pack(side="left")

        ttk.Button(
            tor_frame,
            text="Use",
            command=self.use_custom_tor_port,
        ).pack(side="left", padx=6)

        ttk.Button(
            tor_frame,
            text="Choose cookie",
            command=self.choose_tor_cookie,
        ).pack(side="left", padx=8)

        input_frame = ttk.Frame(main)
        input_frame.pack(fill="x", pady=(8, 0))

        self.input_box = tk.Text(
            input_frame,
            height=4,
            wrap="word",
            font=("Menlo", 12),
            bg=DARK_COLORS["surface"],
            fg=DARK_COLORS["text"],
            insertbackground=DARK_COLORS["text"],
            relief="flat",
        )
        self.input_box.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 8),
        )

        self.input_box.bind("<Return>", self.on_enter)
        self.input_box.bind(
            "<Shift-Return>",
            lambda event: None,
        )

        buttons = ttk.Frame(input_frame)
        buttons.pack(side="right", fill="y")

        ttk.Button(
            buttons,
            text="Send",
            command=self.send_message,
        ).pack(fill="x", pady=(0, 6))

        ttk.Button(
            buttons,
            text="Mic",
            command=self.start_voice_input,
        ).pack(fill="x", pady=(0, 6))

        ttk.Button(
            buttons,
            text="Speak last",
            command=self.speak_last_answer,
        ).pack(fill="x")

        self.add_system_message(
            f"{BOT_NAME} is ready. Dark mode is enabled. "
            "Use New private chat for a private session. "
            "Add .txt, .md, .pdf or .docx files for RAG."
        )

    def open_audit_log(self):
        window = tk.Toplevel(self)
        window.title(f"{BOT_NAME} — Audit Log")
        window.geometry("900x600")
        window.configure(bg=DARK_COLORS["background"])

        frame = ttk.Frame(window, padding=10)
        frame.pack(fill="both", expand=True)

        self.audit_area = scrolledtext.ScrolledText(
            frame,
            wrap="word",
            font=("Menlo", 10),
            bg=DARK_COLORS["surface"],
            fg=DARK_COLORS["text"],
            insertbackground=DARK_COLORS["text"],
            relief="flat",
        )
        self.audit_area.pack(fill="both", expand=True)

        self.audit_area.tag_configure(
            "info",
            foreground=DARK_COLORS["muted"],
        )

        self.audit_area.tag_configure(
            "success",
            foreground=DARK_COLORS["success"],
        )

        self.audit_area.tag_configure(
            "warning",
            foreground=DARK_COLORS["warning"],
        )

        self.audit_area.tag_configure(
            "error",
            foreground=DARK_COLORS["danger"],
        )

        for line in self.audit_log_lines:
            self.audit_area.insert("end", line + "\n")

        self.audit_area.see("end")

    def audit_log(self, action, details=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "action": action,
            "details": details,
        }

        self.audit_log_lines.append(entry)

        self.save_audit_log(entry)

    def save_audit_log(self, entry):
        audit_file = Path(__file__).resolve().parent / "tw1n_audit.log"

        try:
            with audit_file.open("a", encoding="utf-8") as file:
                file.write(
                    json.dumps(
                        entry,
                        ensure_ascii=False,
                    )
                    + "\n"
                )

        except OSError:
            pass

    def verify_audit_log(self):
        audit_file = Path(__file__).resolve().parent / "tw1n_audit.log"

        if not audit_file.exists():
            return False

        previous_hash = ""

        for line in audit_file.read_text(
            encoding="utf-8"
        ).splitlines():
            entry = json.loads(line)

            expected_hash = hashlib.sha256(
                (
                    previous_hash
                    + entry["timestamp"]
                    + entry["action"]
                    + entry["details"]
                ).encode()
            ).hexdigest()

            if entry["hash"] != expected_hash:
                return False

            previous_hash = entry["hash"]

        return True

    def enable_2fa(self):
        secret = pyotp.random_base32()

        self.totp_secret = secret

        totp = pyotp.TOTP(secret)

        self.add_system_message(
            f"2FA enabled. Secret: {secret}"
        )

    def verify_2fa(self):
        if not self.totp_secret:
            return True

        code = simpledialog.askstring(
            "2FA",
            "Enter 2FA code:",
            show="*",
        )

        totp = pyotp.TOTP(self.totp_secret)

        if totp.verify(code):
            return True

        self.add_system_message(
            "Invalid 2FA code."
        )
        return False

    def open_key_manager(self):
        window = tk.Toplevel(self)
        window.title(f"{BOT_NAME} — Key Manager")
        window.geometry("700x500")
        window.configure(bg=DARK_COLORS["background"])

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(
            frame,
            text="Encryption Key Manager",
            font=("Menlo", 16, "bold"),
            foreground=DARK_COLORS["accent"],
        )
        title.pack(pady=(0, 16))

        self.key_manager_text = tk.Text(
            frame,
            height=14,
            wrap="word",
            font=("Menlo", 11),
            bg=DARK_COLORS["surface"],
            fg=DARK_COLORS["text"],
            insertbackground=DARK_COLORS["text"],
            relief="flat",
        )
        self.key_manager_text.pack(fill="both", expand=True)

        self.key_manager_text.insert(
            "end",
            "Loading key manager...\n"
        )

        ttk.Button(
            frame,
            text="Generate new key",
            command=self.generate_new_key,
        ).pack(pady=10)

        ttk.Button(
            frame,
            text="Rotate key",
            command=self.rotate_key,
        ).pack(pady=10)

        ttk.Button(
            frame,
            text="Save key",
            command=self.save_key,
        ).pack(pady=10)

        self.key_manager_window = window

    def generate_new_key(self):
        key = Fernet.generate_key()

        self.encryption_key = key

        self.key_manager_text.delete("1.0", "end")
        self.key_manager_text.insert(
            "end",
            f"New key generated:\n{key.decode()}\n"
        )

    def rotate_key(self):
        if not self.encryption_key:
            self.key_manager_text.delete("1.0", "end")
            self.key_manager_text.insert(
                "end",
                "No key available.\n"
            )
            return

        old_key = self.encryption_key
        new_key = Fernet.generate_key()

        multi_fernet = MultiFernet(
            [
                Fernet(new_key),
                Fernet(old_key),
            ]
        )

        self.encryption_key = new_key

        self.key_manager_text.delete("1.0", "end")
        self.key_manager_text.insert(
            "end",
            f"Key rotated.\nOld key: {old_key.decode()}\n"
            f"New key: {new_key.decode()}\n"
        )

    def save_key(self):
        if not self.encryption_key:
            self.key_manager_text.delete("1.0", "end")
            self.key_manager_text.insert(
                "end",
                "No key available.\n"
            )
            return

        path = filedialog.asksaveasfilename(
            title="Save encryption key",
            defaultextension=".key",
            filetypes=[
                ("Key file", "*.key"),
            ],
        )

        if not path:
            return

        Path(path).write_bytes(
            self.encryption_key
        )

        self.key_manager_text.delete("1.0", "end")
        self.key_manager_text.insert(
            "end",
            f"Key saved to {path}\n"
        )

    def backup_security_logs(self):
        if not self.encryption_key:
            self.add_system_message(
                "No encryption key available."
            )
            return

        path = filedialog.asksaveasfilename(
            title="Backup security logs",
            defaultextension=".zip",
            filetypes=[
                ("ZIP file", "*.zip"),
            ],
        )

        if not path:
            return

        with AESZipFile(
            path,
            "w",
            compression=ZIP_LZMA,
            encryption=WZ_AES,
        ) as zip_file:
            zip_file.setpassword(
                self.encryption_key
            )
            zip_file.setencryption(WZ_AES, nbits=256)
            zip_file.writestr(
                "tw1n_security.log",
                "\n".join(self.tor_log_lines),
            )

        self.add_system_message(
            f"Security logs backed up to {path}"
        )

    def open_first_run_wizard(self):
        window = tk.Toplevel(self)
        window.title(f"{BOT_NAME} — First Run Wizard")
        window.geometry("700x500")
        window.configure(bg=DARK_COLORS["background"])

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(
            frame,
            text="First Run Wizard",
            font=("Menlo", 16, "bold"),
            foreground=DARK_COLORS["accent"],
        )
        title.pack(pady=(0, 16))

        self.wizard_text = tk.Text(
            frame,
            height=14,
            wrap="word",
            font=("Menlo", 11),
            bg=DARK_COLORS["surface"],
            fg=DARK_COLORS["text"],
            insertbackground=DARK_COLORS["text"],
            relief="flat",
        )
        self.wizard_text.pack(fill="both", expand=True)

        self.wizard_text.insert(
            "end",
            "Welcome to TW1N.\n\n"
            "This wizard will help you set up the app.\n"
            "1. Set your API key.\n"
            "2. Enable Tor if needed.\n"
            "3. Choose your preferred theme.\n"
            "4. Set a PIN code for GUI protection.\n"
            "5. Enable 2FA.\n"
        )

        ttk.Button(
            frame,
            text="Next",
            command=self.wizard_next,
        ).pack(pady=10)

        self.wizard_window = window

    def wizard_next(self):
        self.wizard_text.insert(
            "end",
            "Setup complete.\n"
        )

    def verify_security_logs(self):
        if not self.encryption_key:
            self.add_system_message(
                "No encryption key available."
            )
            return

        try:
            fernet = Fernet(self.encryption_key)
            fernet.decrypt(
                fernet.encrypt(
                    b"test"
                )
            )

            self.add_system_message(
                "Security logs integrity verified."
            )

        except Exception as error:
            self.add_system_message(
                f"Integrity check failed: {error}"
            )

    def set_pin_code(self):
        pin = simpledialog.askstring(
            "Set PIN",
            "Enter a 4-digit PIN:",
            show="*",
        )

        if not pin or not pin.isdigit() or len(pin) != 4:
            self.add_system_message(
                "PIN must be 4 digits."
            )
            return

        self.pin_code = pin

        self.add_system_message(
            "PIN code set."
        )

    def check_pin(self):
        if not self.pin_code:
            return True

        pin = simpledialog.askstring(
            "PIN",
            "Enter your PIN:",
            show="*",
        )

        if pin == self.pin_code:
            return True

        self.add_system_message(
            "Incorrect PIN."
        )
        return False

    def switch_theme(self):
        if self.theme == "dark":
            self.theme = "light"
            self.colors = LIGHT_COLORS
        else:
            self.theme = "dark"
            self.colors = DARK_COLORS

        self.apply_theme()

    def apply_theme(self):
        self.configure(bg=self.colors["background"])

        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "TFrame",
            background=self.colors["background"],
        )

        style.configure(
            "TLabel",
            background=self.colors["background"],
            foreground=self.colors["text"],
        )

        style.configure(
            "TButton",
            background=self.colors["surface_alt"],
            foreground=self.colors["text"],
            borderwidth=0,
            focusthickness=0,
        )

        style.map(
            "TButton",
            background=[
                ("active", self.colors["surface_alt"]),
                ("pressed", self.colors["surface"]),
            ],
        )

        style.configure(
            "TCheckbutton",
            background=self.colors["background"],
            foreground=self.colors["text"],
        )

        style.map(
            "TCheckbutton",
            background=[
                ("active", self.colors["background"]),
            ],
        )

        style.configure(
            "TCombobox",
            fieldbackground=self.colors["surface"],
            background=self.colors["surface_alt"],
            foreground=self.colors["text"],
            arrowcolor=self.colors["text"],
        )

    def open_tor_log(self):
        if hasattr(self, "tor_log_window") and self.tor_log_window.winfo_exists():
            self.tor_log_window.lift()
            return

        self.tor_log_window = tk.Toplevel(self)
        self.tor_log_window.title(f"{BOT_NAME} — Tor Log")
        self.tor_log_window.geometry("900x600")
        self.tor_log_window.configure(bg=self.colors["background"])

        frame = ttk.Frame(self.tor_log_window, padding=10)
        frame.pack(fill="both", expand=True)

        self.tor_log_area = scrolledtext.ScrolledText(
            frame,
            wrap="word",
            font=("Menlo", 10),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
        )
        self.tor_log_area.pack(fill="both", expand=True)

        self.tor_log_area.tag_configure(
            "info",
            foreground=self.colors["muted"],
        )

        self.tor_log_area.tag_configure(
            "success",
            foreground=self.colors["success"],
        )

        self.tor_log_area.tag_configure(
            "warning",
            foreground=self.colors["warning"],
        )

        self.tor_log_area.tag_configure(
            "error",
            foreground=self.colors["danger"],
        )

        for line in self.tor_log_lines:
            self.tor_log_area.insert("end", line + "\n")

        self.tor_log_area.see("end")

    def tor_log(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] [{level.upper()}] {message}"

        self.tor_log_lines.append(line)

        self.save_security_log(line)

        if hasattr(self, "tor_log_area") and self.tor_log_area.winfo_exists():
            self.tor_log_area.insert("end", line + "\n", level)
            self.tor_log_area.see("end")

    def save_security_log(self, line):
        log_file = Path(__file__).resolve().parent / "tw1n_security.log"

        try:
            if self.encryption_key:
                fernet = Fernet(self.encryption_key)
                encrypted = fernet.encrypt(
                    line.encode()
                )

                with log_file.open("ab") as file:
                    file.write(encrypted + b"\n")

            else:
                with log_file.open("a", encoding="utf-8") as file:
                    file.write(line + "\n")

        except OSError:
            pass

    def play_status_sound(self, status):
        if status == self.last_tor_status:
            return

        self.last_tor_status = status

        if sys.platform == "darwin":
            sounds = {
                "ON": "/System/Library/Sounds/Glass.aiff",
                "OFF": "/System/Library/Sounds/Pop.aiff",
                "ERROR": "/System/Library/Sounds/Basso.aiff",
            }

            sound_file = sounds.get(status)

            if sound_file and Path(sound_file).exists():
                subprocess.Popen(
                    ["afplay", sound_file],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return

        print("\a", end="", flush=True)

    def toggle_tor(self):
        self.use_tor = self.use_tor_var.get()

        self.tor_status_label.configure(
            text="Tor: CHECKING",
            foreground=self.colors["warning"],
        )

        if self.use_tor:
            self.add_system_message(
                "Tor proxy enabled. Detecting available port..."
            )
            self.detect_tor_port()
        else:
            self.tor_proxy_url = None
            self.rebuild_client(proxy_url=None)

            self.tor_status_label.configure(
                text="Tor: OFF",
                foreground=self.colors["warning"],
            )
            self.stop_tor_autocheck()
            self.add_system_message(
                "Tor proxy disabled. "
                "Requests use the normal network."
            )

    def detect_tor_port(self):
        def worker():
            working_port = None

            for port in TOR_PORTS:
                proxy_url = f"socks5://127.0.0.1:{port}"

                try:
                    with httpx.Client(
                        proxy=proxy_url,
                        timeout=5.0,
                    ) as client:
                        response = client.get(TOR_CHECK_URL)
                        response.raise_for_status()

                        data = response.json()

                        if data.get("IsTor") is True:
                            working_port = port
                            break

                except Exception:
                    continue

            if working_port:
                proxy_url = (
                    f"socks5://127.0.0.1:{working_port}"
                )

                self.tor_proxy_url = proxy_url
                self.rebuild_client(proxy_url=proxy_url)

                self.after(
                    0,
                    lambda: self.update_tor_status(
                        "ON",
                        f"Tor detected on port {working_port}.",
                    ),
                )
                self.after(
                    0,
                    self.start_tor_autocheck,
                )
            else:
                self.use_tor_var.set(False)
                self.use_tor = False
                self.tor_proxy_url = None
                self.rebuild_client(proxy_url=None)

                self.after(
                    0,
                    lambda: self.update_tor_status(
                        "ERROR",
                        "No working Tor proxy found on ports "
                        f"{', '.join(map(str, TOR_PORTS))}.",
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def check_tor_status(self):
        if not self.tor_proxy_url:
            return

        def worker():
            status = "ERROR"
            details = "Tor check failed."

            try:
                self.tor_log(
                    f"Checking Tor via {self.tor_proxy_url}"
                )

                with httpx.Client(
                    proxy=self.tor_proxy_url,
                    timeout=15.0,
                ) as client:
                    response = client.get(TOR_CHECK_URL)
                    response.raise_for_status()

                    data = response.json()

                    if data.get("IsTor") is True:
                        status = "ON"
                        details = (
                            "Tor is active. "
                            f"Exit IP: {data.get('IP', 'unknown')}"
                        )

                        self.tor_details = {
                            "is_tor": True,
                            "ip": data.get("IP", "Unknown"),
                            "country": data.get("Country", "Unknown"),
                            "port": self.get_current_tor_port(),
                            "checked_at": datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                        }

                        self.ip_history.append(
                            {
                                "time": datetime.now(),
                                "ip": data.get("IP", "Unknown"),
                            }
                        )

                    else:
                        status = "OFF"
                        details = (
                            "Connection is not going through Tor."
                        )

            except Exception as error:
                status = "ERROR"
                details = f"Tor check failed: {error}"

            self.after(
                0,
                lambda: self.update_tor_status(status, details),
            )

        threading.Thread(target=worker, daemon=True).start()

    def update_tor_status(self, status, details):
        if status == "ON":
            color = self.colors["success"]
            text = "Tor: ON"
        elif status == "OFF":
            color = self.colors["warning"]
            text = "Tor: OFF"
        else:
            color = self.colors["danger"]
            text = "Tor: ERROR"

        self.tor_status_label.configure(
            text=text,
            foreground=color,
        )

        self.tor_log(
            details,
            level="success" if status == "ON" else (
                "warning" if status == "OFF" else "error"
            ),
        )

        self.play_status_sound(status)
        self.add_system_message(details)

    def on_tor_status_click(self, event=None):
        if self.use_tor_var.get():
            self.tor_status_label.configure(
                text="Tor: CHECKING",
                foreground=self.colors["warning"],
            )
            self.check_tor_status()
        else:
            self.add_system_message(
                "Enable Use Tor proxy to check Tor status."
            )

    def start_tor_autocheck(self):
        self.stop_tor_autocheck()

        self.tor_check_job = self.after(
            TOR_CHECK_INTERVAL_MS,
            self.auto_check_tor,
        )

    def auto_check_tor(self):
        if self.use_tor_var.get():
            self.check_tor_status()

        self.start_tor_autocheck()

    def stop_tor_autocheck(self):
        if self.tor_check_job:
            self.after_cancel(self.tor_check_job)
            self.tor_check_job = None

    def show_tor_details(self):
        window = tk.Toplevel(self)
        window.title(f"{BOT_NAME} — Tor Details")
        window.geometry("520x420")
        window.configure(bg=self.colors["background"])
        window.resizable(False, False)

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(
            frame,
            text="Tor Connection Details",
            font=("Menlo", 16, "bold"),
            foreground=self.colors["accent"],
        )
        title.pack(pady=(0, 16))

        self.details_text = tk.Text(
            frame,
            height=14,
            wrap="word",
            font=("Menlo", 11),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
        )
        self.details_text.pack(fill="both", expand=True)

        self.details_text.insert(
            "end",
            "Loading Tor details...\n"
        )

        ttk.Button(
            frame,
            text="Refresh",
            command=self.refresh_tor_details,
        ).pack(pady=10)

        self.tor_details_window = window

        self.refresh_tor_details()

    def refresh_tor_details(self):
        if not self.tor_proxy_url:
            self.update_details_text(
                "Tor is not enabled.\n\n"
                "Enable Use Tor proxy first."
            )
            return

        def worker():
            try:
                with httpx.Client(
                    proxy=self.tor_proxy_url,
                    timeout=15.0,
                ) as client:
                    response = client.get(TOR_CHECK_URL)
                    response.raise_for_status()

                    data = response.json()

                    self.tor_details = {
                        "is_tor": data.get("IsTor", False),
                        "ip": data.get("IP", "Unknown"),
                        "country": data.get("Country", "Unknown"),
                        "port": self.get_current_tor_port(),
                        "checked_at": datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                    }

                self.after(0, self.render_tor_details)

            except Exception as error:
                self.after(
                    0,
                    lambda: self.update_details_text(
                        f"Tor check failed:\n{error}"
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def render_tor_details(self):
        details = self.tor_details

        text = (
            f"Tor status: {'ON' if details.get('is_tor') else 'OFF'}\n"
            f"Exit IP: {details.get('ip', 'Unknown')}\n"
            f"Country: {details.get('country', 'Unknown')}\n"
            f"Proxy port: {details.get('port', 'Unknown')}\n"
            f"Checked at: {details.get('checked_at', 'Unknown')}\n"
        )

        self.update_details_text(text)

    def update_details_text(self, text):
        if hasattr(self, "details_text"):
            self.details_text.configure(state="normal")
            self.details_text.delete("1.0", "end")
            self.details_text.insert("end", text)
            self.details_text.configure(state="disabled")

    def get_current_tor_port(self):
        if not self.tor_proxy_url:
            return "Not connected"

        match = re.search(r":(\d+)$", self.tor_proxy_url)

        if match:
            return match.group(1)

        return "Unknown"

    def use_custom_tor_port(self):
        port_text = self.tor_custom_port.get().strip()

        if not port_text:
            self.add_system_message("Enter a Tor port first.")
            return

        if not port_text.isdigit():
            self.add_system_message("Port must be a number.")
            return

        port = int(port_text)

        if not 1 <= port <= 65535:
            self.add_system_message(
                "Port must be between 1 and 65535."
            )
            return

        proxy_url = f"socks5://127.0.0.1:{port}"

        self.tor_proxy_url = proxy_url
        self.use_tor_var.set(True)
        self.use_tor = True

        self.rebuild_client(proxy_url=proxy_url)

        self.add_system_message(
            f"Custom Tor port set to {port}. Checking connection..."
        )

        self.check_tor_status()

    def choose_tor_cookie(self):
        path = filedialog.askopenfilename(
            title="Select Tor control authentication cookie",
            filetypes=[
                ("All files", "*.*"),
            ],
        )

        if not path:
            return

        self.tor_cookie_path = Path(path)

        self.add_system_message(
            f"Tor cookie selected: {self.tor_cookie_path}"
        )

    def show_tor_diagnostics(self):
        window = tk.Toplevel(self)
        window.title(f"{BOT_NAME} — Tor Diagnostics")
        window.geometry("1000x760")
        window.configure(bg=self.colors["background"])

        frame = ttk.Frame(window, padding=16)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(
            frame,
            text="Tor Diagnostics",
            font=("Menlo", 16, "bold"),
            foreground=self.colors["accent"],
        )
        title.pack(pady=(0, 16))

        self.diagnostics_text = tk.Text(
            frame,
            height=14,
            wrap="word",
            font=("Menlo", 11),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
        )
        self.diagnostics_text.pack(fill="both", expand=True)

        self.diagnostics_text.insert(
            "end",
            "Loading Tor diagnostics...\n"
        )

        self.diagnostics_figure = Figure(
            figsize=(7, 3),
            dpi=100,
        )

        self.diagnostics_plot = (
            self.diagnostics_figure.add_subplot(111)
        )

        self.diagnostics_canvas = FigureCanvasTkAgg(
            self.diagnostics_figure,
            master=frame,
        )

        self.diagnostics_canvas.get_tk_widget().pack(
            fill="both",
            expand=True,
            pady=10,
        )

        ttk.Button(
            frame,
            text="Refresh",
            command=self.refresh_tor_diagnostics,
        ).pack(pady=10)

        self.tor_diagnostics_window = window

        self.refresh_tor_diagnostics()

    def refresh_tor_diagnostics(self):
        if not self.tor_proxy_url:
            self.update_diagnostics_text(
                "Tor is not enabled.\n\n"
                "Enable Use Tor proxy first."
            )
            return

        def worker():
            try:
                version = self.get_tor_info("version")
                circuits = self.get_tor_info("circuit-status")

                circuit_lines = [
                    line
                    for line in circuits.splitlines()
                    if line.strip()
                ]

                exit_node = self.get_exit_node(circuits)
                country = self.tor_details.get("country", "Unknown")

                last_change = (
                    self.last_ip_change.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    if self.last_ip_change
                    else "Never"
                )

                self.tor_diagnostics = {
                    "version": version,
                    "circuits": circuit_lines,
                    "exit_node": exit_node,
                    "country": country,
                    "last_ip_change": last_change,
                }

                self.after(0, self.render_tor_diagnostics)

            except Exception as error:
                self.after(
                    0,
                    lambda: self.update_diagnostics_text(
                        f"Tor diagnostics failed:\n{error}"
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def read_tor_cookie(self):
        if hasattr(self, "tor_cookie_path") and self.tor_cookie_path:
            if self.tor_cookie_path.exists():
                cookie = self.tor_cookie_path.read_bytes()

                if len(cookie) >= 32:
                    return cookie[:32]

        for path in TOR_COOKIE_PATHS:
            if path.exists():
                try:
                    cookie = path.read_bytes()

                    if len(cookie) >= 32:
                        return cookie[:32]

                except OSError:
                    continue

        raise RuntimeError(
            "Tor control authentication cookie not found."
        )

    def tor_control_auth(self, control_socket):
        cookie = self.read_tor_cookie()

        client_nonce = os.urandom(32)

        control_socket.sendall(
            b"AUTHCHALLENGE SAFECOOKIE "
            + client_nonce.hex().encode()
            + b"\r\n"
        )

        response = self.read_control_response(control_socket)

        server_hash = bytes.fromhex(
            self.extract_control_value(response, "SERVERHASH")
        )

        server_nonce = bytes.fromhex(
            self.extract_control_value(response, "SERVERNONCE")
        )

        expected_server_hash = hmac.new(
            cookie,
            TOR_SERVER_HASH_LABEL.encode()
            + client_nonce
            + server_nonce,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(
            server_hash,
            expected_server_hash,
        ):
            raise RuntimeError(
                "Tor server hash verification failed."
            )

        client_hash = hmac.new(
            cookie,
            TOR_CLIENT_HASH_LABEL.encode()
            + client_nonce
            + server_nonce,
            hashlib.sha256,
        ).digest()

        control_socket.sendall(
            b"AUTHENTICATE "
            + client_hash.hex().encode()
            + b"\r\n"
        )

        response = self.read_control_response(control_socket)

        if "250" not in response:
            raise RuntimeError(
                "Tor SAFECOOKIE authentication failed."
            )

    def read_control_response(self, control_socket):
        data = b""

        while True:
            chunk = control_socket.recv(4096)

            if not chunk:
                break

            data += chunk

            if b"\r\n\r\n" in data or data.endswith(b"\r\n"):
                break

        return data.decode(errors="ignore")

    def extract_control_value(self, response, key):
        match = re.search(
            rf"{key}=([A-Fa-f0-9]+)",
            response,
        )

        if not match:
            raise RuntimeError(
                f"Missing {key} in Tor response."
            )

        return match.group(1)

    def get_tor_info(self, key):
        with socket.create_connection(
            (
                TOR_CONTROL_HOST,
                TOR_CONTROL_PORT,
            ),
            timeout=5,
        ) as control_socket:
            self.tor_control_auth(control_socket)

            control_socket.sendall(
                f"GETINFO {key}\r\n".encode()
            )

            return self.read_control_response(control_socket)

    def get_exit_node(self, circuits):
        for line in circuits.splitlines():
            if "EXIT" in line:
                parts = line.split()

                for part in parts:
                    if part.startswith("$"):
                        return part[1:11]

        return "Unknown"

    def render_tor_diagnostics(self):
        details = self.tor_diagnostics
        circuits = details.get("circuits", [])

        text = (
            f"Tor version: {details.get('version', 'Unknown')}\n"
            f"Active circuits: {len(circuits)}\n"
            f"Exit node: {details.get('exit_node', 'Unknown')}\n"
            f"Country: {details.get('country', 'Unknown')}\n"
            f"Last IP change: {details.get('last_ip_change', 'Never')}\n\n"
            "Active circuits:\n"
        )

        for circuit in circuits:
            text += f"{circuit}\n"

        self.update_diagnostics_text(text)
        self.update_ip_graph()

    def update_ip_graph(self):
        self.diagnostics_plot.clear()

        times = [
            item["time"]
            for item in self.ip_history
        ]

        ips = [
            item["ip"]
            for item in self.ip_history
        ]

        if not times:
            self.diagnostics_plot.text(
                0.5,
                0.5,
                "No IP changes yet",
                ha="center",
                va="center",
                color="white",
            )

        else:
            self.diagnostics_plot.plot(
                times,
                range(len(ips)),
                marker="o",
                color=self.colors["accent"],
            )

            self.diagnostics_plot.set_title(
                "IP changes over time",
                color="white",
            )

            self.diagnostics_plot.set_xlabel(
                "Time",
                color="white",
            )

            self.diagnostics_plot.set_ylabel(
                "IP change",
                color="white",
            )

            self.diagnostics_plot.tick_params(
                colors="white",
            )

        self.diagnostics_figure.patch.set_facecolor(
            self.colors["surface"]
        )

        self.diagnostics_canvas.draw()

    def update_diagnostics_text(self, text):
        if hasattr(self, "diagnostics_text"):
            self.diagnostics_text.configure(state="normal")
            self.diagnostics_text.delete("1.0", "end")
            self.diagnostics_text.insert("end", text)
            self.diagnostics_text.configure(state="disabled")

    def rotate_tor_ip(self):
        if not self.use_tor_var.get():
            self.add_system_message(
                "Enable Use Tor proxy first."
            )
            return

        def worker():
            try:
                self.tor_log("Requesting new Tor identity...")

                with socket.create_connection(
                    (
                        TOR_CONTROL_HOST,
                        TOR_CONTROL_PORT,
                    ),
                    timeout=5,
                ) as control_socket:
                    self.tor_control_auth(control_socket)

                    control_socket.sendall(
                        b"SIGNAL NEWNYM\r\n"
                    )

                    response = (
                        self.read_control_response(control_socket)
                    )

                    if "250" not in response:
                        raise RuntimeError(
                            "Tor rejected NEWNYM signal."
                        )

                self.tor_log(
                    "New Tor identity requested successfully.",
                    level="success",
                )

                self.last_ip_change = datetime.now()

                time.sleep(2)
                self.check_tor_status()

            except Exception as error:
                self.tor_log(
                    f"IP rotation failed: {error}",
                    level="error",
                )

                self.after(
                    0,
                    lambda: self.add_system_message(
                        "IP rotation failed. Enable Tor ControlPort."
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def start_ip_rotation_timer(self):
        self.stop_ip_rotation_timer()

        interval = self.ip_rotate_interval.get()

        if interval <= 0:
            return

        self.ip_rotate_job = self.after(
            interval * 1000,
            self.auto_rotate_ip,
        )

    def auto_rotate_ip(self):
        if self.use_tor_var.get():
            self.rotate_tor_ip()

        self.start_ip_rotation_timer()

    def stop_ip_rotation_timer(self):
        if self.ip_rotate_job:
            self.after_cancel(self.ip_rotate_job)
            self.ip_rotate_job = None

    def check_dns_leak(self):
        if not self.tor_proxy_url:
            self.add_system_message(
                "Enable Use Tor proxy first."
            )
            return

        def worker():
            try:
                self.tor_log("Checking DNS through Tor...")

                with httpx.Client(
                    proxy=self.tor_proxy_url,
                    timeout=15.0,
                ) as client:
                    response = client.get(DNS_CHECK_URL)
                    response.raise_for_status()

                    data = response.json()

                    if data.get("Status") == 0:
                        self.tor_log(
                            "DNS request completed through Tor.",
                            level="success",
                        )
                    else:
                        self.tor_log(
                            "DNS request failed.",
                            level="warning",
                        )

            except Exception as error:
                self.tor_log(
                    f"DNS check failed: {error}",
                    level="error",
                )

        threading.Thread(target=worker, daemon=True).start()

    def check_web_through_tor(self):
        if not self.tor_proxy_url:
            self.add_system_message(
                "Enable Use Tor proxy first."
            )
            return

        def worker():
            try:
                self.tor_log(
                    "Checking web access through Tor..."
                )

                with httpx.Client(
                    proxy=self.tor_proxy_url,
                    timeout=15.0,
                ) as client:
                    response = client.get(WEB_CHECK_URL)
                    response.raise_for_status()

                    data = response.json()

                    if data.get("IsTor") is True:
                        self.tor_log(
                            "Web access through Tor confirmed.",
                            level="success",
                        )
                    else:
                        self.tor_log(
                            "Web access is not going through Tor.",
                            level="warning",
                        )

            except Exception as error:
                self.tor_log(
                    f"Web check failed: {error}",
                    level="error",
                )

        threading.Thread(target=worker, daemon=True).start()

    def run_speed_test(self):
        if not self.tor_proxy_url:
            self.add_system_message(
                "Enable Use Tor proxy first."
            )
            return

        def worker():
            try:
                self.tor_log("Running Tor speed test...")

                start_time = time.time()

                with httpx.Client(
                    proxy=self.tor_proxy_url,
                    timeout=30.0,
                ) as client:
                    response = client.get(SPEED_TEST_URL)
                    response.raise_for_status()

                    elapsed = time.time() - start_time
                    size = len(response.content)

                    speed_mbps = (
                        size * 8 / elapsed / 1_000_000
                    )

                self.tor_log(
                    f"Speed test: {speed_mbps:.2f} Mbps",
                    level="success",
                )

                self.after(
                    0,
                    lambda: self.add_system_message(
                        f"Tor speed: {speed_mbps:.2f} Mbps"
                    ),
                )

            except Exception as error:
                self.tor_log(
                    f"Speed test failed: {error}",
                    level="error",
                )

        threading.Thread(target=worker, daemon=True).start()

    def open_traffic_monitor(self):
        if hasattr(self, "traffic_window") and self.traffic_window.winfo_exists():
            self.traffic_window.lift()
            return

        self.traffic_window = tk.Toplevel(self)
        self.traffic_window.title(f"{BOT_NAME} — Traffic Monitor")
        self.traffic_window.geometry("1000x650")
        self.traffic_window.configure(bg=self.colors["background"])

        frame = ttk.Frame(self.traffic_window, padding=10)
        frame.pack(fill="both", expand=True)

        filter_frame = ttk.Frame(frame)
        filter_frame.pack(fill="x", pady=(0, 8))

        ttk.Label(
            filter_frame,
            text="Filter:",
        ).pack(side="left")

        self.traffic_filter_var = tk.StringVar()

        self.traffic_filter_entry = ttk.Entry(
            filter_frame,
            textvariable=self.traffic_filter_var,
            width=30,
        )
        self.traffic_filter_entry.pack(
            side="left",
            padx=8,
        )

        ttk.Button(
            filter_frame,
            text="Apply",
            command=self.apply_traffic_filter,
        ).pack(side="left")

        ttk.Button(
            filter_frame,
            text="Clear",
            command=self.clear_traffic_filter,
        ).pack(side="left", padx=6)

        self.traffic_area = scrolledtext.ScrolledText(
            frame,
            wrap="word",
            font=("Menlo", 10),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
        )
        self.traffic_area.pack(fill="both", expand=True)

        self.traffic_area.tag_configure(
            "info",
            foreground=self.colors["muted"],
        )

        self.traffic_area.tag_configure(
            "success",
            foreground=self.colors["success"],
        )

        self.traffic_area.tag_configure(
            "warning",
            foreground=self.colors["warning"],
        )

        self.traffic_area.tag_configure(
            "error",
            foreground=self.colors["danger"],
        )

        ttk.Button(
            frame,
            text="Start monitoring",
            command=self.start_traffic_monitor,
        ).pack(pady=8)

        ttk.Button(
            frame,
            text="Stop monitoring",
            command=self.stop_traffic_monitor,
        ).pack(pady=8)

    def apply_traffic_filter(self):
        filter_text = self.traffic_filter_var.get().strip()

        if not filter_text:
            return

        self.traffic_area.delete("1.0", "end")

        for line in self.traffic_log_lines:
            if filter_text.lower() in line.lower():
                self.traffic_area.insert(
                    "end",
                    line + "\n",
                    "info",
                )

    def clear_traffic_filter(self):
        self.traffic_filter_var.set("")
        self.traffic_area.delete("1.0", "end")

    def start_traffic_monitor(self):
        self.stop_traffic_monitor()

        self.traffic_monitor_job = self.after(
            5000,
            self.update_traffic_stats,
        )

    def stop_traffic_monitor(self):
        if self.traffic_monitor_job:
            self.after_cancel(self.traffic_monitor_job)
            self.traffic_monitor_job = None

    def update_traffic_stats(self):
        if not self.tor_proxy_url:
            return

        try:
            streams = self.get_tor_info("stream-status")

            stream_count = len(
                [
                    line
                    for line in streams.splitlines()
                    if line.strip()
                ]
            )

            self.traffic_stats["requests"] += 1

            line = (
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Active streams: {stream_count}"
            )

            self.traffic_log_lines.append(line)

            self.traffic_area.insert(
                "end",
                line + "\n",
                "info",
            )

            self.traffic_area.see("end")

        except Exception as error:
            self.traffic_stats["errors"] += 1

            line = (
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Traffic monitor error: {error}"
            )

            self.traffic_log_lines.append(line)

            self.traffic_area.insert(
                "end",
                line + "\n",
                "error",
            )

            self.traffic_area.see("end")

        self.traffic_monitor_job = self.after(
            5000,
            self.update_traffic_stats,
        )

    def open_security_dashboard(self):
        window = tk.Toplevel(self)
        window.title(f"{BOT_NAME} — Security Dashboard")
        window.geometry("1100x720")
        window.configure(bg=self.colors["background"])

        notebook = ttk.Notebook(window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        overview = ttk.Frame(notebook)
        notebook.add(overview, text="Overview")

        tor_tab = ttk.Frame(notebook)
        notebook.add(tor_tab, text="Tor")

        traffic_tab = ttk.Frame(notebook)
        notebook.add(traffic_tab, text="Traffic")

        self.dashboard_overview = tk.Text(
            overview,
            wrap="word",
            font=("Menlo", 11),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            relief="flat",
        )
        self.dashboard_overview.pack(fill="both", expand=True)

        self.dashboard_tor = tk.Text(
            tor_tab,
            wrap="word",
            font=("Menlo", 11),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            relief="flat",
        )
        self.dashboard_tor.pack(fill="both", expand=True)

        self.dashboard_traffic = tk.Text(
            traffic_tab,
            wrap="word",
            font=("Menlo", 11),
            bg=self.colors["surface"],
            fg=self.colors["text"],
            relief="flat",
        )
        self.dashboard_traffic.pack(fill="both", expand=True)

        self.update_security_dashboard()

    def update_security_dashboard(self):
        tor_status = (
            "ON" if self.use_tor_var.get() else "OFF"
        )

        overview_text = (
            f"Tor status: {tor_status}\n"
            f"Private mode: {self.private_mode.get()}\n"
            f"Current model: {self.current_model}\n"
            f"Knowledge chunks: {len(self.rag.chunks)}\n"
            f"Tor requests: {self.traffic_stats['requests']}\n"
            f"Tor errors: {self.traffic_stats['errors']}\n"
        )

        tor_text = (
            f"Tor proxy: {self.tor_proxy_url or 'Not connected'}\n"
            f"Exit IP: {self.tor_details.get('ip', 'Unknown')}\n"
            f"Country: {self.tor_details.get('country', 'Unknown')}\n"
            f"Last check: {self.tor_details.get('checked_at', 'Unknown')}\n"
        )

        traffic_text = (
            f"Requests: {self.traffic_stats['requests']}\n"
            f"Errors: {self.traffic_stats['errors']}\n"
        )

        self.dashboard_overview.delete("1.0", "end")
        self.dashboard_overview.insert("end", overview_text)

        self.dashboard_tor.delete("1.0", "end")
        self.dashboard_tor.insert("end", tor_text)

        self.dashboard_traffic.delete("1.0", "end")
        self.dashboard_traffic.insert("end", traffic_text)

    def export_dashboard(self):
        file_path = filedialog.asksaveasfilename(
            title="Export dashboard",
            defaultextension=".pdf",
            filetypes=[
                ("PDF file", "*.pdf"),
                ("HTML file", "*.html"),
            ],
        )

        if not file_path:
            return

        if file_path.endswith(".pdf"):
            self.export_dashboard_pdf(file_path)
        elif file_path.endswith(".html"):
            self.export_dashboard_html(file_path)
        else:
            self.add_system_message(
                "Unsupported export format."
            )

    def export_dashboard_pdf(self, path):
        doc = SimpleDocTemplate(
            path,
            pagesize=A4,
        )

        styles = getSampleStyleSheet()

        elements = []

        elements.append(
            Paragraph(
                f"{BOT_NAME} Security Dashboard",
                styles["Title"],
            )
        )

        elements.append(
            Spacer(1, 12)
        )

        overview_text = (
            f"Tor status: {self.use_tor_var.get()}\n"
            f"Private mode: {self.private_mode.get()}\n"
            f"Current model: {self.current_model}\n"
            f"Knowledge chunks: {len(self.rag.chunks)}\n"
            f"Tor requests: {self.traffic_stats['requests']}\n"
            f"Tor errors: {self.traffic_stats['errors']}\n"
        )

        elements.append(
            Paragraph(
                overview_text.replace("\n", "<br/>"),
                styles["Normal"],
            )
        )

        elements.append(
            Spacer(1, 12)
        )

        tor_text = (
            f"Tor proxy: {self.tor_proxy_url or 'Not connected'}\n"
            f"Exit IP: {self.tor_details.get('ip', 'Unknown')}\n"
            f"Country: {self.tor_details.get('country', 'Unknown')}\n"
            f"Last check: {self.tor_details.get('checked_at', 'Unknown')}\n"
        )

        elements.append(
            Paragraph(
                tor_text.replace("\n", "<br/>"),
                styles["Normal"],
            )
        )

        elements.append(
            Spacer(1, 12)
        )

        traffic_text = (
            f"Requests: {self.traffic_stats['requests']}\n"
            f"Errors: {self.traffic_stats['errors']}\n"
        )

        elements.append(
            Paragraph(
                traffic_text.replace("\n", "<br/>"),
                styles["Normal"],
            )
        )

        doc.build(elements)

        self.add_system_message(
            f"Dashboard exported to PDF: {path}"
        )

    def export_dashboard_html(self, path):
        overview_text = (
            f"Tor status: {self.use_tor_var.get()}\n"
            f"Private mode: {self.private_mode.get()}\n"
            f"Current model: {self.current_model}\n"
            f"Knowledge chunks: {len(self.rag.chunks)}\n"
            f"Tor requests: {self.traffic_stats['requests']}\n"
            f"Tor errors: {self.traffic_stats['errors']}\n"
        )

        tor_text = (
            f"Tor proxy: {self.tor_proxy_url or 'Not connected'}\n"
            f"Exit IP: {self.tor_details.get('ip', 'Unknown')}\n"
            f"Country: {self.tor_details.get('country', 'Unknown')}\n"
            f"Last check: {self.tor_details.get('checked_at', 'Unknown')}\n"
        )

        traffic_text = (
            f"Requests: {self.traffic_stats['requests']}\n"
            f"Errors: {self.traffic_stats['errors']}\n"
        )

        html = f"""
        <html>
        <head>
            <title>{BOT_NAME} Security Dashboard</title>
        </head>
        <body>
            <h1>{BOT_NAME} Security Dashboard</h1>
            <h2>Overview</h2>
            <pre>{overview_text}</pre>
            <h2>Tor</h2>
            <pre>{tor_text}</pre>
            <h2>Traffic</h2>
            <pre>{traffic_text}</pre>
        </body>
        </html>
        """

        Path(path).write_text(
            html,
            encoding="utf-8",
        )

        self.add_system_message(
            f"Dashboard exported to HTML: {path}"
        )

    def export_security_logs(self):
        password = self.ask_for_password()

        if not password:
            return

        file_path = filedialog.asksaveasfilename(
            title="Export security logs",
            defaultextension=".zip",
            filetypes=[
                ("ZIP file", "*.zip"),
            ],
        )

        if not file_path:
            return

        with AESZipFile(
            file_path,
            "w",
            compression=ZIP_LZMA,
            encryption=WZ_AES,
        ) as zip_file:
            zip_file.setpassword(password.encode())
            zip_file.setencryption(WZ_AES, nbits=256)
            zip_file.writestr(
                "tw1n_security.log",
                "\n".join(self.tor_log_lines),
            )

        self.add_system_message(
            f"Security logs exported to encrypted ZIP: {file_path}"
        )

    def ask_for_password(self):
        password = simpledialog.askstring(
            "Password",
            "Enter password for encrypted export:",
            show="*",
        )

        return password

    def add_system_message(self, text):
        self.chat_area.configure(state="normal")
        self.chat_area.insert(
            "end",
            f"{BOT_NAME}: {text}\n\n",
            "system",
        )
        self.chat_area.see("end")
        self.chat_area.configure(state="disabled")

    def add_user_message(self, text):
        self.chat_area.configure(state="normal")
        self.chat_area.insert("end", "You: ", "user")
        self.chat_area.insert("end", f"{text}\n\n")
        self.chat_area.see("end")
        self.chat_area.configure(state="disabled")

    def add_bot_message(self, text):
        self.chat_area.configure(state="normal")
        self.chat_area.insert("end", f"{BOT_NAME}: ", "bot")
        self.chat_area.insert("end", f"{text}\n\n")
        self.chat_area.see("end")
        self.chat_area.configure(state="disabled")

    def add_source_message(self, sources):
        if not sources:
            return

        names = sorted(
            {source["source"] for source in sources}
        )

        self.chat_area.configure(state="normal")
        self.chat_area.insert(
            "end",
            f"Sources: {', '.join(names)}\n\n",
            "source",
        )
        self.chat_area.see("end")
        self.chat_area.configure(state="disabled")

    def on_enter(self, event):
        self.send_message()
        return "break"

    def send_message(self):
        user_text = self.input_box.get("1.0", "end").strip()

        if not user_text:
            return

        self.input_box.delete("1.0", "end")
        self.add_user_message(user_text)

        threading.Thread(
            target=self.process_message,
            args=(user_text,),
            daemon=True,
        ).start()

    def process_message(self, user_text):
        context = self.rag.search(user_text)

        if context:
            context_text = "\n\n".join(
                f"Source: {item['source']}\n{item['text']}"
                for item in context
            )

            request = (
                "Use the following context from the user's documents "
                "if it is relevant.\n\n"
                f"{context_text}\n\n"
                f"Question: {user_text}"
            )
        else:
            request = user_text

        self.messages.append(
            {"role": "user", "content": request}
        )
        self.messages = self.trim_history(self.messages)

        try:
            stream = self.client.chat.completions.create(
                model=self.current_model,
                messages=self.messages,
                stream=True,
                temperature=self.temperature,
            )

            answer_parts = []

            for chunk in stream:
                if not chunk.choices:
                    continue

                content = chunk.choices[0].delta.content

                if content:
                    answer_parts.append(content)

            answer = "".join(answer_parts).strip()

            if not answer:
                self.after(
                    0,
                    lambda: self.add_system_message(
                        "Empty response."
                    ),
                )
                self.messages.pop()
                return

            self.messages.append(
                {"role": "assistant", "content": answer}
            )

            self.after(
                0,
                lambda: self.add_bot_message(answer),
            )

            if context:
                self.after(
                    0,
                    lambda: self.add_source_message(context),
                )

            if self.speak_answers.get():
                self.after(
                    0,
                    lambda: self.speak_text(answer),
                )

        except Exception as error:
            self.after(
                0,
                lambda: self.add_system_message(
                    f"Error: {error}"
                ),
            )
            self.messages.pop()

    def trim_history(self, messages):
        system = messages[0]
        history = messages[1:]
        return [system] + history[-MAX_HISTORY * 2:]

    def add_knowledge_files(self):
        paths = filedialog.askopenfilenames(
            title="Select knowledge files",
            filetypes=[
                (
                    "Supported documents",
                    "*.txt *.md *.pdf *.docx",
                ),
                ("All files", "*.*"),
            ],
        )

        if not paths:
            return

        added = 0

        for path in paths:
            try:
                self.rag.add_file(path)
                added += 1
            except Exception as error:
                messagebox.showerror(
                    BOT_NAME,
                    f"Could not read {path}:\n{error}",
                )

        self.knowledge_label.configure(
            text=f"Knowledge: {len(self.rag.chunks)} chunks"
        )

        self.add_system_message(
            f"Added {added} file(s). "
            f"Knowledge base has {len(self.rag.chunks)} chunks."
        )

    def clear_knowledge(self):
        self.rag.clear()
        self.knowledge_label.configure(
            text="Knowledge: 0 chunks"
        )
        self.add_system_message("Knowledge base cleared.")

    def start_voice_input(self):
        threading.Thread(
            target=self.record_and_transcribe,
            daemon=True,
        ).start()

    def record_and_transcribe(self):
        try:
            self.after(
                0,
                lambda: self.add_system_message(
                    f"Recording for {RECORD_SECONDS} seconds..."
                ),
            )

            recording = sd.rec(
                int(SAMPLE_RATE * RECORD_SECONDS),
                samplerate=SAMPLE_RATE,
                channels=1,
                dtype="int16",
            )
            sd.wait()

            buffer = io.BytesIO()

            with wave.open(buffer, "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(SAMPLE_RATE)
                wav_file.writeframes(recording.tobytes())

            buffer.seek(0)

            with tempfile.NamedTemporaryFile(
                suffix=".wav",
                delete=False,
            ) as temp_file:
                temp_file.write(buffer.read())
                temp_path = temp_file.name

            with open(temp_path, "rb") as audio_file:
                response = self.client.audio.transcriptions.create(
                    model=STT_MODEL,
                    file=audio_file,
                )

            Path(temp_path).unlink(missing_ok=True)

            text = response.text.strip()

            if not text:
                self.after(
                    0,
                    lambda: self.add_system_message(
                        "I could not hear you."
                    ),
                )
                return

            self.after(
                0,
                lambda: self.add_user_message(
                    f"{text} (voice)"
                ),
            )
            self.after(
                0,
                lambda: self.process_message(text),
            )

        except Exception as error:
            self.after(
                0,
                lambda: self.add_system_message(
                    f"Voice error: {error}"
                ),
            )

    def speak_last_answer(self):
        for message in reversed(self.messages):
            if message.get("role") == "assistant":
                self.speak_text(message["content"])
                return

        self.add_system_message("No answer to speak yet.")

    def speak_text(self, text):
        if not text.strip():
            return

        def worker():
            try:
                response = self.client.audio.speech.create(
                    model=TTS_MODEL,
                    voice=TTS_VOICE,
                    input=text[:500],
                    response_format="wav",
                )

                audio_bytes = response.content

                with tempfile.NamedTemporaryFile(
                    suffix=".wav",
                    delete=False,
                ) as temp_file:
                    temp_file.write(audio_bytes)
                    temp_path = temp_file.name

                data, samplerate = sf.read(temp_path)
                sd.play(data, samplerate)
                sd.wait()

                Path(temp_path).unlink(missing_ok=True)

            except Exception as error:
                self.after(
                    0,
                    lambda: self.add_system_message(
                        f"Speech error: {error}"
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def new_private_chat(self):
        self.private_mode.set(True)
        self.clear_chat()
        self.add_system_message(
            "New private chat started. "
            "This session will not be saved to disk."
        )

    def on_close(self):
        self.stop_tor_autocheck()
        self.stop_ip_rotation_timer()
        self.stop_traffic_monitor()

        if not self.private_mode.get():
            self.save_chat()

        self.destroy()

    def save_chat(self):
        if self.private_mode.get():
            self.add_system_message(
                "Private mode is on. Chat was not saved."
            )
            return

        try:
            CHAT_FILE.write_text(
                json.dumps(
                    self.messages,
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as error:
            self.add_system_message(
                f"Could not save chat: {error}"
            )
        else:
            self.add_system_message(
                f"Chat saved to {CHAT_FILE.name}."
            )

    def load_chat(self):
        try:
            messages = json.loads(
                CHAT_FILE.read_text(encoding="utf-8")
            )

            if not isinstance(messages, list) or not messages:
                raise ValueError("Chat file is empty or invalid.")

            if messages[0].get("role") != "system":
                raise ValueError("Missing system message.")

            self.messages = messages

        except FileNotFoundError:
            self.add_system_message("No saved chat found.")
        except (OSError, ValueError) as error:
            self.add_system_message(
                f"Could not load chat: {error}"
            )
        else:
            self.add_system_message(
                f"Chat loaded from {CHAT_FILE.name}."
            )

    def clear_chat(self):
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT}
        ]
        self.add_system_message("Chat cleared.")

    def change_model(self, event=None):
        selected = self.model_var.get()

        if selected:
            self.current_model = selected
            self.add_system_message(
                f"Model changed to {self.current_model}."
            )


def main():
    app = TW1NApp()
    app.mainloop()


if __name__ == "__main__":
    main()
