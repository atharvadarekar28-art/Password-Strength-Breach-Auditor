"""
Password Security & Breach Auditor (k-Anonymity)
Native desktop GUI built with PyQt6 (No Tkinter used).
Adheres strictly to the developer-utility layout from reference mockup,
with high-contrast visible text, zero-knowledge HIBP auditing, and QThread concurrency.
"""

import sys
import os
import math
import string
import ctypes
from typing import Dict, Any, List

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QProgressBar,
    QTabWidget, QTextBrowser, QFrame, QGridLayout, QMessageBox,
    QRadioButton, QButtonGroup, QScrollArea, QDialog
)
from PyQt6.QtGui import QFont, QIcon, QColor, QPainter, QBrush, QPen

# Import core security modules
from core.hibp_client import audit_pwned_password
from core.entropy_calculator import analyze_entropy
from core.pattern_detector import detect_patterns
from core.scorer import calculate_score
from core.generator import generate_random_password, generate_diceware_passphrase


def set_dark_titlebar(window: QWidget):
    """Enables Windows 10/11 immersive dark mode title bar."""
    try:
        hwnd = int(window.winId())
        # DWMWA_USE_IMMERSIVE_DARK_MODE is 20 in Windows 10 18985+ / Windows 11, 19 in earlier builds
        for attr in (20, 19):
            val = ctypes.c_int(1)
            ret = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attr, ctypes.byref(val), ctypes.sizeof(val)
            )
            if ret == 0:
                break
    except Exception:
        pass


# Global QSS Theme (Dark Slate Developer Utility with High-Contrast Visible Text)
STYLE_SHEET = """
QMainWindow, QWidget#CentralWidget {
    background-color: #121422;
    color: #e2e8f0;
    font-family: "Segoe UI", Arial, sans-serif;
}

/* Container Cards */
QFrame.CardFrame {
    background-color: #181c2e;
    border: 1px solid #282f4c;
    border-radius: 4px;
}

QFrame.InnerCard {
    background-color: #111424;
    border: 1px solid #242a44;
    border-radius: 4px;
}

/* Headers & Labels */
QLabel {
    color: #e2e8f0;
}

QLabel#AppTitle {
    color: #5b8bf7;
    font-size: 19px;
    font-weight: bold;
}

QLabel#AppSubtitle {
    color: #94a3b8;
    font-size: 11px;
}

QLabel#InputLabel {
    color: #cbd5e1;
    font-size: 12px;
    font-weight: bold;
}

QLabel#ScoreNumber {
    font-size: 32px;
    font-weight: bold;
    color: #ef4444;
}

QLabel#StatusBadge {
    font-size: 13px;
    font-weight: bold;
    color: #ef4444;
}

QLabel#AlertMsg {
    font-size: 11px;
    font-weight: bold;
    color: #f87171;
}

/* Inputs */
QLineEdit#PasswordInput {
    background-color: #0c0e1a;
    border: 1px solid #333a57;
    border-radius: 3px;
    color: #ffffff;
    font-family: "Consolas", monospace;
    font-size: 14px;
    padding: 7px 10px;
    selection-background-color: #2563eb;
}

QLineEdit#PasswordInput:focus {
    border: 1px solid #3b82f6;
}

QLineEdit#GenResultInput {
    background-color: #0c0e1a;
    border: 1px solid #2c334e;
    border-radius: 3px;
    color: #ffffff;
    font-family: "Consolas", monospace;
    font-size: 12px;
    padding: 5px 8px;
}

/* Buttons */
QPushButton#PrimaryButton {
    background-color: #2563eb;
    color: #ffffff;
    font-size: 12px;
    font-weight: bold;
    border: none;
    border-radius: 3px;
    padding: 7px 18px;
}

QPushButton#PrimaryButton:hover {
    background-color: #1d4ed8;
}

QPushButton#PrimaryButton:pressed {
    background-color: #1e40af;
}

QPushButton#PrimaryButton:disabled {
    background-color: #1e293b;
    color: #64748b;
}

QPushButton#SecondaryButton {
    background-color: #1e233a;
    color: #cbd5e1;
    font-size: 11px;
    border: 1px solid #2c3452;
    border-radius: 3px;
    padding: 5px 12px;
}

QPushButton#SecondaryButton:hover {
    background-color: #28304f;
    color: #ffffff;
}

QPushButton#SecondaryButton:pressed {
    background-color: #181d30;
}

QPushButton#LinkButton {
    background: transparent;
    color: #38bdf8;
    font-size: 11px;
    border: none;
    text-decoration: underline;
    padding: 0px;
}

QPushButton#LinkButton:hover {
    color: #7dd3fc;
}

/* Checkboxes */
QCheckBox {
    color: #cbd5e1;
    font-size: 11px;
    spacing: 6px;
}

QCheckBox::indicator {
    width: 14px;
    height: 14px;
    background-color: #0c0e1a;
    border: 1px solid #3b4263;
    border-radius: 2px;
}

QCheckBox::indicator:checked {
    background-color: #2563eb;
    border: 1px solid #3b82f6;
    image: none;
}

QRadioButton {
    color: #cbd5e1;
    font-size: 11px;
    spacing: 6px;
}

QRadioButton::indicator {
    width: 13px;
    height: 13px;
    background-color: #0c0e1a;
    border: 1px solid #3b4263;
    border-radius: 6px;
}

QRadioButton::indicator:checked {
    background-color: #2563eb;
    border: 1px solid #3b82f6;
}

/* Progress Bar */
QProgressBar#ScoreProgressBar {
    background-color: #0c0e1a;
    border: 1px solid #282f4c;
    border-radius: 2px;
    height: 12px;
    text-align: center;
}

QProgressBar#ScoreProgressBar::chunk {
    background-color: #ef4444;
    border-radius: 1px;
}

/* Tab Widget with 100% VISIBLE, HIGH-CONTRAST TEXT */
QTabWidget::pane {
    border: 1px solid #282f4c;
    background-color: #181c2e;
    top: -1px;
}

QTabBar::tab {
    background-color: #151829;
    color: #cbd5e1; /* Clear light slate text */
    font-size: 11px;
    font-weight: 600;
    border: 1px solid #282f4c;
    border-bottom: none;
    padding: 7px 14px;
    margin-right: 2px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}

QTabBar::tab:selected {
    background-color: #2563eb; /* High-contrast vibrant blue */
    color: #ffffff;            /* Pure white bold text */
    font-weight: bold;
    border: 1px solid #3b82f6;
    border-bottom: 1px solid #2563eb;
}

QTabBar::tab:hover:!selected {
    background-color: #22273e;
    color: #ffffff;
}

/* Console Text Views */
QTextBrowser {
    background-color: #090c17;
    border: 1px solid #242a44;
    border-radius: 3px;
    color: #e2e8f0;
    font-family: "Consolas", monospace;
    font-size: 12px;
    padding: 10px;
}

QScrollBar:vertical {
    background-color: #090c17;
    width: 10px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #232840;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #3b82f6;
}

/* Dialogs & Message Boxes - Explicit Dark Theme so text is always 100% visible */
QDialog, QMessageBox {
    background-color: #141728;
    color: #f1f5f9;
}

QMessageBox QLabel {
    color: #f1f5f9;
    background-color: transparent;
    font-size: 12px;
}

QMessageBox QPushButton {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: bold;
    border: none;
    border-radius: 3px;
    padding: 6px 18px;
    min-width: 75px;
}

QMessageBox QPushButton:hover {
    background-color: #1d4ed8;
}
"""


class KAnonymityDialog(QDialog):
    """Custom dark dialog with crisp, high-contrast typography explaining k-Anonymity."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Zero-Knowledge k-Anonymity Explained")
        self.resize(650, 530)
        self.setMinimumSize(560, 440)
        self.setStyleSheet("""
            QDialog {
                background-color: #131627;
                border: 1px solid #282f4c;
            }
        """)
        set_dark_titlebar(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)

        # Header with shield icon
        hdr_row = QHBoxLayout()
        hdr_row.setSpacing(12)

        shield_icon = QLabel("🛡️")
        shield_icon.setFont(QFont("Segoe UI Emoji", 22))
        hdr_row.addWidget(shield_icon)

        hdr_vbox = QVBoxLayout()
        hdr_vbox.setSpacing(2)

        title_lbl = QLabel("Zero-Knowledge k-Anonymity Protocol")
        title_lbl.setStyleSheet("color: #60a5fa; font-size: 16px; font-weight: bold;")
        hdr_vbox.addWidget(title_lbl)

        sub_lbl = QLabel("How passwords are checked against 850M+ leaks without ever transmitting them")
        sub_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        hdr_vbox.addWidget(sub_lbl)

        hdr_row.addLayout(hdr_vbox, stretch=1)
        layout.addLayout(hdr_row)

        # Content text browser with crisp high-contrast styling
        browser = QTextBrowser()
        browser.setStyleSheet("""
            QTextBrowser {
                background-color: #0a0d1a;
                border: 1px solid #252b47;
                border-radius: 4px;
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
                padding: 14px;
            }
        """)

        html = """
        <div style='line-height: 1.6;'>
            <p style='color: #38bdf8; font-weight: bold; font-size: 13px; margin-top: 0;'>
                HOW THE HAVE I BEEN PWNED k-ANONYMITY MODEL WORKS:
            </p>

            <div style='margin-bottom: 12px;'>
                <b style='color: #ffffff; font-size: 13px;'>1. Local Client-Side Hashing:</b><br/>
                <span style='color: #cbd5e1;'>
                Your computer calculates the 40-character SHA-1 hash strictly in memory using Python's <code>hashlib</code>.<br/>
                <span style='color: #34d399; font-weight: bold;'>✓ Your plaintext password never leaves this computer.</span>
                </span>
            </div>

            <div style='margin-bottom: 12px;'>
                <b style='color: #ffffff; font-size: 13px;'>2. 5-Character Prefix Transmission:</b><br/>
                <span style='color: #cbd5e1;'>
                Only the <b>first 5 hexadecimal characters</b> of the hash (e.g. <code>2FBD1</code>) are sent over HTTPS.<br/>
                Because 5 hex characters match thousands of different passwords, the remote server has <b>zero knowledge</b> of which password you entered.
                </span>
            </div>

            <div style='margin-bottom: 12px;'>
                <b style='color: #ffffff; font-size: 13px;'>3. Bulk Suffix Download:</b><br/>
                <span style='color: #cbd5e1;'>
                The HIBP API returns hundreds of hash suffixes that share the same 5-character prefix, along with their breach counts.
                </span>
            </div>

            <div style='margin-bottom: 12px;'>
                <b style='color: #ffffff; font-size: 13px;'>4. Client-Side Suffix Verification:</b><br/>
                <span style='color: #cbd5e1;'>
                Your computer checks the remaining 35-character suffix locally against the downloaded candidates in memory.
                </span>
            </div>

            <div style='margin-top: 14px; padding: 12px; background-color: #0f2b20; border: 1px solid #065f46; border-radius: 4px;'>
                <b style='color: #10b981; font-size: 13px;'>🔒 ZERO-KNOWLEDGE PRIVACY GUARANTEE:</b><br/>
                <span style='color: #a7f3d0;'>
                Your actual password and full hash <b>NEVER</b> left this computer at any point during the audit.
                </span>
            </div>
        </div>
        """
        browser.setHtml(html)
        layout.addWidget(browser, stretch=1)

        # OK button
        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_ok = QPushButton("OK")
        btn_ok.setObjectName("PrimaryButton")
        btn_ok.setFixedWidth(110)
        btn_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_ok.clicked.connect(self.accept)
        btn_box.addWidget(btn_ok)

        layout.addLayout(btn_box)


class AuditWorker(QThread):
    """Background worker thread for asynchronous HIBP queries and local computations."""
    finished = pyqtSignal(dict)

    def __init__(self, password: str, query_hibp: bool):
        super().__init__()
        self.password = password
        self.query_hibp = query_hibp

    def run(self):
        # 1. Local entropy
        entropy_info = analyze_entropy(self.password)

        # 2. Local patterns
        patterns = detect_patterns(self.password)

        # 3. HIBP k-Anonymity API check
        if self.query_hibp and self.password:
            breach_info = audit_pwned_password(self.password)
        else:
            breach_info = {
                "breached": False,
                "count": 0,
                "sha1_full": "",
                "sha1_prefix": "",
                "sha1_suffix": "",
                "api_url": "",
                "total_suffixes": 0,
                "error": None if not self.query_hibp else "Empty password"
            }

        # 4. Score calculation
        score_data = calculate_score(self.password, entropy_info, patterns, breach_info)

        # Emit back to main UI thread
        self.finished.emit({
            "password": self.password,
            "entropy": entropy_info,
            "patterns": patterns,
            "breach": breach_info,
            "score": score_data
        })


class PasswordAuditorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Security & Breach Auditor (k-Anonymity)")
        self.resize(1100, 780)
        self.setMinimumSize(980, 680)

        set_dark_titlebar(self)

        self.worker = None

        self._build_ui()
        self.setStyleSheet(STYLE_SHEET)

        # Run initial audit
        self.run_audit()

    def _build_ui(self):
        central_widget = QWidget(self)
        central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(24, 20, 24, 20)
        root_layout.setSpacing(14)

        # 1. Header Section
        root_layout.addLayout(self._create_header())

        # 2. Input Box Section
        root_layout.addWidget(self._create_input_card())

        # 3. Score & Status Banner Section
        root_layout.addWidget(self._create_score_banner())

        # 4. Tabbed Notebook Section
        root_layout.addWidget(self._create_tab_widget(), stretch=1)

    # --------------------------------------------------------------------------
    # Header Section
    # --------------------------------------------------------------------------
    def _create_header(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        layout.setSpacing(12)

        # Shield Icon
        shield_label = QLabel("🛡️")
        shield_label.setFont(QFont("Segoe UI Emoji", 24))
        layout.addWidget(shield_label)

        title_vbox = QVBoxLayout()
        title_vbox.setSpacing(2)

        title_lbl = QLabel("Password Auditor & Breach Checker")
        title_lbl.setObjectName("AppTitle")
        title_vbox.addWidget(title_lbl)

        sub_lbl = QLabel("Evaluates length, entropy, patterns, and checks Have I Been Pwned via zero-knowledge k-Anonymity.")
        sub_lbl.setObjectName("AppSubtitle")
        title_vbox.addWidget(sub_lbl)

        layout.addLayout(title_vbox, stretch=1)
        return layout

    # --------------------------------------------------------------------------
    # Input Box Section
    # --------------------------------------------------------------------------
    def _create_input_card(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 14, 18, 14)
        card_layout.setSpacing(8)

        # Top row: Label + Generate Link
        top_row = QHBoxLayout()
        lbl = QLabel("Enter Password to Audit:")
        lbl.setObjectName("InputLabel")
        top_row.addWidget(lbl)

        top_row.addStretch()

        self.btn_gen_link = QPushButton("🎲 Generate Strong Password")
        self.btn_gen_link.setObjectName("LinkButton")
        self.btn_gen_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_gen_link.clicked.connect(self.quick_generate)
        top_row.addWidget(self.btn_gen_link)

        card_layout.addLayout(top_row)

        # Middle row: Input + Audit Now Button
        input_row = QHBoxLayout()
        input_row.setSpacing(10)

        self.pwd_input = QLineEdit()
        self.pwd_input.setObjectName("PasswordInput")
        self.pwd_input.setPlaceholderText("Enter password here...")
        self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_input.returnPressed.connect(self.run_audit)
        input_row.addWidget(self.pwd_input, stretch=1)

        self.btn_audit = QPushButton("🔍 Audit Now")
        self.btn_audit.setObjectName("PrimaryButton")
        self.btn_audit.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_audit.clicked.connect(self.run_audit)
        input_row.addWidget(self.btn_audit)

        card_layout.addLayout(input_row)

        # Bottom row: Checkboxes + Toast Status
        check_row = QHBoxLayout()
        check_row.setSpacing(20)

        self.cb_show = QCheckBox("Show Password")
        self.cb_show.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cb_show.toggled.connect(self.toggle_show_password)
        check_row.addWidget(self.cb_show)

        self.cb_hibp = QCheckBox("Query Have I Been Pwned (k-Anonymity prefix check)")
        self.cb_hibp.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cb_hibp.setChecked(True)
        check_row.addWidget(self.cb_hibp)

        check_row.addStretch()

        self.lbl_toast = QLabel("")
        self.lbl_toast.setStyleSheet("color: #34d399; font-weight: bold; font-size: 11px;")
        check_row.addWidget(self.lbl_toast)

        card_layout.addLayout(check_row)

        return card

    # --------------------------------------------------------------------------
    # Score & Status Banner Section
    # --------------------------------------------------------------------------
    def _create_score_banner(self) -> QFrame:
        card = QFrame()
        card.setProperty("class", "CardFrame")
        card_layout = QHBoxLayout(card)
        card_layout.setContentsMargins(20, 16, 20, 16)
        card_layout.setSpacing(24)

        # Left Column: Big Score & Status Badge
        left_vbox = QVBoxLayout()
        left_vbox.setSpacing(2)

        self.lbl_score = QLabel("0 / 100")
        self.lbl_score.setObjectName("ScoreNumber")
        left_vbox.addWidget(self.lbl_score)

        self.lbl_status = QLabel("🚨 COMPROMISED (Found in breaches!)")
        self.lbl_status.setObjectName("StatusBadge")
        left_vbox.addWidget(self.lbl_status)

        card_layout.addLayout(left_vbox)

        # Right Column: Progress Bar & Alert Message
        right_vbox = QVBoxLayout()
        right_vbox.setSpacing(8)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("ScoreProgressBar")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        right_vbox.addWidget(self.progress_bar)

        self.lbl_alert = QLabel("⚠️ BREACH DETECTED: Seen in 55 public data leaks!")
        self.lbl_alert.setObjectName("AlertMsg")
        right_vbox.addWidget(self.lbl_alert)

        card_layout.addLayout(right_vbox, stretch=1)
        return card

    # --------------------------------------------------------------------------
    # Tab Widget Section
    # --------------------------------------------------------------------------
    def _create_tab_widget(self) -> QTabWidget:
        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(False)

        # Tab 0: Breach Verification
        self.tab_breach = QWidget()
        self._setup_tab_breach(self.tab_breach)
        self.tabs.addTab(self.tab_breach, "🔍 Breach Verification")

        # Tab 1: Entropy & Crack Times
        self.tab_entropy = QWidget()
        self._setup_tab_entropy(self.tab_entropy)
        self.tabs.addTab(self.tab_entropy, "⚡ Entropy & Cracking")

        # Tab 2: Pattern Detection
        self.tab_patterns = QWidget()
        self._setup_tab_patterns(self.tab_patterns)
        self.tabs.addTab(self.tab_patterns, "⚠️ Pattern Detection")

        # Tab 3: Recommendations & Generator
        self.tab_recom = QWidget()
        self._setup_tab_recom(self.tab_recom)
        self.tabs.addTab(self.tab_recom, "💡 Recommendations")

        return self.tabs

    # --------------------------------------------------------------------------
    # Tab 0 Setup: Breach Verification
    # --------------------------------------------------------------------------
    def _setup_tab_breach(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        self.txt_breach = QTextBrowser()
        self.txt_breach.setOpenExternalLinks(True)
        layout.addWidget(self.txt_breach, stretch=1)

        btn_row = QHBoxLayout()
        btn_copy = QPushButton("📋 Copy Verification Report")
        btn_copy.setObjectName("SecondaryButton")
        btn_copy.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_copy.clicked.connect(self.copy_breach_report)
        btn_row.addWidget(btn_copy)

        btn_explain = QPushButton("ℹ️ How Zero-Knowledge k-Anonymity Works")
        btn_explain.setObjectName("SecondaryButton")
        btn_explain.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_explain.clicked.connect(self.show_kanonymity_dialog)
        btn_row.addWidget(btn_explain)

        btn_row.addStretch()
        layout.addLayout(btn_row)

    # --------------------------------------------------------------------------
    # Tab 1 Setup: Entropy & Crack Times
    # --------------------------------------------------------------------------
    def _setup_tab_entropy(self, parent: QWidget):
        layout = QHBoxLayout(parent)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Left Card: Metrics
        left_card = QFrame()
        left_card.setProperty("class", "InnerCard")
        left_vbox = QVBoxLayout(left_card)
        left_vbox.setContentsMargins(14, 12, 14, 12)

        hdr1 = QLabel("INFORMATION ENTROPY & CHARSETS")
        hdr1.setStyleSheet("color: #60a5fa; font-weight: bold; font-size: 12px;")
        left_vbox.addWidget(hdr1)

        self.txt_entropy_metrics = QTextBrowser()
        self.txt_entropy_metrics.setStyleSheet("background: transparent; border: none; font-size: 11px;")
        left_vbox.addWidget(self.txt_entropy_metrics, stretch=1)

        layout.addWidget(left_card, stretch=1)

        # Right Card: Scenarios
        right_card = QFrame()
        right_card.setProperty("class", "InnerCard")
        right_vbox = QVBoxLayout(right_card)
        right_vbox.setContentsMargins(14, 12, 14, 12)

        hdr2 = QLabel("BRUTE-FORCE CRACK TIME SCENARIOS")
        hdr2.setStyleSheet("color: #60a5fa; font-weight: bold; font-size: 12px;")
        right_vbox.addWidget(hdr2)

        self.txt_crack_times = QTextBrowser()
        self.txt_crack_times.setStyleSheet("background: transparent; border: none; font-size: 11px;")
        right_vbox.addWidget(self.txt_crack_times, stretch=1)

        layout.addWidget(right_card, stretch=1)

    # --------------------------------------------------------------------------
    # Tab 2 Setup: Pattern Detection
    # --------------------------------------------------------------------------
    def _setup_tab_patterns(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setContentsMargins(14, 14, 14, 14)

        self.txt_patterns = QTextBrowser()
        layout.addWidget(self.txt_patterns, stretch=1)

    # --------------------------------------------------------------------------
    # Tab 3 Setup: Recommendations & Generator
    # --------------------------------------------------------------------------
    def _setup_tab_recom(self, parent: QWidget):
        layout = QVBoxLayout(parent)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Top: Recommendations text
        recom_card = QFrame()
        recom_card.setProperty("class", "InnerCard")
        recom_vbox = QVBoxLayout(recom_card)
        recom_vbox.setContentsMargins(14, 12, 14, 12)

        hdr1 = QLabel("ACTIONABLE SECURITY RECOMMENDATIONS")
        hdr1.setStyleSheet("color: #60a5fa; font-weight: bold; font-size: 12px;")
        recom_vbox.addWidget(hdr1)

        self.txt_recom = QTextBrowser()
        self.txt_recom.setStyleSheet("background: transparent; border: none; font-size: 11px;")
        recom_vbox.addWidget(self.txt_recom, stretch=1)

        layout.addWidget(recom_card, stretch=1)

        # Bottom: Generator Card
        gen_card = QFrame()
        gen_card.setProperty("class", "InnerCard")
        gen_vbox = QVBoxLayout(gen_card)
        gen_vbox.setContentsMargins(14, 12, 14, 12)
        gen_vbox.setSpacing(8)

        hdr2 = QLabel("STRONG PASSWORD & PASSPHRASE GENERATOR")
        hdr2.setStyleSheet("color: #60a5fa; font-weight: bold; font-size: 12px;")
        gen_vbox.addWidget(hdr2)

        # Radio buttons
        mode_row = QHBoxLayout()
        self.rb_random = QRadioButton("Random Cryptographic Characters (18 chars)")
        self.rb_random.setChecked(True)
        self.rb_random.setCursor(Qt.CursorShape.PointingHandCursor)
        mode_row.addWidget(self.rb_random)

        self.rb_diceware = QRadioButton("Diceware Multi-Word Passphrase (4 words)")
        self.rb_diceware.setCursor(Qt.CursorShape.PointingHandCursor)
        mode_row.addWidget(self.rb_diceware)

        mode_row.addStretch()
        gen_vbox.addLayout(mode_row)

        # Output entry + Action buttons
        out_row = QHBoxLayout()
        out_row.setSpacing(8)

        self.gen_input = QLineEdit()
        self.gen_input.setObjectName("GenResultInput")
        self.gen_input.setReadOnly(True)
        out_row.addWidget(self.gen_input, stretch=1)

        btn_gen = QPushButton("🎲 Generate")
        btn_gen.setObjectName("PrimaryButton")
        btn_gen.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_gen.clicked.connect(self.generate_in_tab)
        out_row.addWidget(btn_gen)

        btn_use = QPushButton("⚡ Use in Auditor")
        btn_use.setObjectName("SecondaryButton")
        btn_use.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_use.clicked.connect(self.use_generated_in_auditor)
        out_row.addWidget(btn_use)

        btn_copy = QPushButton("📋 Copy")
        btn_copy.setObjectName("SecondaryButton")
        btn_copy.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_copy.clicked.connect(self.copy_generated)
        out_row.addWidget(btn_copy)

        gen_vbox.addLayout(out_row)
        layout.addWidget(gen_card)

        # Initial password in generator
        self.generate_in_tab()

    # --------------------------------------------------------------------------
    # Audit Execution (QThread)
    # --------------------------------------------------------------------------
    def run_audit(self):
        if self.worker and self.worker.isRunning():
            return

        password = self.pwd_input.text()
        query_hibp = self.cb_hibp.isChecked()

        self.btn_audit.setText("⏳ Auditing...")
        self.btn_audit.setEnabled(False)

        self.worker = AuditWorker(password, query_hibp)
        self.worker.finished.connect(self._on_audit_finished)
        self.worker.start()

    def _on_audit_finished(self, data: dict):
        self.btn_audit.setText("🔍 Audit Now")
        self.btn_audit.setEnabled(True)

        password = data["password"]
        entropy_info = data["entropy"]
        patterns = data["patterns"]
        breach_info = data["breach"]
        score_data = data["score"]

        score = score_data["score"]
        status_label = score_data["status_label"]
        status_color = score_data["status_color"]
        summary_text = score_data["summary_text"]
        is_compromised = score_data["is_compromised"]

        # 1. Update Score & Banner
        self.lbl_score.setText(f"{score} / 100")
        self.lbl_score.setStyleSheet(f"color: {status_color}; font-size: 32px; font-weight: bold;")

        if is_compromised:
            badge_icon = "🚨"
            alert_fg = "#f87171"
            alert_text = f"⚠️ {summary_text}"
        elif score < 30:
            badge_icon = "⚠️"
            alert_fg = "#f87171"
            alert_text = f"⚠️ {summary_text}"
        elif score < 55:
            badge_icon = "⚠️"
            alert_fg = "#fbbf24"
            alert_text = f"⚠️ {summary_text}"
        elif score < 75:
            badge_icon = "🟡"
            alert_fg = "#fbbf24"
            alert_text = f"ℹ️ {summary_text}"
        elif score < 90:
            badge_icon = "🛡️"
            alert_fg = "#34d399"
            alert_text = f"✅ {summary_text}"
        else:
            badge_icon = "✅"
            alert_fg = "#34d399"
            alert_text = f"✅ {summary_text}"

        self.lbl_status.setText(f"{badge_icon} {status_label}")
        self.lbl_status.setStyleSheet(f"color: {status_color}; font-size: 13px; font-weight: bold;")

        self.progress_bar.setValue(score)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar#ScoreProgressBar::chunk {{
                background-color: {status_color};
                border-radius: 1px;
            }}
        """)

        self.lbl_alert.setText(alert_text)
        self.lbl_alert.setStyleSheet(f"color: {alert_fg}; font-size: 11px; font-weight: bold;")

        # 2. Update Tabs
        self._render_breach_tab(breach_info, password)
        self._render_entropy_tab(entropy_info)
        self._render_patterns_tab(patterns, password)
        self._render_recom_tab(score_data["recommendations"])

    # --------------------------------------------------------------------------
    # Render Tab Content
    # --------------------------------------------------------------------------
    def _render_breach_tab(self, breach_info: dict, password: str):
        if not password:
            html = """
            <p style='color: #60a5fa; font-weight: bold;'>--- HAVE I BEEN PWNED k-ANONYMITY VERIFICATION ---</p>
            <p style='color: #94a3b8;'>No password entered. Type a password or generate one above to audit.</p>
            """
            self.txt_breach.setHtml(html)
            return

        if not self.cb_hibp.isChecked():
            html = """
            <p style='color: #60a5fa; font-weight: bold;'>--- HAVE I BEEN PWNED k-ANONYMITY VERIFICATION ---</p>
            <p style='color: #f97316; font-weight: bold;'>• HIBP Query Mode: DISABLED by user (Local evaluation only).</p>
            <p style='color: #94a3b8;'>Check the 'Query Have I Been Pwned' checkbox above and click 'Audit Now' to query breaches.</p>
            """
            self.txt_breach.setHtml(html)
            return

        error = breach_info.get("error")
        if error:
            html = f"""
            <p style='color: #60a5fa; font-weight: bold;'>--- HAVE I BEEN PWNED k-ANONYMITY VERIFICATION ---</p>
            <p style='color: #ef4444; font-weight: bold;'>• Connection Notice: {error}</p>
            <p style='color: #94a3b8;'>Unable to reach HIBP API. Check your internet connection or firewall.</p>
            """
            self.txt_breach.setHtml(html)
            return

        prefix = breach_info.get("sha1_prefix", "")
        suffix = breach_info.get("sha1_suffix", "")
        masked_suffix = f"{suffix[:2]}...{suffix[-2:]}" if len(suffix) >= 4 else suffix
        count = breach_info.get("count", 0)
        is_breached = breach_info.get("breached", False)

        result_html = (
            f"<span style='color: #ef4444; font-weight: bold;'>COMPROMISED: Appeared {count:,} time(s) in known public data breaches!</span>"
            if is_breached else
            "<span style='color: #10b981; font-weight: bold;'>SAFE: 0 occurrences found in Have I Been Pwned database!</span>"
        )

        warning_block = ""
        if is_breached:
            warning_block = f"""
            <div style='margin-top: 14px; padding: 10px; background-color: #2d1519; border: 1px solid #7f1d1d; border-radius: 4px;'>
                <b style='color: #ef4444;'>SECURITY WARNING:</b><br/>
                <span style='color: #fca5a5;'>
                This exact password has appeared {count:,} times in known data breaches.<br/>
                Attackers test known breach lists first in automated credential stuffing attacks.<br/>
                <b>DO NOT USE THIS PASSWORD</b> for any account or service!
                </span>
            </div>
            """
        else:
            warning_block = """
            <div style='margin-top: 14px; padding: 10px; background-color: #0f2b20; border: 1px solid #065f46; border-radius: 4px;'>
                <b style='color: #10b981;'>SECURITY ASSESSMENT:</b><br/>
                <span style='color: #a7f3d0;'>
                No occurrences of this password were found across 850+ million breached records.<br/>
                Provided it has adequate length and entropy, it is well protected against dictionary dumps.
                </span>
            </div>
            """

        html = f"""
        <p style='color: #60a5fa; font-weight: bold;'>--- HAVE I BEEN PWNED k-ANONYMITY VERIFICATION ---</p>
        <p>
            • <b style='color: #cbd5e1;'>SHA-1 Prefix Sent to HIBP API:</b> <span style='color: #38bdf8; font-weight: bold;'>{prefix}</span> <span style='color: #94a3b8;'>(Only first 5 characters sent via HTTPS)</span><br/>
            • <b style='color: #cbd5e1;'>Local Suffix Checked (Client):</b> <span style='color: #ffffff;'>{masked_suffix}</span> <span style='color: #94a3b8;'>(Full suffix: {suffix})</span><br/>
            • <b style='color: #cbd5e1;'>Privacy Guarantee:</b> <span style='color: #34d399; font-weight: bold;'>The full password NEVER left this computer.</span><br/>
            • <b style='color: #cbd5e1;'>API Endpoint Queried:</b> <span style='color: #94a3b8;'>{breach_info.get('api_url')}</span><br/>
            • <b style='color: #cbd5e1;'>Hash Suffixes Returned:</b> <span style='color: #ffffff;'>{breach_info.get('total_suffixes'):,} hash candidates downloaded</span><br/>
            • <b style='color: #cbd5e1;'>Result:</b> {result_html}
        </p>
        {warning_block}
        """
        self.txt_breach.setHtml(html)

    def _render_entropy_tab(self, entropy_info: dict):
        length = entropy_info.get("length", 0)
        pool = entropy_info.get("pool_size", 0)
        bits = entropy_info.get("entropy_bits", 0.0)
        eff_bits = entropy_info.get("effective_entropy_bits", 0.0)
        combs = entropy_info.get("combinations", 0)
        comb_str = f"{combs:.2e}" if combs > 1_000_000 else f"{combs:,}"

        lower_chk = "<span style='color:#10b981;'>[✓] Present (26)</span>" if entropy_info.get("has_lower") else "<span style='color:#64748b;'>[ ] Missing</span>"
        upper_chk = "<span style='color:#10b981;'>[✓] Present (26)</span>" if entropy_info.get("has_upper") else "<span style='color:#64748b;'>[ ] Missing</span>"
        digit_chk = "<span style='color:#10b981;'>[✓] Present (10)</span>" if entropy_info.get("has_digit") else "<span style='color:#64748b;'>[ ] Missing</span>"
        sym_chk   = "<span style='color:#10b981;'>[✓] Present (33)</span>" if entropy_info.get("has_symbol") else "<span style='color:#64748b;'>[ ] Missing</span>"
        spc_chk   = "<span style='color:#10b981;'>[✓] Present (1)</span>"  if entropy_info.get("has_space") else "<span style='color:#64748b;'>[ ] None</span>"

        html_metrics = f"""
        <p style='line-height: 1.5;'>
        • <b style='color:#cbd5e1;'>Password Length:</b> <span style='color:#ffffff; font-weight:bold;'>{length} characters</span><br/>
        • <b style='color:#cbd5e1;'>Character Pool (R):</b> <span style='color:#ffffff; font-weight:bold;'>{pool} symbols</span><br/>
        • <b style='color:#cbd5e1;'>Keyspace Combinations:</b> <span style='color:#38bdf8;'>{comb_str}</span><br/>
        • <b style='color:#cbd5e1;'>Raw Entropy:</b> <span style='color:#34d399; font-weight:bold;'>{bits:.1f} bits</span><br/>
        • <b style='color:#cbd5e1;'>Effective Entropy:</b> <span style='color:#34d399; font-weight:bold;'>{eff_bits:.1f} bits</span><br/>
        </p>
        <p style='line-height: 1.4;'>
        <b style='color:#60a5fa;'>CHARACTER CLASS DISTRIBUTION:</b><br/>
        &nbsp;&nbsp;Lowercase (a-z): {lower_chk}<br/>
        &nbsp;&nbsp;Uppercase (A-Z): {upper_chk}<br/>
        &nbsp;&nbsp;Numeric (0-9):   {digit_chk}<br/>
        &nbsp;&nbsp;Symbols (!@#...): {sym_chk}<br/>
        &nbsp;&nbsp;Whitespace:      {spc_chk}<br/>
        </p>
        <p style='line-height: 1.4; color:#94a3b8;'>
        <b style='color:#cbd5e1;'>SECURITY BENCHMARK:</b><br/>
        &nbsp;&nbsp;&lt; 36 bits: Vulnerable to instant offline crack<br/>
        &nbsp;&nbsp;36-59 bits: Vulnerable to GPU rigs within days<br/>
        &nbsp;&nbsp;60-79 bits: High resistance against attacks<br/>
        &nbsp;&nbsp;80+ bits: Military grade / Quantum-resistant
        </p>
        """
        self.txt_entropy_metrics.setHtml(html_metrics)

        # Scenarios
        scenarios_html = "<div style='line-height: 1.5;'>"
        for item in entropy_info.get("crack_times", []):
            sec = item["seconds"]
            if sec < 3600:
                color = "#ef4444"
            elif sec < 86400 * 365:
                color = "#f59e0b"
            else:
                color = "#10b981"

            scenarios_html += f"""
            <div style='margin-bottom: 8px;'>
                <b style='color:#ffffff;'>▸ {item['name']}</b><br/>
                &nbsp;&nbsp;Crack Time: <span style='color:{color}; font-weight:bold;'>{item['human_readable']}</span><br/>
                &nbsp;&nbsp;<span style='color:#94a3b8; font-size:10px;'>{item['description']}</span>
            </div>
            """
        scenarios_html += "</div>"
        self.txt_crack_times.setHtml(scenarios_html)

    def _render_patterns_tab(self, patterns: list, password: str):
        if not password:
            self.txt_patterns.setHtml("<p style='color:#94a3b8;'>Enter a password to inspect for pattern weaknesses.</p>")
            return

        if not patterns:
            html = """
            <h3 style='color:#10b981; margin-top:0;'>✅ No Common Patterns or Structural Weaknesses Detected!</h3>
            <p style='color:#e2e8f0; line-height: 1.6;'>
            • No sequential numbers or letters (e.g. '1234', 'abc').<br/>
            • No repetitive character clusters (e.g. 'aaa').<br/>
            • No keyboard walk paths (e.g. 'qwerty', '1qaz').<br/>
            • No common dictionary words or predictable leetspeak substitutions.<br/>
            • No birth/event year patterns.<br/>
            </p>
            <p style='color:#94a3b8;'>The password exhibits strong pseudorandom character entropy distribution.</p>
            """
            self.txt_patterns.setHtml(html)
            return

        html = f"<h4 style='color:#ffffff; margin-top:0;'>DETECTED {len(patterns)} PATTERN WEAKNESSES:</h4>"
        for p in patterns:
            sev = p["severity"]
            if sev == "CRITICAL":
                badge = "<span style='background-color:#7f1d1d; color:#fca5a5; padding:2px 6px; border-radius:3px; font-weight:bold;'>CRITICAL</span>"
            elif sev == "HIGH":
                badge = "<span style='background-color:#7c2d12; color:#fdba74; padding:2px 6px; border-radius:3px; font-weight:bold;'>HIGH</span>"
            else:
                badge = "<span style='background-color:#713f12; color:#fde047; padding:2px 6px; border-radius:3px; font-weight:bold;'>MEDIUM</span>"

            html += f"""
            <div style='margin-bottom: 12px; padding: 8px; background-color: #121524; border: 1px solid #242a44; border-radius: 4px;'>
                {badge} <b style='color:#ffffff; font-size:12px;'>{p['name']}</b>
                <span style='color:#f87171; font-weight:bold;'>(Penalty: -{p['penalty']} pts)</span><br/>
                <span style='color:#38bdf8;'>Match:</span> <code style='color:#f1f5f9;'>"{p['match']}"</code><br/>
                <span style='color:#cbd5e1;'>Details:</span> <span style='color:#94a3b8;'>{p['description']}</span>
            </div>
            """
        self.txt_patterns.setHtml(html)

    def _render_recom_tab(self, recommendations: list):
        html = "<div style='line-height: 1.6;'>"
        for rec in recommendations:
            if "CRITICAL" in rec or "🚨" in rec:
                html += f"<div style='color:#fca5a5; margin-bottom:8px; font-weight:bold;'>{rec}</div>"
            else:
                html += f"<div style='color:#e2e8f0; margin-bottom:8px;'>{rec}</div>"
        html += "</div>"
        self.txt_recom.setHtml(html)

    # --------------------------------------------------------------------------
    # Helper Actions & Generator
    # --------------------------------------------------------------------------
    def toggle_show_password(self, checked: bool):
        if checked:
            self.pwd_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.pwd_input.setEchoMode(QLineEdit.EchoMode.Password)

    def quick_generate(self):
        pwd = generate_random_password(length=18, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
        self.pwd_input.setText(pwd)
        self._show_toast("🎲 Generated new 18-char strong password!")
        self.run_audit()

    def generate_in_tab(self):
        if self.rb_diceware.isChecked():
            pwd = generate_diceware_passphrase(num_words=4, separator="-", capitalize=True, include_number=True)
        else:
            pwd = generate_random_password(length=18, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
        self.gen_input.setText(pwd)

    def use_generated_in_auditor(self):
        pwd = self.gen_input.text()
        if pwd:
            self.pwd_input.setText(pwd)
            self._show_toast("⚡ Inserted into auditor!")
            self.run_audit()

    def copy_generated(self):
        pwd = self.gen_input.text()
        if pwd:
            QApplication.clipboard().setText(pwd)
            self._show_toast("📋 Password copied to clipboard!")

    def copy_breach_report(self):
        text = self.txt_breach.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self._show_toast("📋 Breach report copied to clipboard!")

    def _show_toast(self, message: str):
        """Displays non-intrusive clean green confirmation toast in the UI."""
        self.lbl_toast.setText(message)
        # Fade or clear after 3.5 seconds
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(3500, lambda: self.lbl_toast.setText(""))

    def show_kanonymity_dialog(self):
        """Opens custom dark modal dialog with perfectly visible high-contrast text."""
        dlg = KAnonymityDialog(self)
        dlg.exec()


def main():
    app = QApplication(sys.argv)
    window = PasswordAuditorWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
