"""DICOM Secure — Sunucu GUI (PyQt5).

Tasarim: koyu petrol/teal tibbi guvenlik temas. Sol sutunda oturum listesi ve
AI analiz paneli (onizlemeli, guven skoru gosterimli), sagda canli log.
"""

# ONEMLI: torch, PyQt5'ten ONCE ice aktarilmali (Windows DLL cakismasi,
# WinError 1114). Bu nedenle server_core en ustte.
import server_core as core

import csv
import io
import os
import re
import shutil
import sys
from datetime import datetime

from PyQt5.QtCore import Qt, QObject, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QImage, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QFrame,
    QGridLayout, QHBoxLayout, QLabel, QMainWindow, QProgressBar, QPushButton,
    QScrollArea, QSpinBox, QTextEdit, QVBoxLayout, QWidget,
)

# ------------------------------------------------------------------
# Tema (istemci ile ayni dil)
# ------------------------------------------------------------------

BG = "#0E171B"
SURFACE = "#142227"
SURFACE2 = "#1B2E35"
BORDER = "#24404A"
ACCENT = "#35C9B0"
ACCENT_DIM = "#1F6E63"
TEXT = "#DCE9EA"
MUTED = "#7FA0A6"
OK = "#4ADE80"
ERR = "#F87171"
WARN = "#FBBF24"
INFO = "#5BB8D4"

THEME = f"""
QWidget {{ background-color: {BG}; color: {TEXT}; font-family: 'Segoe UI'; font-size: 10pt; }}
QLabel#titleLabel {{ font-size: 15pt; font-weight: 600; color: {ACCENT}; }}
QLabel#subtitleLabel {{ color: {MUTED}; font-size: 9pt; }}
QLabel#sectionLabel {{ color: {MUTED}; font-size: 8pt; font-weight: 600;
    letter-spacing: 1px; text-transform: uppercase; }}
QLabel#statValue {{ font-size: 13pt; font-weight: 600; color: {TEXT}; }}
QLabel#statKey {{ color: {MUTED}; font-size: 8pt; }}
QFrame#card {{ background-color: {SURFACE}; border: 1px solid {BORDER}; border-radius: 10px; }}
QFrame#chip {{ background-color: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 11px; }}
QLabel#chipText {{ color: {MUTED}; font-size: 9pt; padding: 2px 6px; }}
QPushButton#primary {{
    background-color: {ACCENT}; color: #06231F; font-weight: 600; font-size: 10.5pt;
    border: none; border-radius: 8px; padding: 10px 16px;
}}
QPushButton#primary:hover {{ background-color: #4ADCC2; }}
QPushButton#primary:disabled {{ background-color: {ACCENT_DIM}; color: #0B3A34; }}
QPushButton#ghost {{
    background-color: transparent; color: {MUTED}; border: 1px solid {BORDER};
    border-radius: 8px; padding: 6px 12px;
}}
QPushButton#ghost:hover {{ color: {TEXT}; border-color: {ACCENT_DIM}; }}
QSpinBox {{ background-color: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 6px;
    padding: 6px 8px; }}
QCheckBox {{ color: {MUTED}; spacing: 7px; }}
QCheckBox::indicator {{
    width: 15px; height: 15px; border: 1px solid {BORDER}; border-radius: 4px;
    background: {SURFACE2};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QTextEdit#logView {{
    background-color: {BG}; border: 1px solid {BORDER}; border-radius: 8px;
    font-family: 'Consolas'; font-size: 9pt; color: {TEXT}; padding: 6px;
}}
QScrollArea {{ border: none; background: transparent; }}
QDialog {{ background-color: {SURFACE}; }}
QToolTip {{ background-color: {SURFACE2}; color: {TEXT}; border: 1px solid {BORDER}; }}
"""


def chip_style(bg, fg):
    return f"QFrame#chip {{ background-color: {bg}; border: 1px solid {fg}; border-radius: 11px; }}" \
           f"QLabel#chipText {{ color: {fg}; font-size: 9pt; padding: 2px 6px; }}"


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024


# ------------------------------------------------------------------
# Olay koprusu: sunucu thread'leri -> GUI thread
# ------------------------------------------------------------------

class ServerEventBridge(QObject):
    event = pyqtSignal(str, dict)


# ------------------------------------------------------------------
# AI analiz thread'i
# ------------------------------------------------------------------

class AnalysisWorker(QThread):
    row_signal = pyqtSignal(str, bool, float, bytes)   # dosya, tumor, guven, png
    log_signal = pyqtSignal(str, str)
    done_signal = pyqtSignal(bool, dict)

    def __init__(self, analyzer, session_dir, cfg, parent=None):
        super().__init__(parent)
        self.analyzer = analyzer
        self.session_dir = session_dir
        self.cfg = cfg

    def log(self, msg, color=TEXT):
        self.log_signal.emit(msg, color)

    def run(self):
        files = sorted(f for f in os.listdir(self.session_dir) if f.endswith(".dcm"))
        if not files:
            self.done_signal.emit(False, {"error": "Klasorde .dcm dosyasi yok"})
            return

        timestamp = os.path.basename(self.session_dir.rstrip("/\\"))
        results = []
        self.log(f"AI analizi basliyor: {len(files)} goruntu ({timestamp})", INFO)

        for f in files:
            path = os.path.join(self.session_dir, f)
            try:
                image = core.dicom_to_pil(path)
                tumor, confidence = self.analyzer.predict_image(image)
            except Exception as exc:
                self.log(f"{f}: analiz hatasi ({exc})", ERR)
                continue

            # sinif bilincinde renk onizleme
            label = "TUMOR" if tumor else "TEMIZ"
            thumb = self._thumbnail(image)
            self.row_signal.emit(f, tumor, confidence, thumb)
            results.append({"file": f, "tumor": tumor, "confidence": confidence})
            self.log(f"{f} → {label} (guven %{confidence * 100:.1f})",
                     ERR if tumor else OK)

        if not results:
            self.done_signal.emit(False, {"error": "Hicbir goruntu analiz edilemedi"})
            return

        tumor_any = any(r["tumor"] for r in results)
        report_dir = core.resolve_path(self.cfg["reports_folder"])
        os.makedirs(report_dir, exist_ok=True)
        csv_path = os.path.join(report_dir, f"{timestamp}_analiz.csv")
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as fobj:
                writer = csv.writer(fobj)
                writer.writerow(["dosya", "tumor", "guven"])
                for r in results:
                    writer.writerow([r["file"], "VAR" if r["tumor"] else "YOK",
                                     f"{r['confidence']:.4f}"])
        except OSError as exc:
            self.log(f"Rapor yazilamadi: {exc}", WARN)

        # oturumu tumor/tumorsuz klasorune kopyala (eski davranis korunuyor)
        dest_root = core.resolve_path(
            self.cfg["tumor_folder"] if tumor_any else self.cfg["notumor_folder"])
        dest = os.path.join(dest_root, timestamp)
        if not os.path.exists(dest):
            try:
                shutil.copytree(self.session_dir, dest)
            except OSError as exc:
                self.log(f"Klasor kopyalanamadi: {exc}", WARN)

        self.done_signal.emit(True, {
            "timestamp": timestamp, "results": results, "csv": csv_path,
            "tumor_any": tumor_any, "copied_to": dest,
        })

    @staticmethod
    def _thumbnail(image, max_px=72):
        img = image.copy()
        img.thumbnail((max_px, max_px))
        buf = io.BytesIO()
        img.save(buf, "PNG")
        return buf.getvalue()


# ------------------------------------------------------------------
# Ayarlar
# ------------------------------------------------------------------

class ServerSettingsDialog(QDialog):
    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sunucu Ayarları")
        self.setMinimumWidth(360)
        self.cfg = dict(cfg)

        layout = QVBoxLayout(self)
        title = QLabel("Dinleme Ayarları")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        grid = QGridLayout()
        grid.addWidget(QLabel("Port:"), 0, 0)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(int(cfg["listen_port"]))
        grid.addWidget(self.port_spin, 0, 1)
        layout.addLayout(grid)

        self.tls_check = QCheckBox("TLS kullan (sertifika gerekli)")
        self.tls_check.setChecked(bool(cfg.get("tls_enabled", True)))
        layout.addWidget(self.tls_check)

        note = QLabel("Sertifikalar: tools/generate_certs.py ile uretilir\n"
                      f"({core.resolve_path(cfg['cert_path'])})")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {MUTED}; font-size: 8.5pt;")
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_config(self):
        cfg = dict(self.cfg)
        cfg["listen_port"] = self.port_spin.value()
        cfg["tls_enabled"] = self.tls_check.isChecked()
        return cfg


# ------------------------------------------------------------------
# Ana pencere
# ------------------------------------------------------------------

class ServerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = core.load_config()
        self.analyzer = None
        self.worker = None
        self._init_ui()
        self._start_server()
        self._load_model()

    # --- arayuz ---
    def _init_ui(self):
        self.setWindowTitle("DICOM Secure — Sunucu")
        self.resize(1000, 640)

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(14)

        left = QVBoxLayout()
        left.addWidget(self._build_header())
        left.addWidget(self._build_sessions_card())
        left.addWidget(self._build_analysis_card(), 1)
        root.addLayout(left, 1)

        right = QVBoxLayout()
        right.addWidget(self._build_log_card())
        root.addLayout(right, 1)

        self.setCentralWidget(central)

    def _build_header(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QHBoxLayout(card)
        lay.setContentsMargins(16, 12, 16, 12)

        col = QVBoxLayout()
        title = QLabel("DICOM Secure — Sunucu")
        title.setObjectName("titleLabel")
        self.subtitle = QLabel("dinleme bekleniyor…")
        self.subtitle.setObjectName("subtitleLabel")
        col.addWidget(title)
        col.addWidget(self.subtitle)
        lay.addLayout(col)
        lay.addStretch()

        settings_btn = QPushButton("Ayarlar")
        settings_btn.setObjectName("ghost")
        settings_btn.clicked.connect(self._open_settings)
        lay.addWidget(settings_btn)

        self.chip = QFrame()
        self.chip.setObjectName("chip")
        chip_lay = QHBoxLayout(self.chip)
        chip_lay.setContentsMargins(10, 4, 10, 4)
        self.chip_text = QLabel("başlatılıyor")
        self.chip_text.setObjectName("chipText")
        chip_lay.addWidget(self.chip_text)
        lay.addWidget(self.chip)
        return card

    def _build_sessions_card(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        head = QHBoxLayout()
        section = QLabel("SON OTURUMLAR")
        section.setObjectName("sectionLabel")
        head.addWidget(section)
        head.addStretch()
        refresh_btn = QPushButton("Yenile")
        refresh_btn.setObjectName("ghost")
        refresh_btn.clicked.connect(self._refresh_sessions)
        head.addWidget(refresh_btn)
        lay.addLayout(head)

        self.sessions_area = QScrollArea()
        self.sessions_area.setWidgetResizable(True)
        self.sessions_area.setFixedHeight(120)
        inner = QWidget()
        self.sessions_layout = QVBoxLayout(inner)
        self.sessions_layout.setContentsMargins(0, 0, 0, 0)
        self.sessions_layout.setSpacing(6)
        self.sessions_layout.addStretch()
        self.sessions_area.setWidget(inner)
        lay.addWidget(self.sessions_area)
        return card

    def _build_analysis_card(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        head = QHBoxLayout()
        section = QLabel("AI TÜMÖR TESPİTİ")
        section.setObjectName("sectionLabel")
        head.addWidget(section)
        head.addStretch()
        self.model_label = QLabel("model yükleniyor…")
        self.model_label.setObjectName("subtitleLabel")
        head.addWidget(self.model_label)
        lay.addLayout(head)

        self.analyze_button = QPushButton("Son Oturumu Analiz Et")
        self.analyze_button.setObjectName("primary")
        self.analyze_button.clicked.connect(self.start_analysis)
        lay.addWidget(self.analyze_button)

        self.analysis_summary = QLabel("Henüz analiz yapılmadı.")
        self.analysis_summary.setObjectName("subtitleLabel")
        lay.addWidget(self.analysis_summary)

        self.results_area = QScrollArea()
        self.results_area.setWidgetResizable(True)
        inner = QWidget()
        self.results_layout = QVBoxLayout(inner)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(6)
        self.results_layout.addStretch()
        self.results_area.setWidget(inner)
        lay.addWidget(self.results_area, 1)
        return card

    def _build_log_card(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        section = QLabel("SUNUCU GÜNLÜĞÜ")
        section.setObjectName("sectionLabel")
        lay.addWidget(section)

        self.log_view = QTextEdit()
        self.log_view.setObjectName("logView")
        self.log_view.setReadOnly(True)
        lay.addWidget(self.log_view, 1)
        return card

    # --- sunucu baslatma ---
    def _start_server(self):
        for folder in ("encrypted_folder", "decrypted_folder", "tumor_folder",
                       "notumor_folder", "temp_folder", "reports_folder"):
            os.makedirs(core.resolve_path(self.cfg[folder]), exist_ok=True)

        self.bridge = ServerEventBridge()
        self.bridge.event.connect(self._on_server_event)

        self.server = core.SessionServer(self.cfg, on_event=self._emit_event)
        self.server.start()
        self._refresh_sessions()

        tls_txt = "TLS aktif" if self.cfg.get("tls_enabled", True) else "TLS KAPALI"
        self.subtitle.setText(
            f"dinleme: {self.cfg['listen_ip']}:{self.cfg['listen_port']} · {tls_txt}")

    def _emit_event(self, kind, payload):
        self.bridge.event.emit(kind, payload)

    def _load_model(self):
        model_path = core.resolve_path(self.cfg["model_path"])
        try:
            self.analyzer = core.AIAnalyzer(model_path)
            self.model_label.setText("model hazır (CPU)")
            self.analyze_button.setEnabled(True)
        except Exception as exc:
            self.analyzer = None
            self.model_label.setText(f"model yüklenemedi: {exc}")
            self.analyze_button.setEnabled(False)
            self._append_log(f"Model yuklenemedi: {exc}", ERR)

    # --- olaylar ---
    def _append_log(self, message, color=TEXT):
        self.log_view.setTextColor(QColor(color))
        self.log_view.append(message)
        self.log_view.setTextColor(QColor(TEXT))

    def _on_server_event(self, kind, payload):
        message = payload.get("message")
        data = payload.get("data", {})
        if kind == "log" and message:
            self._append_log(message)
        elif kind == "fatal" and message:
            self._append_log(f"ÖLÜMCÜL: {message}", ERR)
            self.chip.setStyleSheet(chip_style(SURFACE2, ERR))
            self.chip_text.setText("hata")
        elif kind == "file" and message:
            self._append_log(message, MUTED)
        elif kind == "decrypted" and message:
            self._append_log(message, OK)
        elif kind == "decrypt_failed" and message:
            self._append_log(message, ERR)
        elif kind == "session_done":
            summary = data
            self._append_log(
                f"OTURUM BİTTİ: {summary['decrypted']} çözüldü, "
                f"{summary['failed']} başarısız ({summary['received_files']} dosya, "
                f"{fmt_bytes(summary['received_bytes'])}).", INFO)
            self._refresh_sessions()

    def _refresh_sessions(self):
        while self.sessions_layout.count() > 1:
            item = self.sessions_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        sessions = self._list_sessions("encrypted_folder")
        enc_root = core.resolve_path(self.cfg["encrypted_folder"])
        for name in sessions[-8:][::-1]:
            path = os.path.join(enc_root, name)
            n_dcm = len([f for f in os.listdir(path) if f.endswith(".dcm")])
            region = ""
            meta_path = os.path.join(path, "session_meta.json")
            if os.path.exists(meta_path):
                try:
                    import json
                    with open(meta_path, "r", encoding="utf-8") as mf:
                        region = json.load(mf).get("region", "")
                except (OSError, ValueError):
                    pass
            row = QWidget()
            h = QHBoxLayout(row)
            h.setContentsMargins(8, 6, 8, 6)
            h.setSpacing(10)
            row.setStyleSheet(f"background: {SURFACE2}; border-radius: 8px;")
            t = QLabel(name)
            r = QLabel(region or "—")
            c = QLabel(f"{n_dcm} dosya")
            for lbl, wdt in ((t, 1), (r, 0), (c, 0)):
                lbl.setObjectName("subtitleLabel")
                h.addWidget(lbl, wdt)
            self.sessions_layout.insertWidget(self.sessions_layout.count() - 1, row)

    def _open_settings(self):
        dialog = ServerSettingsDialog(self.cfg, self)
        if dialog.exec_() == QDialog.Accepted:
            self.cfg = dialog.get_config()
            core.save_config(self.cfg)
            self.server.cfg = self.cfg
            self.subtitle.setText(
                f"dinleme: {self.cfg['listen_ip']}:{self.cfg['listen_port']} · "
                f"{'TLS aktif' if self.cfg.get('tls_enabled', True) else 'TLS KAPALI'}")
            self._append_log(
                "Ayarlar kaydedildi. Port degistiyseniz yeniden baslatin.", WARN)

    # --- AI analiz ---
    def _list_sessions(self, root_cfg_key):
        """Zaman damgali oturum klasorlerini gercek tarihe gore sirali dondurur."""
        root = core.resolve_path(self.cfg[root_cfg_key])
        pattern = re.compile(r"^\d{2}_\d{2}_\d{2}_\d{2}_\d{2}_\d{4}$")
        sessions = [
            d for d in os.listdir(root)
            if pattern.match(d) and os.path.isdir(os.path.join(root, d))
        ]
        # Format HH_MM_SS_DD_MM_YYYY: alfabetik siralama yanlis siralar,
        # gercek tarihe gore sirala.
        sessions.sort(key=lambda d: datetime.strptime(d, core.TIMESTAMP_FMT))
        return sessions

    def start_analysis(self):
        if self.worker and self.worker.isRunning():
            return
        if self.analyzer is None:
            self._append_log("Model yuklu olmadigi icin analiz baslatilamaz.", ERR)
            return

        sessions = self._list_sessions("decrypted_folder")
        if not sessions:
            self._append_log("Analiz edilecek cozulmus oturum yok.", WARN)
            return

        latest = os.path.join(core.resolve_path(self.cfg["decrypted_folder"]), sessions[-1])
        self.analyze_button.setEnabled(False)
        self._clear_results()

        self.worker = AnalysisWorker(self.analyzer, latest, self.cfg)
        self.worker.log_signal.connect(self._append_log)
        self.worker.row_signal.connect(self._add_result_row)
        self.worker.done_signal.connect(self._on_analysis_done)
        self.worker.start()

    def _clear_results(self):
        while self.results_layout.count() > 1:
            item = self.results_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _add_result_row(self, file_name, tumor, confidence, png_bytes):
        row = QWidget()
        row.setStyleSheet(f"background: {SURFACE2}; border-radius: 8px;")
        h = QHBoxLayout(row)
        h.setContentsMargins(8, 6, 10, 6)
        h.setSpacing(12)

        pix = QLabel()
        img = QImage.fromData(png_bytes)
        pix.setPixmap(QPixmap.fromImage(img).scaled(
            72, 72, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        pix.setFixedSize(76, 76)
        pix.setAlignment(Qt.AlignCenter)
        pix.setStyleSheet(f"border: 1px solid {BORDER}; border-radius: 6px;")
        h.addWidget(pix)

        name = QLabel(file_name)
        name.setWordWrap(False)
        h.addWidget(name, 1)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(int(confidence * 100))
        bar.setFixedWidth(140)
        bar.setFormat(f"guven %p")
        h.addWidget(bar)

        chip = QLabel("TÜMÖR" if tumor else "TEMİZ")
        color = ERR if tumor else OK
        chip.setStyleSheet(
            f"background: {color}22; color: {color}; border: 1px solid {color};"
            f"border-radius: 10px; padding: 3px 10px; font-weight: 600;")
        h.addWidget(chip)

        self.results_layout.insertWidget(self.results_layout.count() - 1, row)

    def _on_analysis_done(self, ok, summary):
        self.analyze_button.setEnabled(True)
        if not ok:
            self.analysis_summary.setText(f"Analiz hatası: {summary.get('error')}")
            return
        n = len(summary["results"])
        tumor_n = sum(1 for r in summary["results"] if r["tumor"])
        verdict = "TÜMÖR TESPİT EDİLDİ" if summary["tumor_any"] else "TEMİZ"
        color = ERR if summary["tumor_any"] else OK
        self.analysis_summary.setText(
            f"{summary['timestamp']}: {n} görüntü, {tumor_n} tümörlü → "
            f"klasör: {os.path.basename(os.path.dirname(summary['copied_to']))}")
        self.analysis_summary.setStyleSheet(
            f"color: {color}; font-weight: 600; font-size: 11pt;")
        self._append_log(
            f"Analiz bitti: {verdict} · rapor: {summary['csv']}", color)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.wait(3000)
        self.server.stop()
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(THEME)
    window = ServerWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
