"""DICOM Secure — Istemci GUI (PyQt5).

Tasarim: koyu petrol/teal tibbi guvenlik temas; sol tarafta tarama formu,
sagda canli onizleme + ilerleme + renkli log.
"""

import os
import random
import sys
import time
from datetime import datetime

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QImage, QPixmap
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QDoubleSpinBox, QFormLayout, QFrame, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QProgressBar, QPushButton,
    QScrollArea, QSpinBox, QTextEdit, QVBoxLayout, QWidget,
)

import client_core as core

# ------------------------------------------------------------------
# Tema
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
QLabel#chipText {{ color: {MUTED}; font-size: 9pt; padding: 2px 4px; }}
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
QComboBox, QSpinBox, QDoubleSpinBox, QLineEdit {{
    background-color: {SURFACE2}; border: 1px solid {BORDER}; border-radius: 6px;
    padding: 6px 8px; selection-background-color: {ACCENT_DIM};
}}
QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover {{ border-color: {ACCENT_DIM}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QCheckBox {{ color: {MUTED}; spacing: 7px; }}
QCheckBox::indicator {{
    width: 15px; height: 15px; border: 1px solid {BORDER}; border-radius: 4px;
    background: {SURFACE2};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QProgressBar {{
    background-color: {SURFACE2}; border: none; border-radius: 6px; height: 12px;
    text-align: center; color: transparent; font-size: 8pt;
}}
QProgressBar::chunk {{ background-color: {ACCENT}; border-radius: 6px; }}
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


# ------------------------------------------------------------------
# Calisan thread: sifreleme + gonderim
# ------------------------------------------------------------------

class ScanWorker(QThread):
    stage_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int, int, int)   # bitti, toplam, gonderilen_bayt, toplam_bayt
    thumb_signal = pyqtSignal(str, bytes)              # dosya adi, png baytlari
    log_signal = pyqtSignal(str, str)                  # mesaj, renk hex
    stats_signal = pyqtSignal(dict)
    done_signal = pyqtSignal(bool, dict)

    def __init__(self, selected_files, settings, meta):
        super().__init__()
        self.files = selected_files
        self.cfg = settings
        self.meta = meta
        self.session_folder = None

    def log(self, message, color=TEXT):
        self.log_signal.emit(message, color)

    def run(self):
        started = time.perf_counter()
        session_id = datetime.now().strftime("%H_%M_%S_%d_%m_%Y")
        encrypted_root = os.path.join(core.BASE_DIR, self.cfg["encrypted_folder"])
        self.session_folder = os.path.join(encrypted_root, session_id)
        os.makedirs(self.session_folder, exist_ok=True)

        try:
            self.log("Anahtar uretiliyor (Lorenz + donanim entropisi)...", INFO)
            master_key = core.derive_master_key(session_id)
        except Exception as exc:
            self.done_signal.emit(False, {"error": f"Anahtar uretimi basarisiz: {exc}"})
            return
        self.log("Oturum anahtari hazir.", OK)

        total = len(self.files)
        total_bytes = 0
        enc_ok, enc_fail = 0, 0
        stage_label = "Sifreleme"

        self.stage_signal.emit("Şifreleme")
        for idx, src_name in enumerate(self.files):
            src = os.path.join(core.BASE_DIR, self.cfg["dataset_path"], src_name)
            dst_name = f"slice{idx + 1:02d}_encrypted.dcm"
            dst = os.path.join(self.session_folder, dst_name)
            ok, info = core.encrypt_dicom_file(
                src, dst, master_key, session_id,
                anonymize_flag=self.cfg.get("anonymize_metadata", True),
            )
            if ok:
                enc_ok += 1
                total_bytes += info["bytes"]
                self.log(f"{src_name} şifrelendi → {dst_name} "
                         f"({info['bytes']:,} bayt, {info['elapsed']:.2f} sn)", OK)
                try:
                    thumb = core.make_thumbnail(src, 120)
                    if thumb is not None:
                        import io
                        buf = io.BytesIO()
                        thumb.save(buf, "PNG")
                        self.thumb_signal.emit(dst_name, buf.getvalue())
                except Exception:
                    pass
            else:
                enc_fail += 1
                self.log(f"Hata: {info.get('error', 'bilinmeyen')}", ERR)
            self.progress_signal.emit(idx + 1, total * 2, total_bytes, 0)

        if enc_ok == 0:
            self.done_signal.emit(False, {"error": "Hicbir dosya sifrelenemedi"})
            return

        # --- gonderim ---
        self.stage_signal.emit("Gönderim")
        self.log(f"Sunucuya baglaniliyor: {self.cfg['server_ip']}:{self.cfg['server_port']} "
                 f"({'TLS' if self.cfg.get('tls_enabled') else 'TLS KAPALI!'})", INFO)

        def on_transfer_progress(idx, total_files, sent, total_bytes):
            self.progress_signal.emit(idx + total, total_files * 2, sent, total_bytes)

        ok, summary = core.send_session(self.session_folder, self.meta, self.cfg,
                                        log=lambda msg: self.log(msg, TEXT),
                                        progress=on_transfer_progress)
        if not ok:
            self.done_signal.emit(False, {
                "error": summary.get("error", "Gonderim basarisiz"),
                "session_folder": self.session_folder,
                "encrypted": enc_ok, "failed": enc_fail,
            })
            return

        elapsed = time.perf_counter() - started
        self.stats_signal.emit({
            "files": enc_ok, "bytes": total_bytes, "elapsed": elapsed,
            "throughput": summary.get("throughput", 0),
        })
        self.log(f"OTURUM TAMAM: {enc_ok} dosya şifrelendi, gönderildi ve sunucu tarafından "
                 f"onaylandı. Toplam {elapsed:.2f} sn.", OK)
        if enc_fail:
            self.log(f"Dikkat: {enc_fail} dosya sifrelenemedi.", WARN)
        self.done_signal.emit(True, {
            "session_folder": self.session_folder,
            "encrypted": enc_ok, "failed": enc_fail,
            "transfer": summary, "elapsed": elapsed,
        })


# ------------------------------------------------------------------
# Ayarlar penceresi
# ------------------------------------------------------------------

class SettingsDialog(QDialog):
    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.cfg = dict(cfg)
        self.setWindowTitle("Bağlantı Ayarları")
        self.setMinimumWidth(380)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel("Sunucu Bağlantısı")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(8)
        self.ip_edit = QLineEdit(self.cfg["server_ip"])
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1024, 65535)
        self.port_spin.setValue(int(self.cfg["server_port"]))
        self.ca_edit = QLineEdit(self.cfg.get("tls_ca_path", ""))
        form.addRow("Sunucu IP:", self.ip_edit)
        form.addRow("Port:", self.port_spin)
        form.addRow("CA sertifikası:", self.ca_edit)
        layout.addLayout(form)

        self.tls_check = QCheckBox("TLS ile bağlan (önerilen)")
        self.tls_check.setChecked(bool(self.cfg.get("tls_enabled", True)))
        layout.addWidget(self.tls_check)

        self.anon_check = QCheckBox("Hasta kimlik verilerini şifrelemeden önce temizle")
        self.anon_check.setChecked(bool(self.cfg.get("anonymize_metadata", True)))
        layout.addWidget(self.anon_check)

        note = QLabel("CA yolu boşsa ../certs/ca.pem varsayılanı kullanılır.\n"
                      "Sertifikaları üretmek için: tools/generate_certs.py")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {MUTED}; font-size: 8.5pt;")
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_config(self):
        cfg = dict(self.cfg)
        cfg["server_ip"] = self.ip_edit.text().strip() or "127.0.0.1"
        cfg["server_port"] = self.port_spin.value()
        cfg["tls_enabled"] = self.tls_check.isChecked()
        cfg["tls_ca_path"] = self.ca_edit.text().strip()
        cfg["anonymize_metadata"] = self.anon_check.isChecked()
        return cfg


# ------------------------------------------------------------------
# Ana pencere
# ------------------------------------------------------------------

class ClientWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = core.load_config()
        self.worker = None
        self._init_ui()
        self._set_status("hazır", MUTED, BG)

    # --- arayuz kurulumu ---
    def _init_ui(self):
        self.setWindowTitle("DICOM Secure — İstemci")
        self.resize(940, 620)

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(14)

        # --- sol sutun: tarama formu ---
        left = QVBoxLayout()
        left.addWidget(self._build_header())
        left.addSpacing(6)
        left.addWidget(self._build_scan_card(), 1)
        root.addLayout(left, 0)

        # --- sag sutun: onizleme + durum + log ---
        right = QVBoxLayout()
        right.addWidget(self._build_preview_card())
        right.addWidget(self._build_status_card())
        right.addWidget(self._build_log_card(), 1)
        root.addLayout(right, 1)

        self.setCentralWidget(central)

    def _build_header(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QHBoxLayout(card)
        lay.setContentsMargins(16, 12, 16, 12)

        text_col = QVBoxLayout()
        title = QLabel("DICOM Secure — İstemci")
        title.setObjectName("titleLabel")
        subtitle = QLabel("MR tarama simülasyonu · Lorenz + ChaCha20-Poly1305 · TLS aktarım")
        subtitle.setObjectName("subtitleLabel")
        text_col.addWidget(title)
        text_col.addWidget(subtitle)
        lay.addLayout(text_col)
        lay.addStretch()

        settings_btn = QPushButton("Ayarlar")
        settings_btn.setObjectName("ghost")
        settings_btn.clicked.connect(self._open_settings)
        lay.addWidget(settings_btn)

        self.chip = QFrame()
        self.chip.setObjectName("chip")
        chip_lay = QHBoxLayout(self.chip)
        chip_lay.setContentsMargins(10, 4, 10, 4)
        self.chip_text = QLabel("hazır")
        self.chip_text.setObjectName("chipText")
        chip_lay.addWidget(self.chip_text)
        lay.addWidget(self.chip)
        return card

    def _build_scan_card(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(16, 14, 16, 16)
        lay.setSpacing(10)

        section = QLabel("MR TARAMA SİMÜLASYONU")
        section.setObjectName("sectionLabel")
        lay.addWidget(section)

        form = QFormLayout()
        form.setSpacing(9)

        self.region_combo = QComboBox()
        self.region_combo.addItems(["Beyin", "Diz", "Omuz", "Bel", "Karın", "Pelvis"])
        self.sequence_combo = QComboBox()
        self.sequence_combo.addItems(["T1-weighted", "T2-weighted", "FLAIR"])
        self.slice_spin = QSpinBox()
        self.slice_spin.setRange(1, 10)
        self.slice_spin.setValue(5)
        self.thickness_spin = QDoubleSpinBox()
        self.thickness_spin.setRange(0.5, 10.0)
        self.thickness_spin.setSingleStep(0.5)
        self.thickness_spin.setValue(5.0)

        form.addRow("Anatomik bölge", self.region_combo)
        form.addRow("Sekans türü", self.sequence_combo)
        form.addRow("Görüntü (slice) sayısı", self.slice_spin)
        form.addRow("Slice kalınlığı (mm)", self.thickness_spin)
        lay.addLayout(form)

        self.anon_check = QCheckBox("Hasta kimlik verilerini temizle (anonimleştir)")
        self.anon_check.setChecked(bool(self.cfg.get("anonymize_metadata", True)))
        lay.addWidget(self.anon_check)

        lay.addStretch()

        self.start_button = QPushButton("Taramayı Başlat ve Gönder")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_scan)
        lay.addWidget(self.start_button)

        info = QLabel(f"Veri seti: {self.cfg['dataset_path']} · "
                      f"Sunucu: {self.cfg['server_ip']}:{self.cfg['server_port']}")
        info.setObjectName("subtitleLabel")
        info.setWordWrap(True)
        lay.addWidget(info)
        self.info_label = info
        return card

    def _build_preview_card(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        head = QHBoxLayout()
        section = QLabel("SEÇİLEN GÖRÜNTÜLER")
        section.setObjectName("sectionLabel")
        head.addWidget(section)
        head.addStretch()
        self.preview_count = QLabel("0")
        self.preview_count.setObjectName("subtitleLabel")
        head.addWidget(self.preview_count)
        lay.addLayout(head)

        self.preview_area = QScrollArea()
        self.preview_area.setWidgetResizable(True)
        self.preview_area.setFixedHeight(140)
        inner = QWidget()
        self.preview_layout = QHBoxLayout(inner)
        self.preview_layout.setContentsMargins(0, 0, 0, 0)
        self.preview_layout.setSpacing(8)
        self.preview_layout.addStretch()
        self.preview_area.setWidget(inner)
        lay.addWidget(self.preview_area)
        return card

    def _build_status_card(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        self.stage_label = QLabel("Kullanıcı bir tarama başlatmadı.")
        self.stage_label.setObjectName("subtitleLabel")
        lay.addWidget(self.stage_label)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setFormat("%p%")
        lay.addWidget(self.progress)

        stats = QGridLayout()
        stats.setSpacing(2)
        self.stat_files = self._stat(stats, 0, 0, "DOSYA")
        self.stat_bytes = self._stat(stats, 0, 1, "VERİ")
        self.stat_time = self._stat(stats, 0, 2, "SÜRE")
        self.stat_speed = self._stat(stats, 0, 3, "HIZ")
        lay.addLayout(stats)
        return card

    def _stat(self, grid, row, col, key):
        box = QVBoxLayout()
        val = QLabel("—")
        val.setObjectName("statValue")
        k = QLabel(key)
        k.setObjectName("statKey")
        box.addWidget(val)
        box.addWidget(k)
        holder = QWidget()
        holder.setLayout(box)
        grid.addWidget(holder, row, col)
        return val

    def _build_log_card(self):
        card = QFrame()
        card.setObjectName("card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        section = QLabel("İŞLEM GÜNLÜĞÜ")
        section.setObjectName("sectionLabel")
        lay.addWidget(section)

        self.log_view = QTextEdit()
        self.log_view.setObjectName("logView")
        self.log_view.setReadOnly(True)
        lay.addWidget(self.log_view)
        return card

    # --- yardimcilar ---
    def _set_status(self, text, fg, bg):
        self.chip.setStyleSheet(chip_style(bg, fg))
        self.chip_text.setText(text)

    def log_message(self, message, color=TEXT):
        self.log_view.setTextColor(QColor(color))
        self.log_view.append(message)
        self.log_view.setTextColor(QColor(TEXT))

    def _fmt_bytes(self, n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
            n /= 1024

    # --- olaylar ---
    def _open_settings(self):
        dialog = SettingsDialog(self.cfg, self)
        if dialog.exec_() == QDialog.Accepted:
            self.cfg = dialog.get_config()
            core.save_config(self.cfg)
            self.info_label.setText(
                f"Veri seti: {self.cfg['dataset_path']} · "
                f"Sunucu: {self.cfg['server_ip']}:{self.cfg['server_port']}")
            self.log_message("Ayarlar kaydedildi.", MUTED)

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return

        dataset_dir = os.path.join(core.BASE_DIR, self.cfg["dataset_path"])
        dicom_files = sorted(f for f in os.listdir(dataset_dir) if f.endswith(".dcm"))
        count = self.slice_spin.value()
        if len(dicom_files) < count:
            self.log_message(f"Hata: veri setinde yalnızca {len(dicom_files)} DICOM var, "
                             f"{count} istendi.", ERR)
            return

        selected = random.sample(dicom_files, count)
        meta = {
            "region": self.region_combo.currentText(),
            "sequence": self.sequence_combo.currentText(),
            "slice_count": count,
            "slice_thickness": self.thickness_spin.value(),
            "anonymized": self.anon_check.isChecked(),
        }

        # arayuzu sifirla
        self._clear_previews()
        self.preview_count.setText(str(count))
        self.progress.setValue(0)
        self.stat_files.setText("—")
        self.stat_bytes.setText("—")
        self.stat_time.setText("—")
        self.stat_speed.setText("—")
        self.start_button.setEnabled(False)
        self._set_status("çalışıyor", WARN, SURFACE2)
        self.cfg["anonymize_metadata"] = self.anon_check.isChecked()

        self.log_message(
            f"MR tarama başlatıldı — bölge: {meta['region']}, sekans: {meta['sequence']}, "
            f"slice: {count}, kalınlık: {meta['slice_thickness']:.1f} mm", INFO)

        self.worker = ScanWorker(selected, self.cfg, meta)
        self.worker.log_signal.connect(self.log_message)
        self.worker.stage_signal.connect(self.stage_label.setText)
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.thumb_signal.connect(self._add_thumbnail)
        self.worker.stats_signal.connect(self._on_stats)
        self.worker.done_signal.connect(self._on_done)
        self.worker.start()

    def _on_progress(self, done, total, sent_bytes, total_bytes):
        pct = int(done / max(total, 1) * 100)
        self.progress.setValue(pct)
        if sent_bytes:
            self.stage_label.setText(
                f"Gönderim — {self._fmt_bytes(sent_bytes)} / {self._fmt_bytes(total_bytes)}")

    def _on_stats(self, stats):
        self.stat_files.setText(str(stats["files"]))
        self.stat_bytes.setText(self._fmt_bytes(stats["bytes"]))
        self.stat_time.setText(f"{stats['elapsed']:.2f} sn")
        speed = stats.get("throughput", 0)
        self.stat_speed.setText(f"{self._fmt_bytes(speed)}/sn")

    def _clear_previews(self):
        while self.preview_layout.count() > 1:
            item = self.preview_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _add_thumbnail(self, file_name, png_bytes):
        holder = QWidget()
        col = QVBoxLayout(holder)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(4)
        img = QImage.fromData(png_bytes)
        pix = QPixmap.fromImage(img)
        label = QLabel()
        label.setPixmap(pix)
        label.setFixedSize(120, 96)
        label.setScaledContents(True)
        label.setStyleSheet(f"border: 1px solid {BORDER}; border-radius: 6px; "
                            f"background: {SURFACE2};")
        name = QLabel(file_name.replace("_encrypted.dcm", ""))
        name.setObjectName("subtitleLabel")
        name.setAlignment(Qt.AlignCenter)
        col.addWidget(label, 0, Qt.AlignHCenter)
        col.addWidget(name, 0, Qt.AlignHCenter)
        self.preview_layout.insertWidget(self.preview_layout.count() - 1, holder)

    def _on_done(self, ok, summary):
        self.start_button.setEnabled(True)
        if ok:
            self.progress.setValue(100)
            self.stage_label.setText("Tarama tamamlandı; sunucu dosyaları aldı ve çözdü.")
            self._set_status("tamamlandı", OK, SURFACE2)
            t = summary.get("transfer", {})
            self.log_message(
                f"Sunucu özeti: {t.get('server_result', {}).get('received', '?')} dosya alındı, "
                f"{t.get('server_result', {}).get('decrypted', '?')} çözüldü.", INFO)
        else:
            self.stage_label.setText(f"Hata: {summary.get('error', 'bilinmeyen')}")
            self._set_status("hata", ERR, SURFACE2)
            self.log_message(f"HATA: {summary.get('error', 'bilinmeyen')}", ERR)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.wait(3000)
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(THEME)
    window = ClientWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
