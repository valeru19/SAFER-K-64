"""Главное окно PySide6: шифрование, анализ, файлы."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from safer_k64.analysis.registry import AttackRegistry, default_registry
from safer_k64.domain.models import AnalysisResult, AttackContext
from safer_k64.gui.attack_charts import AttackComparisonWidget
from safer_k64.gui.hexutil import blocks_from_hex, normalize_hex
from safer_k64.gui.styles import APP_STYLESHEET
from safer_k64.services.cipher_service import SaferK64ApplicationService
from safer_k64.services.key_generator import KeyGeneratorService
from safer_k64.services.sample_text import SampleTextService
from safer_k64.services.text_codec import utf8_to_blocks


class _AttackWorker(QThread):
    finished_ok = Signal(object)

    def __init__(self, attack, ctx: AttackContext) -> None:
        super().__init__()
        self._attack = attack
        self._ctx = ctx

    def run(self) -> None:
        res = self._attack.run(self._ctx)
        self.finished_ok.emit(res)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SAFER K-64 — шифрование и криптоанализ")
        self.resize(1140, 820)

        self._cipher = SaferK64ApplicationService()
        self._keys = KeyGeneratorService()
        self._samples = SampleTextService()
        self._last_cipher_hex = ""
        self._registry: AttackRegistry = default_registry()
        self._attack_results: list[AnalysisResult] = []
        self._charts_fs_dlg: QDialog | None = None
        self._chart_panel_layout: QVBoxLayout | None = None
        self._chart_fullscreen_btn: QPushButton | None = None

        root = QWidget()
        self.setCentralWidget(root)
        lay = QHBoxLayout(root)
        lay.setContentsMargins(18, 18, 18, 18)
        lay.setSpacing(16)

        self._nav = QListWidget()
        self._nav.setObjectName("nav")
        self._nav.setMinimumWidth(120)
        self._nav.setMaximumWidth(560)
        for text in ("Шифрование", "Криптоанализ", "Файлы"):
            QListWidgetItem(text, self._nav)
        self._nav.setCurrentRow(0)
        self._nav.currentRowChanged.connect(self._on_nav)

        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_crypto_page())
        self._stack.addWidget(self._build_analysis_page())
        self._stack.addWidget(self._build_files_page())

        self._main_split = QSplitter(Qt.Horizontal)
        self._main_split.setHandleWidth(6)
        self._main_split.setChildrenCollapsible(False)
        self._main_split.addWidget(self._nav)
        self._main_split.addWidget(self._stack)
        self._main_split.setStretchFactor(0, 0)
        self._main_split.setStretchFactor(1, 1)
        self._main_split.setSizes([220, 900])
        lay.addWidget(self._main_split)

        self.setStyleSheet(APP_STYLESHEET)

        self._worker: _AttackWorker | None = None

    def _card(self) -> QFrame:
        f = QFrame()
        f.setObjectName("card")
        return f

    def _title(self, text: str) -> QLabel:
        lb = QLabel(text)
        lb.setObjectName("title")
        return lb

    def _subtitle(self, text: str) -> QLabel:
        lb = QLabel(text)
        lb.setObjectName("subtitle")
        lb.setWordWrap(True)
        return lb

    def _on_nav(self, idx: int) -> None:
        self._stack.setCurrentIndex(max(0, min(idx, self._stack.count() - 1)))

    def _build_crypto_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)

        card = self._card()
        outer.addWidget(card)
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(12, 12, 12, 12)
        card_lay.setSpacing(0)

        split_v = QSplitter(Qt.Vertical)
        split_v.setHandleWidth(6)
        split_v.setChildrenCollapsible(False)

        top = QWidget()
        v = QVBoxLayout(top)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(12)

        v.addWidget(self._title("Текст и ключ"))
        v.addWidget(
            self._subtitle(
                "Учебный блочный шифр: 8 байт на блок, UTF-8, дополнение PKCS#7. "
                "Ключ — 16 hex-символов (64 бита)."
            )
        )

        self.ed_plain = QTextEdit()
        self.ed_plain.setPlaceholderText("Введите открытый текст…")
        self.ed_plain.setMinimumHeight(100)

        row_key = QHBoxLayout()
        self.ed_key = QLineEdit()
        self.ed_key.setPlaceholderText("16 hex-символов, например: " + self._keys.random_key_hex())
        self.sp_rounds_crypto = QSpinBox()
        self.sp_rounds_crypto.setRange(1, 4)
        self.sp_rounds_crypto.setValue(4)
        row_key.addWidget(QLabel("Ключ (hex)"))
        row_key.addWidget(self.ed_key, 1)
        row_key.addWidget(QLabel("Раунды"))
        row_key.addWidget(self.sp_rounds_crypto)

        btn_row = QHBoxLayout()
        b_enc = QPushButton("Зашифровать")
        b_enc.clicked.connect(self._on_encrypt)
        b_dec = QPushButton("Расшифровать")
        b_dec.setObjectName("secondary")
        b_dec.clicked.connect(self._on_decrypt)
        b_rnd = QPushButton("Случайный ключ")
        b_rnd.setObjectName("secondary")
        b_rnd.clicked.connect(lambda: self.ed_key.setText(self._keys.random_key_hex()))
        b_weak = QPushButton("Слабый демо-ключ")
        b_weak.setObjectName("secondary")
        b_weak.setToolTip("Все 8 байт ключа одинаковы — перебор 256 вариантов найдёт ключ.")
        b_weak.clicked.connect(lambda: self.ed_key.setText(self._keys.uniform_byte_key_hex()))
        b_sample = QPushButton("Пример текста")
        b_sample.setObjectName("secondary")
        b_sample.clicked.connect(lambda: self.ed_plain.setPlainText(self._samples.random_sample()))
        btn_row.addWidget(b_enc)
        btn_row.addWidget(b_dec)
        btn_row.addWidget(b_rnd)
        btn_row.addWidget(b_weak)
        btn_row.addWidget(b_sample)

        v.addWidget(self.ed_plain, 1)
        v.addLayout(row_key)
        v.addLayout(btn_row)

        bottom = QWidget()
        vb = QVBoxLayout(bottom)
        vb.setContentsMargins(10, 10, 10, 10)
        vb.setSpacing(8)
        vb.addWidget(self._title("Шифротекст (hex)"))
        self.ed_cipher_hex = QTextEdit()
        self.ed_cipher_hex.setPlaceholderText("Здесь появится hex после шифрования…")
        self.ed_cipher_hex.setMinimumHeight(80)
        vb.addWidget(self.ed_cipher_hex, 1)

        split_v.addWidget(top)
        split_v.addWidget(bottom)
        split_v.setStretchFactor(0, 2)
        split_v.setStretchFactor(1, 1)
        split_v.setSizes([360, 220])

        card_lay.addWidget(split_v)
        return page

    def _build_analysis_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)

        card = self._card()
        outer.addWidget(card)
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(8, 8, 8, 8)
        card_lay.setSpacing(0)

        root_split = QSplitter(Qt.Vertical)
        root_split.setHandleWidth(8)
        root_split.setChildrenCollapsible(False)

        # --- Верх: только данные (компактно, с прокруткой при нехватке места) ---
        scroll = QScrollArea()
        scroll.setObjectName("analysisScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setMinimumHeight(180)
        scroll.setMaximumHeight(440)
        scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        scroll.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)

        input_panel = QWidget()
        input_panel.setObjectName("analysisInputPanel")
        input_panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        v_in = QVBoxLayout(input_panel)
        v_in.setContentsMargins(8, 8, 8, 8)
        v_in.setSpacing(8)

        v_in.addWidget(self._title("Криптоанализ без знания ключа"))
        v_in.addWidget(
            self._subtitle(
                "Текст и hex шифра — как на вкладке «Шифрование». Ниже: выбор атак слева, лог и графики справа "
                "(разделители можно двигать)."
            )
        )

        g = QGridLayout()
        self.ed_a_plain = QTextEdit()
        self.ed_a_plain.setPlaceholderText("Открытый текст (UTF-8)…")
        self.ed_a_plain.setMinimumHeight(64)
        self.ed_a_plain.setMaximumHeight(120)
        self.ed_a_cipher_hex = QTextEdit()
        self.ed_a_cipher_hex.setPlaceholderText("Шифротекст hex…")
        self.ed_a_cipher_hex.setMinimumHeight(52)
        self.ed_a_cipher_hex.setMaximumHeight(100)

        self.cb_pair = QCheckBox("Вторая пара для дифф. анализа (два блока P и C)")
        self.ed_p2_hex = QLineEdit()
        self.ed_p2_hex.setPlaceholderText("P2 — 16 hex (8 байт)")
        self.ed_c2_hex = QLineEdit()
        self.ed_c2_hex.setPlaceholderText("C2 — 16 hex (8 байт)")

        self.ed_oracle_key = QLineEdit()
        self.ed_oracle_key.setPlaceholderText("Ключ-оракул (16 hex) для интегрального / выбранного открытого текста")

        self.sp_rounds_a = QSpinBox()
        self.sp_rounds_a.setRange(1, 4)
        self.sp_rounds_a.setValue(4)
        self.sp_brute_max = QSpinBox()
        self.sp_brute_max.setRange(10_000, 10_000_000)
        self.sp_brute_max.setSingleStep(50_000)
        self.sp_brute_max.setValue(200_000)

        g.addWidget(QLabel("P (UTF-8)"), 0, 0)
        g.addWidget(self.ed_a_plain, 0, 1)
        g.addWidget(QLabel("C (hex)"), 1, 0)
        g.addWidget(self.ed_a_cipher_hex, 1, 1)
        v_in.addLayout(g)

        v_in.addWidget(self.cb_pair)
        row2 = QHBoxLayout()
        row2.addWidget(self.ed_p2_hex)
        row2.addWidget(self.ed_c2_hex)
        v_in.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Раунды"))
        row3.addWidget(self.sp_rounds_a)
        row3.addWidget(QLabel("Лимит перебора"))
        row3.addWidget(self.sp_brute_max)
        row3.addStretch()
        v_in.addLayout(row3)
        v_in.addWidget(QLabel("Оракул-ключ (опционально)"))
        v_in.addWidget(self.ed_oracle_key)

        scroll.setWidget(input_panel)
        root_split.addWidget(scroll)

        # --- Низ: слева список атак, справа вертикально лог | графики ---
        work = QSplitter(Qt.Horizontal)
        work.setHandleWidth(8)
        work.setChildrenCollapsible(False)

        left_col = QWidget()
        left_col.setObjectName("attackListColumn")
        left_col.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        left_col.setMinimumWidth(260)
        left_col.setMaximumWidth(400)
        vl = QVBoxLayout(left_col)
        vl.setContentsMargins(4, 4, 4, 4)
        vl.setSpacing(8)

        lbl_at = QLabel("Атаки")
        lbl_at.setObjectName("title")
        vl.addWidget(lbl_at)

        self.list_attacks = QListWidget()
        self.list_attacks.setSelectionMode(QAbstractItemView.MultiSelection)
        self.list_attacks.setMinimumHeight(220)
        self.list_attacks.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        for a in self._registry.attacks:
            item = QListWidgetItem(a.title)
            item.setData(Qt.UserRole, a.id)
            item.setSelected(True)
            self.list_attacks.addItem(item)
        vl.addWidget(self.list_attacks, 1)

        self.pb = QProgressBar()
        self.pb.setRange(0, 0)
        self.pb.setVisible(False)
        vl.addWidget(self.pb)

        row_run = QHBoxLayout()
        b_copy = QPushButton("Взять с шифрования")
        b_copy.setObjectName("secondary")
        b_copy.clicked.connect(self._copy_from_crypto)
        b_run = QPushButton("Запустить")
        b_run.setToolTip("Запустить выбранные атаки")
        b_run.clicked.connect(self._run_attacks)
        row_run.addWidget(b_copy)
        row_run.addWidget(b_run)
        vl.addLayout(row_run)

        right_split = QSplitter(Qt.Vertical)
        right_split.setHandleWidth(8)
        right_split.setChildrenCollapsible(False)

        log_panel = QWidget()
        log_panel.setObjectName("analysisLogPanel")
        log_panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        v_log = QVBoxLayout(log_panel)
        v_log.setContentsMargins(4, 4, 4, 4)
        v_log.setSpacing(4)
        lbl_log = QLabel("Результаты")
        lbl_log.setObjectName("title")
        v_log.addWidget(lbl_log)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(120)
        self.log.setPlaceholderText("Логи атак…")
        self.log.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        v_log.addWidget(self.log, 1)

        chart_panel = QWidget()
        chart_panel.setObjectName("analysisChartPanel")
        chart_panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        v_ch = QVBoxLayout(chart_panel)
        v_ch.setContentsMargins(4, 4, 4, 4)
        v_ch.setSpacing(4)
        row_ch = QHBoxLayout()
        row_ch.setSpacing(8)
        lbl_ch = QLabel("Сравнение методов и гистограмма шифротекста")
        lbl_ch.setObjectName("subtitle")
        lbl_ch.setWordWrap(True)
        row_ch.addWidget(lbl_ch, 1)
        self._chart_fullscreen_btn = QPushButton("На весь экран")
        self._chart_fullscreen_btn.setObjectName("secondary")
        self._chart_fullscreen_btn.setToolTip("Развернуть графики на весь экран (Esc — выход)")
        self._chart_fullscreen_btn.clicked.connect(self._open_attack_charts_fullscreen)
        row_ch.addWidget(self._chart_fullscreen_btn, 0, Qt.AlignmentFlag.AlignTop)
        v_ch.addLayout(row_ch)
        self._chart_panel_layout = v_ch
        self._attack_chart = AttackComparisonWidget()
        self._attack_chart.setMinimumHeight(320)
        self._attack_chart.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        v_ch.addWidget(self._attack_chart, 1)
        self._attack_chart.clear_placeholder()

        right_split.addWidget(log_panel)
        right_split.addWidget(chart_panel)
        right_split.setStretchFactor(0, 1)
        right_split.setStretchFactor(1, 2)
        right_split.setSizes([220, 380])

        work.addWidget(left_col)
        work.addWidget(right_split)
        work.setStretchFactor(0, 0)
        work.setStretchFactor(1, 1)
        work.setSizes([300, 780])

        root_split.addWidget(work)
        root_split.setStretchFactor(0, 0)
        root_split.setStretchFactor(1, 1)
        root_split.setSizes([300, 520])

        card_lay.addWidget(root_split)
        return page

    def _build_files_page(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        card = self._card()
        outer.addWidget(card)
        v = QVBoxLayout(card)
        v.setContentsMargins(22, 22, 22, 22)
        v.setSpacing(10)
        v.addWidget(self._title("Файлы"))
        v.addWidget(self._subtitle("Шифрование и расшифрование бинарных файлов (дополнение PKCS#7)."))

        self.ed_fin = QLineEdit()
        self.ed_fout = QLineEdit()
        self.ed_fkey = QLineEdit()
        self.sp_rounds_f = QSpinBox()
        self.sp_rounds_f.setRange(1, 4)
        self.sp_rounds_f.setValue(4)

        def pick_in() -> None:
            p, _ = QFileDialog.getOpenFileName(self, "Входной файл")
            if p:
                self.ed_fin.setText(p)

        def pick_out() -> None:
            p, _ = QFileDialog.getSaveFileName(self, "Выходной файл")
            if p:
                self.ed_fout.setText(p)

        row = QHBoxLayout()
        b1 = QPushButton("Вход…")
        b1.setObjectName("secondary")
        b1.clicked.connect(pick_in)
        row.addWidget(b1)
        row.addWidget(self.ed_fin, 1)

        row2 = QHBoxLayout()
        b2 = QPushButton("Выход…")
        b2.setObjectName("secondary")
        b2.clicked.connect(pick_out)
        row2.addWidget(b2)
        row2.addWidget(self.ed_fout, 1)

        v.addLayout(row)
        v.addLayout(row2)
        fk = QHBoxLayout()
        fk.addWidget(QLabel("Ключ hex"))
        fk.addWidget(self.ed_fkey, 1)
        fk.addWidget(QLabel("Раунды"))
        fk.addWidget(self.sp_rounds_f)
        v.addLayout(fk)

        row3 = QHBoxLayout()
        bf_e = QPushButton("Зашифровать файл")
        bf_e.clicked.connect(self._file_encrypt)
        bf_d = QPushButton("Расшифровать файл")
        bf_d.setObjectName("secondary")
        bf_d.clicked.connect(self._file_decrypt)
        row3.addWidget(bf_e)
        row3.addWidget(bf_d)
        v.addLayout(row3)
        v.addStretch()
        return page

    def _msg(self, title: str, text: str) -> None:
        QMessageBox.information(self, title, text)

    def _err(self, title: str, text: str) -> None:
        QMessageBox.critical(self, title, text)

    def _on_encrypt(self) -> None:
        try:
            key = self.ed_key.text().strip()
            r = int(self.sp_rounds_crypto.value())
            pt = self.ed_plain.toPlainText()
            ct = self._cipher.encrypt_text(pt, key, r)
            hx = ct.hex()
            self.ed_cipher_hex.setPlainText(hx)
            self._last_cipher_hex = hx
            self._msg("Готово", "Текст зашифрован. Hex скопирован в поле ниже.")
        except Exception as e:
            self._err("Ошибка", str(e))

    def _on_decrypt(self) -> None:
        try:
            key = self.ed_key.text().strip()
            r = int(self.sp_rounds_crypto.value())
            h = normalize_hex(self.ed_cipher_hex.toPlainText())
            data = bytes.fromhex(h)
            text = self._cipher.decrypt_text(data, key, r)
            self.ed_plain.setPlainText(text)
            self._msg("Готово", "Шифротекст расшифрован.")
        except Exception as e:
            self._err("Ошибка", str(e))

    def _copy_from_crypto(self) -> None:
        self.ed_a_plain.setPlainText(self.ed_plain.toPlainText())
        self.ed_a_cipher_hex.setPlainText(self.ed_cipher_hex.toPlainText())
        self.ed_oracle_key.setText(self.ed_key.text().strip())
        self.sp_rounds_a.setValue(self.sp_rounds_crypto.value())
        self._append_log("Данные скопированы с вкладки «Шифрование».")

    def _append_log(self, s: str) -> None:
        self.log.append(s)

    def _build_context(self) -> AttackContext:
        plain = self.ed_a_plain.toPlainText()
        p_blocks = utf8_to_blocks(plain)
        c_blocks = blocks_from_hex(self.ed_a_cipher_hex.toPlainText())
        if len(p_blocks) != len(c_blocks):
            raise ValueError("Число блоков открытого текста и шифротекста должно совпадать. Проверьте длину hex.")

        rounds = int(self.sp_rounds_a.value())
        oracle = self.ed_oracle_key.text().strip()
        known = None
        if len(oracle) == 16:
            from safer_k64.cipher.key_schedule import validate_key_hex

            known = validate_key_hex(oracle)

        plain_pairs = None
        cipher_pairs = None
        if self.cb_pair.isChecked():
            p2h = normalize_hex(self.ed_p2_hex.text())
            c2h = normalize_hex(self.ed_c2_hex.text())
            if len(p2h) != 16 or len(c2h) != 16:
                raise ValueError("Для пары нужны ровно 16 hex-символов на P2 и C2.")
            p2 = list(bytes.fromhex(p2h))
            c2 = list(bytes.fromhex(c2h))
            plain_pairs = [(p_blocks[0], p2)]
            cipher_pairs = [(c_blocks[0], c2)]

        return AttackContext(
            num_rounds=rounds,
            plaintext_blocks=p_blocks,
            ciphertext_blocks=c_blocks,
            plain_pairs=plain_pairs,
            cipher_pairs=cipher_pairs,
            known_key_bytes=known,
        )

    def _open_attack_charts_fullscreen(self) -> None:
        if self._charts_fs_dlg is not None:
            self._charts_fs_dlg.raise_()
            self._charts_fs_dlg.activateWindow()
            return
        lay = self._chart_panel_layout
        if lay is None:
            return
        lay.removeWidget(self._attack_chart)
        self._attack_chart.setParent(None)

        dlg = QDialog(self)
        dlg.setWindowTitle("Графики — полный экран")
        dlg.setModal(False)
        dlg.setWindowFlags(
            dlg.windowFlags()
            | Qt.WindowType.Window
            | Qt.WindowType.WindowMaximizeButtonHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        outer = QVBoxLayout(dlg)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(0)
        outer.addWidget(self._attack_chart, 1)
        self._attack_chart.show()

        esc = QShortcut(QKeySequence(Qt.Key.Key_Escape), dlg)
        esc.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        esc.activated.connect(dlg.close)

        def _restore(_: int = 0) -> None:
            if self._attack_chart.parent() is dlg:
                outer.removeWidget(self._attack_chart)
                self._attack_chart.setParent(None)
                lay.insertWidget(1, self._attack_chart, 1)
                self._attack_chart.show()
            if self._chart_fullscreen_btn is not None:
                self._chart_fullscreen_btn.setEnabled(True)
            self._charts_fs_dlg = None

        dlg.finished.connect(_restore)
        self._charts_fs_dlg = dlg
        if self._chart_fullscreen_btn is not None:
            self._chart_fullscreen_btn.setEnabled(False)
        dlg.showFullScreen()

    def _run_attacks(self) -> None:
        if self._worker and self._worker.isRunning():
            self._err("Занято", "Дождитесь завершения текущего запуска.")
            return
        try:
            ctx = self._build_context()
        except Exception as e:
            self._err("Данные", str(e))
            return

        if not any(self.list_attacks.item(i).isSelected() for i in range(self.list_attacks.count())):
            self._err("Атаки", "Выберите хотя бы одну атаку.")
            return

        max_keys = int(self.sp_brute_max.value())
        self._registry = default_registry(brute_max_keys=max_keys)

        self._attack_results = []
        self._attack_chart.clear_placeholder()
        try:
            raw = bytes.fromhex(normalize_hex(self.ed_a_cipher_hex.toPlainText()))
            self._attack_chart.set_ciphertext_bytes(raw)
        except ValueError:
            self._attack_chart.set_ciphertext_bytes(b"")

        self.log.clear()
        self._append_log("── Запуск ──")
        self.pb.setVisible(True)
        self.pb.setRange(0, 0)

        self._attack_queue = []
        for i in range(self.list_attacks.count()):
            it = self.list_attacks.item(i)
            if not it.isSelected():
                continue
            aid = it.data(Qt.UserRole)
            a = self._registry.by_id(aid)
            if a:
                self._attack_queue.append((a.title, a))

        self._run_next_attack(ctx)

    def _run_next_attack(self, ctx: AttackContext) -> None:
        if not self._attack_queue:
            self.pb.setVisible(False)
            self._append_log("── Готово ──")
            if self._attack_results:
                try:
                    raw = bytes.fromhex(normalize_hex(self.ed_a_cipher_hex.toPlainText()))
                    self._attack_chart.set_ciphertext_bytes(raw)
                except ValueError:
                    pass
                self._attack_chart.update_results(self._attack_results)
            return
        title, attack = self._attack_queue.pop(0)
        self._append_log(f"\n▶ {title}")

        self._worker = _AttackWorker(attack, ctx)
        self._worker.finished_ok.connect(lambda res, c=ctx: self._on_attack_done(res, c))
        self._worker.start()

    def _on_attack_done(self, res: AnalysisResult, ctx: AttackContext) -> None:
        self._attack_results.append(res)
        self._append_log(f"  Успех: {res.success} | {res.message} | {res.elapsed_seconds:.3f} с")
        if res.recovered_key_hex:
            self._append_log(f"  Ключ: {res.recovered_key_hex}")
        if res.details:
            self._append_log(res.details)
        self._worker = None
        self._run_next_attack(ctx)

    def _file_encrypt(self) -> None:
        try:
            from safer_k64.cipher.key_schedule import validate_key_hex

            inp = Path(self.ed_fin.text().strip())
            out = Path(self.ed_fout.text().strip())
            validate_key_hex(self.ed_fkey.text())
            self._cipher.encrypt_file(inp, out, self.ed_fkey.text().strip(), int(self.sp_rounds_f.value()))
            self._msg("Файл", f"Записано: {out}")
        except Exception as e:
            self._err("Файл", str(e))

    def _file_decrypt(self) -> None:
        try:
            from safer_k64.cipher.key_schedule import validate_key_hex

            inp = Path(self.ed_fin.text().strip())
            out = Path(self.ed_fout.text().strip())
            validate_key_hex(self.ed_fkey.text())
            self._cipher.decrypt_file(inp, out, self.ed_fkey.text().strip(), int(self.sp_rounds_f.value()))
            self._msg("Файл", f"Записано: {out}")
        except Exception as e:
            self._err("Файл", str(e))
