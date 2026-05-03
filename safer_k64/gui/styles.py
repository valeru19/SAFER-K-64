"""Глобальные стили Qt (тёмная тема, скругления)."""

APP_STYLESHEET = """
QWidget { color: #e8eaf0; font-size: 13px; }
QMainWindow, QDialog { background-color: #12141c; }

/* Панели без своего фона (сплиттер, стек) — не оставлять системный светлый цвет */
QSplitter, QStackedWidget {
    background-color: #12141c;
}

/* Область прокрутки и её viewport (иначе на Windows — белое «молоко», светлый текст не читается) */
QScrollArea {
    background-color: #1b1e2a;
    border: 1px solid #2f3548;
    border-radius: 10px;
}
QAbstractScrollArea::viewport {
    background-color: #1b1e2a;
}
QScrollArea > QWidget > QWidget {
    background-color: #1b1e2a;
}
QWidget#analysisInputPanel {
    background-color: #1b1e2a;
}

/* Обычные подписи (не только title/subtitle) */
QLabel {
    color: #dce0f0;
    background-color: transparent;
}
QCheckBox {
    color: #dce0f0;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid #4a5270;
    background-color: #0f1118;
}
QCheckBox::indicator:checked {
    background-color: #5c6bc0;
    border-color: #7c8bd4;
}

QFrame#card {
    background-color: #1a1d28;
    border-radius: 14px;
    border: 1px solid #2a3142;
}
QLineEdit, QTextEdit, QSpinBox, QComboBox {
    background-color: #0f1118;
    color: #e8eaf0;
    border: 1px solid #2f3548;
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: #5c6bc0;
    selection-color: #ffffff;
}
QLineEdit::placeholder {
    color: #6a7388;
}

/* Колонки внутри сплиттера (иначе возможен светлый фон системы) */
QWidget#attackListColumn,
QWidget#analysisLogPanel,
QWidget#analysisChartPanel {
    background-color: #151824;
    border-radius: 10px;
    border: 1px solid #2a3142;
}
QPushButton {
    background-color: qlineargradient(x1:0,y1:0,x2:1,y2:1,
        stop:0 #5c6bc0, stop:1 #3949ab);
    color: #ffffff;
    border: none;
    border-radius: 10px;
    padding: 10px 16px;
    font-weight: 600;
}
QPushButton:hover { background-color: #6f7fe0; }
QPushButton:pressed { background-color: #3d4fa8; }
QPushButton#secondary {
    background-color: #2a3142;
    color: #e8eaf0;
}
QPushButton#secondary:hover { background-color: #343d52; }
QListWidget {
    background-color: #151824;
    border: none;
    border-radius: 12px;
    padding: 8px;
    outline: none;
}
QListWidget::item {
    padding: 12px 14px;
    border-radius: 8px;
    margin: 2px 0;
    color: #dce0f0;
}
QListWidget::item:selected {
    background-color: #2c3350;
    color: #ffffff;
}
QListWidget::item:hover { background-color: #222636; }
QProgressBar {
    border: 1px solid #2f3548;
    border-radius: 8px;
    text-align: center;
    height: 22px;
    background-color: #0f1118;
}
QProgressBar::chunk {
    border-radius: 6px;
    background-color: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #7e57c2, stop:1 #5c6bc0);
}
QLabel#title { font-size: 20px; font-weight: 700; color: #f5f6fa; background-color: transparent; }
QLabel#subtitle { color: #b4bcc8; font-size: 12px; background-color: transparent; }
QScrollBar:vertical {
    background: #151824;
    width: 10px;
    margin: 4px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #3d4560;
    min-height: 24px;
    border-radius: 5px;
}
QTabWidget::pane { border: 1px solid #2a3142; border-radius: 12px; top: -1px; }
QTabBar::tab {
    background: #1a1d28;
    padding: 10px 18px;
    margin-right: 4px;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
}
QTabBar::tab:selected { background: #252a3a; color: #fff; font-weight: 600; }
QSplitter::handle {
    background: #2a3142;
}
QSplitter::handle:horizontal {
    width: 6px;
    margin: 2px 0;
    border-radius: 3px;
}
QSplitter::handle:horizontal:hover {
    background: #5c6bc0;
}
QSplitter::handle:vertical {
    height: 6px;
    margin: 0 2px;
    border-radius: 3px;
}
QSplitter::handle:vertical:hover {
    background: #7e57c2;
}
"""
