"""Точка входа Qt-приложения."""

from __future__ import annotations


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication

        from safer_k64.gui.main_window import MainWindow
    except ImportError as e:
        print(
            "Не удалось загрузить GUI. Установите зависимости:\n"
            "  py -3.12 -m pip install -r requirements.txt\n"
            f"Причина: {e}"
        )
        return 1
    app = QApplication([])
    app.setApplicationName("SAFER K-64 Lab")
    w = MainWindow()
    w.show()
    return app.exec()


def run_app() -> int:
    """То же, что main() (старые вызовы bootstrap.run_app)."""
    return main()
