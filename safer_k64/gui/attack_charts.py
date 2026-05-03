"""Сравнение атак: горизонтальные диаграммы (читаемые подписи) + гистограмма шифра."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QTimer
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

if TYPE_CHECKING:
    from safer_k64.domain.models import AnalysisResult


def _tick_label_line(title: str, max_len: int = 34) -> str:
    """Одна строка для оси Y: короче, чтобы помещалась при узком поле."""
    t = title.replace("\n", " ").strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1] + "…"


class AttackComparisonWidget(QWidget):
    """
    Три панели:
    1) время каждой атаки (сек) — горизонтальные столбцы, слева названия;
    2) успех и кандидаты — одна строка на метод: слева цвет (зел/сер), справа длина оранжевой полосы;
    3) гистограмма байт 0…255 по hex шифротекста.
    """

    _FOOTER = (
        "Как читать:\n"
        "① Время в секундах (при большом разбросе ось — логарифм).\n"
        "② Слева цвет = успех/нет; длина оранжевой полосы = доля кандидатов (норм. к max).\n"
        "③ По X — значение байта шифра 0…255, по Y — сколько раз встретился."
    )
    _FIG_RIGHT = 0.97

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(360, 320)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._canvas = None
        self._fig = None
        self._axes = None
        self._footer_text = None
        self._mpl_ok = False
        self._cipher_bytes: bytes = b""
        self._stored_results: list | None = None
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.timeout.connect(self._on_resize_debounced)

        try:
            from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
            from matplotlib.figure import Figure

            self._fig = Figure(figsize=(9, 8.0), dpi=100, facecolor="#1a1d28")
            self._canvas = FigureCanvasQTAgg(self._fig)
            self._canvas.setMinimumHeight(300)
            axes = self._fig.subplots(
                3,
                1,
                gridspec_kw={"height_ratios": [1.2, 1.2, 1.0], "hspace": 0.52},
            )
            self._axes = (axes[0], axes[1], axes[2])
            for ax in self._axes:
                self._style_axes(ax)
            self._layout.addWidget(self._canvas, 1)
            self._mpl_ok = True
        except ImportError:
            lbl = QLabel(
                "Для графиков установите matplotlib:\n"
                "  py -3.12 -m pip install matplotlib"
            )
            lbl.setWordWrap(True)
            lbl.setObjectName("subtitle")
            self._layout.addWidget(lbl)

    @property
    def _ax_time(self):
        return self._axes[0] if self._axes else None

    @property
    def _ax_metrics(self):
        return self._axes[1] if self._axes else None

    @property
    def _ax_hist(self):
        return self._axes[2] if self._axes else None

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._resize_timer.start(100)

    def _on_resize_debounced(self) -> None:
        if not self._mpl_ok or self._canvas is None:
            return
        if self._stored_results:
            self.update_results(list(self._stored_results))
        else:
            self._sync_figure_size()
            fs = self._fonts_for_canvas()
            if self._axes:
                for ax in self._axes:
                    for t in ax.texts:
                        t.set_fontsize(fs["hint"])
            self._apply_placeholder_layout()
            self._canvas.draw_idle()

    def _sync_figure_size(self) -> None:
        if not self._mpl_ok or self._canvas is None or self._fig is None:
            return
        w, h = max(self._canvas.width(), 120), max(self._canvas.height(), 140)
        self._fig.set_size_inches(w / self._fig.dpi, h / self._fig.dpi)

    def _fonts_for_canvas(self) -> dict[str, int]:
        h = max(self._canvas.height(), 220) if self._canvas else 400
        w = max(self._canvas.width(), 300) if self._canvas else 640
        # Ниже окно — сильнее уменьшаем шрифты, чтобы не наезжали подписи
        scale = max(0.52, min(1.22, (min(h, w * 0.9) / 580) ** 0.48))
        return {
            "tick": max(5, int(7 * scale)),
            "title": max(7, min(12, int(9 * scale))),
            "axis": max(6, int(8 * scale)),
            "ann": max(5, int(6 * scale)),
            "leg": max(5, int(6 * scale)),
            "foot": max(5, min(8, int(6 * scale))),
            "hint": max(7, int(9 * scale)),
        }

    def _apply_tick_style(self, ax, fs: dict[str, int]) -> None:
        ax.tick_params(colors="#c5c9d6", labelsize=fs["tick"])

    def _margins_data(self, fw_px: float, fh_px: float, longest: int, n: int, fs: dict[str, int]) -> tuple[float, float, float, float, float]:
        # Кириллица в matplotlib ~0.62 * fontsize по ширине «средней» буквы
        char_w = fs["tick"] * 0.62
        need_left_px = longest * char_w + 96.0
        left_m = max(0.16, min(0.64, need_left_px / max(fw_px, 1.0)))

        foot_fs = fs["foot"]
        footer_lines = 3.2
        footer_px = foot_fs * 1.45 * footer_lines + 28.0
        # Две верхние панели: подпись оси X + тики + зазор до заголовка ниже
        xband_px = fs["axis"] * 3.2 + fs["tick"] * 1.8 + 36.0
        bottom_px = max(96.0, min(0.48 * fh_px, xband_px + footer_px + max(0.0, (520.0 - fh_px) * 0.08)))
        bottom_m = max(0.16, min(0.48, bottom_px / max(fh_px, 1.0)))

        top_px = max(36.0, fs["title"] * 2.0 + 22.0)
        top_m = max(0.74, 1.0 - top_px / max(fh_px, 1.0))

        # hspace — доля от средней высоты axes; при низком окне и длинных подписях нужно больше
        hspace = max(0.44, min(0.95, 0.36 + n * 0.042 + max(0.0, (720.0 - fh_px) / 650.0) * 0.22))
        # Легенда и подписи n= — чуть уже справа
        right_m = min(self._FIG_RIGHT, max(0.86, 1.0 - 52.0 / max(fw_px, 1.0)))
        return left_m, right_m, top_m, bottom_m, hspace

    def _margins_placeholder(self, fw_px: float, fh_px: float, fs: dict[str, int]) -> tuple[float, float, float, float, float]:
        left_m = max(0.12, min(0.28, 100.0 / max(fw_px, 1.0)))
        bottom_m = max(0.12, min(0.24, 72.0 / max(fh_px, 1.0)))
        top_m = max(0.84, 1.0 - (fs["title"] * 2.0 + 32.0) / max(fh_px, 1.0))
        hspace = max(0.38, min(0.55, 0.34 + max(0.0, (600.0 - fh_px) / 800.0) * 0.2))
        return left_m, self._FIG_RIGHT, top_m, bottom_m, hspace

    def _apply_placeholder_layout(self) -> None:
        """Выставить поля; размер фигуры должен быть уже синхронизован с канвасом."""
        if self._fig is None or self._canvas is None:
            return
        fs = self._fonts_for_canvas()
        fw_px = self._fig.get_figwidth() * self._fig.dpi
        fh_px = self._fig.get_figheight() * self._fig.dpi
        lm, rm, tm, bm, hs = self._margins_placeholder(fw_px, fh_px, fs)
        self._fig.subplots_adjust(left=lm, right=rm, top=tm, bottom=bm, hspace=hs)

    def set_ciphertext_bytes(self, data: bytes | None) -> None:
        self._cipher_bytes = bytes(data or b"")

    @staticmethod
    def _style_axes(ax) -> None:
        ax.set_facecolor("#12141c")
        ax.tick_params(colors="#c5c9d6", labelsize=7)
        for spine in ax.spines.values():
            spine.set_color("#3d4560")
        ax.title.set_color("#f5f6fa")
        ax.xaxis.label.set_color("#e8eaf0")
        ax.yaxis.label.set_color("#e8eaf0")

    def _remove_footer(self) -> None:
        if self._footer_text is not None:
            try:
                self._footer_text.remove()
            except Exception:
                pass
            self._footer_text = None

    def _draw_footer(self, fontsize: int = 7) -> None:
        self._remove_footer()
        if self._fig is None:
            return
        self._footer_text = self._fig.text(
            0.5,
            0.02,
            self._FOOTER,
            transform=self._fig.transFigure,
            ha="center",
            va="bottom",
            fontsize=fontsize,
            color="#a8b0c4",
            linespacing=1.25,
        )

    def _refine_clipping_margins(self) -> None:
        """Доп. отступ слева/снизу по фактическим bbox подписей после отрисовки."""
        if self._fig is None or self._canvas is None:
            return
        try:
            self._fig.canvas.draw()
        except Exception:
            return
        renderer = self._fig.canvas.get_renderer()
        figbb = self._fig.bbox
        pad = 10.0
        p = self._fig.subplotpars
        left_new, bottom_new = p.left, p.bottom

        min_x = figbb.x1
        for ax in (self._ax_time, self._ax_metrics):
            if ax is None:
                continue
            for t in ax.get_yticklabels():
                bb = t.get_window_extent(renderer=renderer)
                min_x = min(min_x, bb.x0)
        if min_x < figbb.x0 + pad:
            left_new = min(0.70, p.left + (figbb.x0 + pad - min_x) / max(figbb.width, 1.0))

        if self._footer_text is not None:
            bb = self._footer_text.get_window_extent(renderer=renderer)
            if bb.y0 < figbb.y0 + pad:
                bottom_new = min(0.52, p.bottom + (figbb.y0 + pad - bb.y0) / max(figbb.height, 1.0))

        if left_new != p.left or bottom_new != p.bottom:
            self._fig.subplots_adjust(
                left=left_new,
                right=p.right,
                top=p.top,
                bottom=bottom_new,
                hspace=p.hspace,
                wspace=p.wspace,
            )

    def clear_placeholder(self) -> None:
        if not self._mpl_ok or self._axes is None:
            return
        self._remove_footer()
        for ax in self._axes:
            ax.clear()
            self._style_axes(ax)
        fs = self._fonts_for_canvas()
        self._ax_time.text(
            0.5,
            0.5,
            "① Время атак (сек)\nЗапустите атаки",
            ha="center",
            va="center",
            color="#7a8199",
            fontsize=fs["hint"],
            transform=self._ax_time.transAxes,
        )
        self._ax_metrics.text(
            0.5,
            0.5,
            "② Успех и кандидаты\n(после запуска)",
            ha="center",
            va="center",
            color="#7a8199",
            fontsize=fs["hint"],
            transform=self._ax_metrics.transAxes,
        )
        self._ax_hist.text(
            0.5,
            0.5,
            "③ Гистограмма байт шифра\n(hex в поле C)",
            ha="center",
            va="center",
            color="#7a8199",
            fontsize=fs["hint"],
            transform=self._ax_hist.transAxes,
        )
        self._stored_results = None
        self._sync_figure_size()
        self._apply_placeholder_layout()
        self._canvas.draw_idle()

    def _draw_ciphertext_histogram(self, fs: dict[str, int]) -> None:
        if self._ax_hist is None:
            return
        self._ax_hist.clear()
        self._style_axes(self._ax_hist)
        self._apply_tick_style(self._ax_hist, fs)
        if not self._cipher_bytes:
            self._ax_hist.text(
                0.5,
                0.5,
                "Нет данных шифра\n(заполните поле C — hex)",
                ha="center",
                va="center",
                color="#9aa3b5",
                fontsize=fs["hint"],
                transform=self._ax_hist.transAxes,
            )
            return
        vals = list(self._cipher_bytes)
        nb = 56 if len(vals) > 200 else 40
        self._ax_hist.hist(
            vals,
            bins=nb,
            range=(0, 256),
            color="#9575cd",
            edgecolor="#1a1530",
            linewidth=0.2,
            alpha=0.9,
        )
        self._ax_hist.set_xlim(0, 255)
        pad = max(4, int(6 + fs["axis"] * 0.25))
        self._ax_hist.set_xlabel(
            "Значение байта в шифротексте (0…255)",
            color="#e8eaf0",
            fontsize=fs["axis"],
            labelpad=pad,
        )
        self._ax_hist.set_ylabel("Сколько раз байт встретился", color="#e8eaf0", fontsize=fs["axis"])
        self._ax_hist.set_title(
            f"③ Распределение байт в шифре ({len(self._cipher_bytes)} байт)",
            fontsize=fs["title"],
            pad=pad,
            color="#f5f6fa",
        )

    def update_results(self, results: list[AnalysisResult]) -> None:
        if not self._mpl_ok or not results or self._fig is None or self._axes is None:
            return

        import math

        from matplotlib.patches import Patch

        self._remove_footer()
        fs = self._fonts_for_canvas()
        ap = max(4, int(5 + fs["axis"] * 0.2))
        tpad = max(3, int(5 + fs["title"] * 0.18))
        xtick_pad = max(3, int(4 + fs["tick"] * 0.35))

        labels = [_tick_label_line(r.title, 32) for r in results]
        n = len(labels)
        y = list(range(n))
        bar_h = min(0.42, 0.82 / max(n, 1))

        times = [max(r.elapsed_seconds, 1e-9) for r in results]
        success = [1.0 if r.success else 0.0 for r in results]
        candidates = [float(r.metadata.get("candidates", 0) or 0) for r in results]
        c_max = max(candidates) if candidates and max(candidates) > 0 else 1.0
        cand_norm = [math.log1p(c) / math.log1p(c_max) if c_max > 0 else 0.0 for c in candidates]

        # --- ① Время: barh ---
        self._ax_time.clear()
        self._style_axes(self._ax_time)
        self._apply_tick_style(self._ax_time, fs)
        self._ax_time.barh(
            y,
            times,
            height=bar_h,
            align="center",
            color="#5c6bc0",
            edgecolor="#c5cae9",
            linewidth=0.35,
            alpha=0.95,
        )
        self._ax_time.set_yticks(y)
        self._ax_time.set_yticklabels(labels, fontsize=fs["tick"])
        self._ax_time.tick_params(axis="x", pad=xtick_pad)
        self._ax_time.set_xlabel("Время, с", color="#e8eaf0", fontsize=fs["axis"], labelpad=ap)
        self._ax_time.set_title(
            "① Сколько времени заняла каждая атака",
            fontsize=fs["title"],
            pad=tpad,
            color="#f5f6fa",
        )
        self._ax_time.invert_yaxis()
        tmax, tmin = max(times), min(times)
        if n > 1 and tmax > 25 * max(tmin, 1e-6):
            self._ax_time.set_xscale("symlog", linthresh=max(tmin * 2, 1e-4))
        else:
            self._ax_time.set_xscale("linear")
        xmax = max(times) * 1.12
        self._ax_time.set_xlim(0, xmax if xmax > 0 else 1)
        if n <= 10:
            for yi, t in zip(y, times):
                if t >= 1000:
                    ts = f"{t:.1f} с"
                elif t >= 10:
                    ts = f"{t:.2f} с"
                else:
                    ts = f"{t:.3f} с"
                self._ax_time.text(
                    t + xmax * 0.012,
                    yi,
                    ts,
                    va="center",
                    ha="left",
                    fontsize=fs["ann"],
                    color="#dce0f0",
                )

        # --- ② Успех + кандидаты: одна строка на метод — слева цвет успеха, справа длина = кандидаты ---
        self._ax_metrics.clear()
        self._style_axes(self._ax_metrics)
        self._apply_tick_style(self._ax_metrics, fs)
        col_s = ["#66bb6a" if s >= 0.5 else "#78909c" for s in success]
        succ_strip = 0.11
        gap_m = 0.018
        cand_left = succ_strip + gap_m
        avail_x = max(0.15, 1.0 - cand_left - 0.06)
        w_cand = [max(0.02, c * avail_x) for c in cand_norm]
        row_h = min(0.78, 0.92 / max(n, 1))
        self._ax_metrics.barh(
            y,
            [succ_strip] * n,
            height=row_h,
            left=0.0,
            color=col_s,
            edgecolor="none",
            linewidth=0,
            label="Успех: цвет слева (зелёный / серый)",
        )
        self._ax_metrics.barh(
            y,
            w_cand,
            height=row_h,
            left=cand_left,
            color="#ff9800",
            edgecolor="none",
            linewidth=0,
            alpha=0.92,
            label="Кандидаты: длина полосы (норм. к max)",
        )
        self._ax_metrics.set_yticks(y)
        self._ax_metrics.set_yticklabels(labels, fontsize=fs["tick"])
        self._ax_metrics.tick_params(axis="x", pad=xtick_pad)
        self._ax_metrics.set_xlabel(
            "Слева — успех (цвет); справа — относительный объём кандидатов (длина полосы)",
            color="#e8eaf0",
            fontsize=fs["axis"],
            labelpad=ap,
        )
        self._ax_metrics.set_xlim(0, 1.12)
        self._ax_metrics.set_title(
            "② Успех атаки и «вес» пространства кандидатов",
            fontsize=fs["title"],
            pad=tpad,
            color="#f5f6fa",
        )
        self._ax_metrics.invert_yaxis()
        leg = self._ax_metrics.legend(
            handles=[
                Patch(facecolor="#66bb6a", edgecolor="none", label="Успех (ключ найден)"),
                Patch(facecolor="#78909c", edgecolor="none", label="Нет ключа"),
                Patch(facecolor="#ff9800", edgecolor="none", label="Кандидаты (длина ∝ норм.)"),
            ],
            loc="upper left",
            bbox_to_anchor=(0.01, 0.99),
            fontsize=fs["leg"],
            framealpha=0.65,
            facecolor="#252a3a",
            edgecolor="#3d4560",
        )
        for t in leg.get_texts():
            t.set_color("#e8eaf0")

        def _fmt_n(cnt: int) -> str:
            if cnt >= 1_000_000:
                return f"n={cnt / 1e6:.1f}M"
            if cnt >= 100_000:
                return f"n={cnt / 1e3:.0f}k"
            if cnt >= 10_000:
                return f"n={cnt / 1e3:.1f}k"
            return f"n={cnt}"

        for i in range(n):
            cnt = int(candidates[i])
            if cnt > 0:
                x_ann = cand_left + w_cand[i] + 0.012
                self._ax_metrics.text(
                    min(x_ann, 0.98),
                    y[i],
                    _fmt_n(cnt),
                    va="center",
                    ha="left",
                    fontsize=max(5, fs["ann"] - 1),
                    color="#ffe0b2",
                )

        self._draw_ciphertext_histogram(fs)

        self._sync_figure_size()
        longest = max(len(lb) for lb in labels) if labels else 20
        fw_px = self._fig.get_figwidth() * self._fig.dpi
        fh_px = self._fig.get_figheight() * self._fig.dpi
        lm, rm, tm, bm, hs = self._margins_data(fw_px, fh_px, longest, n, fs)
        self._fig.subplots_adjust(left=lm, right=rm, top=tm, bottom=bm, hspace=hs)
        self._draw_footer(fs["foot"])
        self._refine_clipping_margins()
        self._stored_results = list(results)
        self._canvas.draw_idle()