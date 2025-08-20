# report_viewer.py
from __future__ import annotations
from pathlib import Path
from datetime import datetime

from PyQt6 import QtWidgets, QtCore
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices


class ReportViewer:
    # === 1) 우측 상단 날짜/시간 라벨 실시간(매분) 갱신 ===
    @staticmethod
    def attach_live_result_time(win: QtWidgets.QMainWindow):
        lbl = win.findChild(QtWidgets.QLabel, "lblResultTime")
        if not lbl:
            return

        def tick():
            lbl.setText(datetime.now().strftime("%Y. %m. %d. %H:%M (결과 전송 완료)"))

        tick()  # 즉시 1회
        timer = QtCore.QTimer(win)
        timer.setInterval(60_000)          # 1분마다
        timer.timeout.connect(tick)
        timer.start()
        win._result_time_timer = timer     # GC 방지

    # === 2) HTML 리포트 생성 ===
    @staticmethod
    def show_html_report(parent: QtWidgets.QWidget):
        win = parent.window()

        # UI 값 수집 (없으면 기본값)
        safe_bar   = win.findChild(QtWidgets.QProgressBar, "safeBar")
        lbl_safe   = win.findChild(QtWidgets.QLabel, "lblSafeCount")
        lbl_weak   = win.findChild(QtWidgets.QLabel, "lblWeakCount")
        lbl_unable = win.findChild(QtWidgets.QLabel, "lblUnableCount")

        safe_pct = safe_bar.value() if safe_bar else 0
        ctx = {
            "now": datetime.now().strftime("%Y. %m. %d. %H:%M (결과 전송 완료)"),
            "safe_pct": max(0, min(100, int(safe_pct))),
            "safe_cnt": lbl_safe.text().strip()   if lbl_safe   else "9건",
            "weak_cnt": lbl_weak.text().strip()   if lbl_weak   else "1건",
            "un_cnt" : lbl_unable.text().strip()  if lbl_unable else "0건",
        }

        html = ReportViewer._build_html(ctx)

        # 저장 다이얼로그
        suggested = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            parent,
            "HTML 리포트 저장",
            str(Path.home() / suggested),
            "HTML 파일 (*.html);;모든 파일 (*.*)"
        )
        if not path:
            return

        out = Path(path)
        out.write_text(html, encoding="utf-8")

        # 생성 성공 팝업 (열기/닫기)
        mb = QtWidgets.QMessageBox(parent)
        mb.setWindowTitle("리포트 생성 성공")
        mb.setText(f"리포트를 저장했습니다.\n{out}")
        mb.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Open |
                              QtWidgets.QMessageBox.StandardButton.Close)
        mb.setDefaultButton(QtWidgets.QMessageBox.StandardButton.Open)
        if mb.exec() == QtWidgets.QMessageBox.StandardButton.Open:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(out)))

    @staticmethod
    def _build_html(ctx: dict) -> str:
        """템플릿 파일 읽어서 placeholder 치환"""
        tpl_path = Path("templates/report_template.html")
        tpl = tpl_path.read_text(encoding="utf-8")

        return (
            tpl.replace("%NOW%", ctx["now"])
               .replace("%SAFE_PCT%", str(ctx["safe_pct"]))
               .replace("%SAFE_CNT%", str(ctx["safe_cnt"]))
               .replace("%WEAK_CNT%", str(ctx["weak_cnt"]))
               .replace("%UNSAFE_CNT%", str(ctx["un_cnt"]))
        )