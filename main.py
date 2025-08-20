# main.py
import sys, random
from datetime import datetime, timedelta
from PyQt6 import QtWidgets, uic
from PyQt6.QtCore import Qt
from qt_material import apply_stylesheet
from report_viewer import ReportViewer
from ai_chat import setup_chat_ui


from dashboard import DonutGauge, TimeSeriesChart, parse_score_from_label

def main():
    app = QtWidgets.QApplication(sys.argv)
    try:
        apply_stylesheet(app, theme='dark_blue.xml')
    except Exception:
        pass

    win = uic.loadUi("main_window.ui")
    setup_chat_ui(win)


    # 초기 점수
    score_label = win.findChild(QtWidgets.QLabel, "scoreValue")
    value = parse_score_from_label(score_label.text(), 90) if score_label else 90

    # Donut
    donut_holder = win.findChild(QtWidgets.QWidget, "donutHolder")
    if donut_holder is not None:
        layout = donut_holder.layout() or QtWidgets.QVBoxLayout(donut_holder)
        win.donut = DonutGauge(value=value, maximum=100, thickness=18)
        layout.addWidget(win.donut, alignment=Qt.AlignmentFlag.AlignCenter)

    # Time-series chart
    chart_holder = win.findChild(QtWidgets.QWidget, "chartHolder")
    if chart_holder is not None:
        layout = chart_holder.layout() or QtWidgets.QVBoxLayout(chart_holder)
        win.ts = TimeSeriesChart(keep_last=5)
        layout.addWidget(win.ts)

        now = datetime.now()
        seed = [
            (now - timedelta(minutes=9), value - 8),
            (now - timedelta(minutes=6), value - 4),
            (now - timedelta(minutes=3), value - 2),
            (now - timedelta(minutes=1), value - 1),
            (now, value),
        ]
        win.ts.set_points(seed)

    # 버튼 이벤트
    btn = win.findChild(QtWidgets.QPushButton, "btnStart")
    if btn is not None:
        def on_click():
            new_score = random.randint(70, 100)
            win.donut.animate_to(new_score, duration_ms=900)
            if score_label:
                score_label.setText(f"{new_score}점")
            if hasattr(win, "ts"):
                win.ts.append_point(datetime.now(), new_score)
        btn.clicked.connect(on_click)

    # UI 로드 후
    ReportViewer.attach_live_result_time(win)  # 날짜/시간 실시간

    btn_html = win.findChild(QtWidgets.QPushButton, "btnHTML")
    if btn_html:
        btn_html.clicked.connect(lambda: ReportViewer.show_html_report(win))  # 생성 성공 팝업


    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
