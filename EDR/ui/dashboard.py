import re
from datetime import datetime
from PyQt6 import QtWidgets, QtCore, QtGui
from PyQt6.QtCharts import QChart, QChartView, QLineSeries, QDateTimeAxis, QValueAxis

# ---------------------------
# Donut Gauge
# ---------------------------
class DonutGauge(QtWidgets.QWidget):
    def __init__(self, value=90, maximum=100, thickness=16,
                 fg="#22c55e", track="#3f4147", text="#e5e7eb", parent=None):
        super().__init__(parent)
        self._value = int(value)
        self._max = int(maximum)
        self._thickness = int(thickness)
        self._fg = QtGui.QColor(fg)
        self._track = QtGui.QColor(track)
        self._text = QtGui.QColor(text)
        self.setAttribute(QtCore.Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred,
                           QtWidgets.QSizePolicy.Policy.Preferred)
        self.setMinimumSize(120, 120)

    def hasHeightForWidth(self): return True
    def heightForWidth(self, w: int) -> int: return w
    def sizeHint(self): return QtCore.QSize(180, 180)

    def value(self): return self._value
    def setValue(self, v: int):
        self._value = max(0, min(int(v), self._max))
        self.update()
    value = QtCore.pyqtProperty(int, fget=value, fset=setValue)

    def animate_to(self, new_value: int, duration_ms: int = 900):
        anim = QtCore.QPropertyAnimation(self, b"value")
        anim.setDuration(duration_ms)
        anim.setStartValue(self._value)
        anim.setEndValue(max(0, min(int(new_value), self._max)))
        anim.setEasingCurve(QtCore.QEasingCurve.Type.InOutCubic)
        self._anim = anim
        anim.start()

    def paintEvent(self, e):
        w, h = self.width(), self.height()
        pad = self._thickness / 2 + 3
        side = max(0.0, min(w, h) - 2 * pad)
        rc = QtCore.QRectF((w - side) / 2, (h - side) / 2, side, side)

        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        pen = QtGui.QPen(self._track, self._thickness)
        pen.setCapStyle(QtCore.Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(QtCore.Qt.PenJoinStyle.RoundJoin)

        # 트랙
        p.setPen(pen)
        p.drawEllipse(rc)

        # 값 아크
        pen.setColor(self._fg)
        p.setPen(pen)
        start = 90 * 16
        span = -int(360 * 16 * (self._value / max(1, self._max)))
        p.drawArc(rc, start, span)

        # 중앙 숫자
        p.setPen(self._text)
        font = self.font(); font.setBold(True); font.setPointSize(int(side * 0.22))
        p.setFont(font)
        p.drawText(self.rect(), QtCore.Qt.AlignmentFlag.AlignCenter, f"{self._value}")


# ---------------------------
# TimeSeriesChart
# ---------------------------
class TimeSeriesChart(QtWidgets.QWidget):
    def __init__(self, keep_last: int = 5, parent=None):
        super().__init__(parent)
        self.keep_last = keep_last
        self.series = QLineSeries()
        self.series.setUseOpenGL(False)

        self.chart = QChart()
        self.chart.addSeries(self.series)
        self.chart.legend().hide()
        self.chart.setBackgroundVisible(False)
        self.chart.setMargins(QtCore.QMargins(6, 6, 6, 6))

        # X축
        self.axis_x = QDateTimeAxis()
        self.axis_x.setFormat("MM/dd\nHH:mm")
        self.axis_x.setTickCount(5)
        fx = self.axis_x.labelsFont()
        fx.setPointSize(8)
        self.axis_x.setLabelsFont(fx)
        self.chart.addAxis(self.axis_x, QtCore.Qt.AlignmentFlag.AlignBottom)
        self.series.attachAxis(self.axis_x)

        # Y축
        self.axis_y = QValueAxis()
        self.axis_y.setRange(0, 100)
        self.axis_y.setTickCount(6)
        f = self.axis_y.labelsFont()
        f.setPointSize(10)
        self.axis_y.setLabelsFont(f)
        self.axis_y.setLabelFormat("%d")
        self.chart.addAxis(self.axis_y, QtCore.Qt.AlignmentFlag.AlignLeft)
        self.series.attachAxis(self.axis_y)

        # 색상
        grid = QtGui.QColor("#2f333a")
        axis_pen = QtGui.QPen(QtGui.QColor("#a3a7b0"))
        self.axis_x.setLinePen(axis_pen)
        self.axis_y.setLinePen(axis_pen)
        self.axis_x.setGridLinePen(QtGui.QPen(grid))
        self.axis_y.setGridLinePen(QtGui.QPen(grid))
        self.axis_x.setLabelsColor(QtGui.QColor("#a3a7b0"))
        self.axis_y.setLabelsColor(QtGui.QColor("#a3a7b0"))

        self.view = QChartView(self.chart)
        self.view.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
        self.view.setStyleSheet("background: transparent;")

        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.addWidget(self.view)

        self._points = []

    @staticmethod
    def _dt_to_msecs(dt: datetime) -> int:
        return int(dt.timestamp() * 1000)

    def set_points(self, pts: list[tuple[datetime, int]]):
        self._points = pts[-self.keep_last:]
        self._apply()

    def append_point(self, dt: datetime, value: int):
        self._points.append((dt, max(0, min(100, int(value)))))
        self._points = self._points[-self.keep_last:]
        self._apply()

    def _apply(self):
        self.series.clear()
        if not self._points:
            return
        for dt, v in self._points:
            self.series.append(self._dt_to_msecs(dt), v)

        tmins = [self._dt_to_msecs(dt) for dt, _ in self._points]
        t_min, t_max = min(tmins), max(tmins)
        if t_min == t_max:
            t_min -= 60_000
            t_max += 60_000
        self.axis_x.setRange(QtCore.QDateTime.fromMSecsSinceEpoch(t_min),
                             QtCore.QDateTime.fromMSecsSinceEpoch(t_max))

        pen = QtGui.QPen(QtGui.QColor("#60a5fa"))
        pen.setWidth(2)
        self.series.setPen(pen)


# ---------------------------
# Utils
# ---------------------------
def parse_score_from_label(text: str, default: int = 90) -> int:
    import re
    m = re.search(r'\d+', text or '')
    return max(0, min(100, int(m.group()))) if m else default