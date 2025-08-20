from PyQt6 import QtWidgets, QtCore


class EnterToSendFilter(QtCore.QObject):
    """
    QTextEdit에서 Enter → send 버튼 클릭
    Shift+Enter → 줄바꿈 유지
    """
    def __init__(self, input_edit: QtWidgets.QTextEdit, send_btn: QtWidgets.QPushButton):
        super().__init__()
        self.input_edit = input_edit
        self.send_btn = send_btn
        # 이벤트 필터 장착
        input_edit.installEventFilter(self)

    def eventFilter(self, obj, ev):
        if obj is self.input_edit and ev.type() == QtCore.QEvent.Type.KeyPress:
            if ev.key() in (QtCore.Qt.Key.Key_Return, QtCore.Qt.Key.Key_Enter):
                if not (ev.modifiers() & QtCore.Qt.KeyboardModifier.ShiftModifier):
                    # Shift 안누른 Enter → 전송
                    self.send_btn.click()
                    return True
        return super().eventFilter(obj, ev)


# === 사용 예시 (ai_chat.py 의 초기화 부분에서) ===
def setup_chat_ui(window: QtWidgets.QMainWindow):
    send_btn = window.findChild(QtWidgets.QPushButton, "btnSend")
    input_edit = window.findChild(QtWidgets.QTextEdit, "chatInput")

    if send_btn and input_edit:
        EnterToSendFilter(input_edit, send_btn)
