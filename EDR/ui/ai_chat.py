from PyQt6 import QtWidgets, QtCore
import sys
import os
import logging

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

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


def setup_chat_ui(window: QtWidgets.QMainWindow):
    """AI 채팅 UI 설정 및 이벤트 연결"""
    send_btn = window.findChild(QtWidgets.QPushButton, "btnSend")
    input_edit = window.findChild(QtWidgets.QTextEdit, "chatInput")
    chat_display = window.findChild(QtWidgets.QTextBrowser, "chatHistory")  # QTextBrowser로 변경
    
    logger.info(f"채팅 UI 요소 찾기 결과: send_btn={send_btn is not None}, input_edit={input_edit is not None}, chat_display={chat_display is not None}")
    
    if send_btn and input_edit:
        # Enter 키 필터 설정
        EnterToSendFilter(input_edit, send_btn)
        
        # 전송 버튼 클릭 이벤트
        def on_send_message():
            message_text = input_edit.toPlainText().strip()
            if not message_text:
                return
            
            logger.info(f"사용자 메시지 전송: {message_text}")
            
            # 사용자 메시지 표시
            add_user_message(chat_display, message_text)
            
            # 입력창 클리어
            input_edit.clear()
            
            # AI 응답 처리
            process_ai_response(chat_display, message_text, window)
        
        send_btn.clicked.connect(on_send_message)
        
        # 초기 메시지
        if chat_display:
            add_bot_message(chat_display, "안녕하세요! EDR 보안 분석 AI입니다.\n먼저 '분석 시작' 버튼을 눌러 보안 분석을 실행해주세요.")
        else:
            logger.warning("채팅 표시창(chatHistory)을 찾을 수 없습니다. UI 파일을 확인해주세요.")
    else:
        logger.warning(f"채팅 UI 요소를 찾을 수 없습니다. btnSend={send_btn is not None}, chatInput={input_edit is not None}")


def add_user_message(chat_display, message):
    """사용자 메시지를 채팅창에 추가"""
    if chat_display:
        chat_display.append(f"👤 <b>사용자:</b> {message}")
        chat_display.append("")  # 빈 줄
    else:
        logger.warning("채팅 표시창이 없어 사용자 메시지를 표시할 수 없습니다")


def add_bot_message(chat_display, message):
    """AI 봇 메시지를 채팅창에 추가"""
    if chat_display:
        chat_display.append(f"🤖 <b>AI:</b> {message}")
        chat_display.append("")  # 빈 줄
    else:
        logger.warning("채팅 표시창이 없어 AI 메시지를 표시할 수 없습니다")


def process_ai_response(chat_display, user_message, window):
    """사용자 메시지에 대한 AI 응답 처리"""
    try:
        # chat_display가 None인지 체크
        if not chat_display:
            logger.error("채팅 표시창을 찾을 수 없습니다")
            return
        
        # 윈도우 객체에서 분석 결과 가져오기
        analysis_results = getattr(window, 'analysis_results', None)
        
        if analysis_results is None:
            add_bot_message(chat_display, "아직 보안 분석이 실행되지 않았습니다.\n'분석 시작' 버튼을 먼저 클릭해주세요.")
            return
        
        # ask_about_scan 함수 사용
        from core.integrated_analyzer import ask_about_scan
        
        logger.info(f"AI 질문 처리: {user_message}")
        
        # 처리 중 메시지 표시
        add_bot_message(chat_display, "🤔 질문을 분석하고 있습니다...")
        
        # 채팅창 스크롤을 마지막으로 (안전하게)
        try:
            if chat_display and hasattr(chat_display, 'verticalScrollBar'):
                chat_display.verticalScrollBar().setValue(chat_display.verticalScrollBar().maximum())
        except Exception as e:
            logger.warning(f"스크롤 업데이트 실패 (무시): {e}")
        
        # Qt 이벤트 처리 (UI 업데이트를 위해)
        QtWidgets.QApplication.processEvents()
        
        # AI 응답 생성
        ai_response = ask_about_scan(user_message, analysis_results)
        
        # 처리 중 메시지 제거하고 실제 응답으로 교체
        remove_last_bot_message(chat_display)
        add_bot_message(chat_display, ai_response)
        
        logger.info("AI 응답 완료")
        
    except ImportError as e:
        logger.error(f"모듈 임포트 오류: {e}")
        if chat_display:
            remove_last_bot_message(chat_display)
            add_bot_message(chat_display, "AI 기능을 사용할 수 없습니다. 시스템 설정을 확인해주세요.")
        
    except Exception as e:
        logger.error(f"AI 응답 처리 오류: {e}")
        if chat_display:
            remove_last_bot_message(chat_display)
            add_bot_message(chat_display, f"죄송합니다. 응답 처리 중 오류가 발생했습니다.\n오류: {e}")


def remove_last_bot_message(chat_display):
    """마지막 봇 메시지 제거 (처리 중 메시지 제거용)"""
    if not chat_display:
        return
        
    text = chat_display.toPlainText()
    lines = text.split('\n')
    
    # 마지막 봇 메시지 찾아서 제거
    new_lines = []
    skip_next_empty = False
    
    for i in range(len(lines) - 1, -1, -1):
        line = lines[i]
        
        if skip_next_empty and line.strip() == "":
            skip_next_empty = False
            continue
            
        if line.startswith("🤖"):
            skip_next_empty = True
            continue
            
        new_lines.insert(0, line)
    
    chat_display.clear()
    for line in new_lines:
        chat_display.append(line)


def generate_analysis_summary_message(results):
    """분석 결과 요약 메시지 생성"""
    try:
        metadata = results.get('integration_metadata', {})
        rule_analysis = results.get('rule_based_analysis', {})
        ai_analysis = results.get('ai_analysis', {})
        
        total_findings = metadata.get('total_rule_findings', 0)
        total_issues = metadata.get('total_ai_issues', 0)
        overall_score = rule_analysis.get('overall_score', 0)
        risk_level = ai_analysis.get('risk_level', 'unknown')
        
        risk_emoji = {
            'high': '🔴',
            'medium': '🟡', 
            'low': '🟢'
        }.get(risk_level, '⚪')
        
        summary = f"""🎉 보안 분석이 완료되었습니다!

📊 **분석 결과 요약:**
• 전체 보안 점수: {overall_score}점
• 위험도 수준: {risk_emoji} {risk_level.upper()}
• 룰 기반 탐지: {total_findings}개 발견사항
• AI 보안 이슈: {total_issues}개 발견

💬 이제 분석 결과에 대해 자유롭게 질문해보세요!
예시: "가장 위험한 문제는 무엇인가요?", "몇 개의 문제가 발견되었나요?"
        """
        
        return summary.strip()
        
    except Exception as e:
        logger.error(f"요약 메시지 생성 오류: {e}")
        return "분석이 완료되었습니다. 결과에 대해 질문해보세요!"


def notify_analysis_complete(window, results):
    """분석 완료를 채팅창에 알림"""
    chat_display = window.findChild(QtWidgets.QTextEdit, "chatDisplay")
    if chat_display:
        summary_message = generate_analysis_summary_message(results)
        add_bot_message(chat_display, summary_message)
