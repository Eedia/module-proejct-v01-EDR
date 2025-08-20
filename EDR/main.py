# main_ui.py - 통합 EDR UI 애플리케이션
import sys
import os
import logging
from datetime import datetime, timedelta
from PyQt6 import QtWidgets, uic
from PyQt6.QtCore import Qt
from qt_material import apply_stylesheet

# UI 모듈들
from ui.report_viewer import ReportViewer
from ui.ai_chat import setup_chat_ui
from ui.analysis_worker import EDRAnalysisWorker
from ui.dashboard import DonutGauge, TimeSeriesChart, parse_score_from_label

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 글로벌 분석 결과 저장
analysis_results = None

def main():
    app = QtWidgets.QApplication(sys.argv)
    try:
        apply_stylesheet(app, theme='dark_blue.xml')
    except Exception:
        pass

    win = uic.loadUi("ui/main_window.ui")
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
        def on_start_analysis():
            """실제 EDR 분석 시작"""
            global analysis_results
            
            logger.info("🚀 EDR 분석 시작 버튼 클릭됨")
            
            # UI 상태 변경
            btn.setText("분석 중...")
            btn.setEnabled(False)
            
            # 진행률 표시 준비 (있다면)
            progress_label = win.findChild(QtWidgets.QLabel, "progressLabel")
            if progress_label:
                progress_label.setText("분석 준비 중...")
                progress_label.setVisible(True)
            
            # 워커 스레드 생성 및 시작
            win.analysis_worker = EDRAnalysisWorker()
            
            # 시그널 연결
            win.analysis_worker.progress_updated.connect(on_progress_update)
            win.analysis_worker.analysis_completed.connect(on_analysis_complete)
            win.analysis_worker.error_occurred.connect(on_analysis_error)
            
            # 분석 시작
            win.analysis_worker.start()
        
        def on_progress_update(progress, message):
            """분석 진행률 업데이트"""
            logger.info(f"진행률: {progress}% - {message}")
            
            # 진행률 라벨 업데이트
            progress_label = win.findChild(QtWidgets.QLabel, "progressLabel")
            if progress_label:
                progress_label.setText(f"{message} ({progress}%)")
            
            # 버튼 텍스트 업데이트
            btn.setText(f"분석 중... {progress}%")
        
        def on_analysis_complete(results):
            """분석 완료 처리"""
            global analysis_results
            analysis_results = results
            
            # 윈도우 객체에도 저장 (AI 채팅에서 사용)
            win.analysis_results = results
            
            logger.info("✅ EDR 분석 완료!")
            
            try:
                # 1. 실제 보안 점수 계산
                rule_score = results.get('rule_based_analysis', {}).get('overall_score', 85)
                ai_risk_level = results.get('ai_analysis', {}).get('risk_level', 'low')
                
                # 리스크 레벨에 따른 점수 조정
                risk_penalty = {'high': 20, 'medium': 10, 'low': 0}.get(ai_risk_level, 0)
                final_score = max(rule_score - risk_penalty, 0)
                
                logger.info(f"계산된 보안 점수: {final_score}")
                
                # 2. UI 업데이트
                win.donut.animate_to(final_score, duration_ms=1500)
                if score_label:
                    score_label.setText(f"{final_score}점")
                
                # 3. 차트 업데이트
                if hasattr(win, "ts"):
                    win.ts.append_point(datetime.now(), final_score)
                
                # 4. 진행률 숨기기
                progress_label = win.findChild(QtWidgets.QLabel, "progressLabel")
                if progress_label:
                    progress_label.setVisible(False)
                
                # 5. 최근 점검 결과 업데이트
                update_recent_findings(win, results)
                
                # 6. AI 채팅창에 분석 완료 알림
                from ui.ai_chat import notify_analysis_complete
                notify_analysis_complete(win, results)
                
                # 6. 분석 완료 메시지
                show_analysis_complete_message(results)
                
            except Exception as e:
                logger.error(f"결과 처리 중 오류: {e}")
                on_analysis_error(f"결과 처리 실패: {e}")
            
            finally:
                # UI 상태 복원
                btn.setText("분석 시작")
                btn.setEnabled(True)
        
        def update_recent_findings(window, results):
            """최근 점검 결과 UI 업데이트"""
            try:
                # 위험 발견사항 수 업데이트
                rule_findings = results.get('rule_based_analysis', {}).get('findings', [])
                ai_issues = results.get('ai_analysis', {}).get('detected_issues', [])
                
                # 고위험 발견사항만 카운트
                high_risk_count = 0
                for finding in rule_findings:
                    if finding.get('severity', '').lower() in ['high', 'critical']:
                        high_risk_count += 1
                
                for issue in ai_issues:
                    if issue.get('severity', '').lower() in ['high', 'critical']:
                        high_risk_count += 1
                
                # 위험 라벨 업데이트 (UI에 해당 라벨이 있다면)
                risk_label = window.findChild(QtWidgets.QLabel, "riskCount")
                if risk_label:
                    if high_risk_count > 0:
                        risk_label.setText(f"위험 ● {high_risk_count}건")
                        risk_label.setStyleSheet("color: #ff4444; font-weight: bold;")
                    else:
                        risk_label.setText("위험 ● 0건")
                        risk_label.setStyleSheet("color: #44ff44; font-weight: bold;")
                
                # 점검 완료 건수 업데이트
                total_checks = len(rule_findings) + len(ai_issues)
                check_label = window.findChild(QtWidgets.QLabel, "checkCount")
                if check_label:
                    check_label.setText(f"점검 완료 {total_checks}건")
                
                logger.info(f"최근 점검 결과 업데이트: 위험 {high_risk_count}건, 총 {total_checks}건")
                
            except Exception as e:
                logger.error(f"최근 점검 결과 업데이트 실패: {e}") 

        def on_analysis_error(error_message):
            """분석 오류 처리"""
            logger.error(f"❌ EDR 분석 오류: {error_message}")
            
            # 에러 메시지 표시
            msg_box = QtWidgets.QMessageBox()
            msg_box.setIcon(QtWidgets.QMessageBox.Icon.Critical)
            msg_box.setWindowTitle("분석 오류")
            msg_box.setText("EDR 분석 중 오류가 발생했습니다.")
            msg_box.setDetailedText(error_message)
            msg_box.exec()
            
            # UI 상태 복원
            btn.setText("분석 시작")
            btn.setEnabled(True)
            
            # 진행률 숨기기
            progress_label = win.findChild(QtWidgets.QLabel, "progressLabel")
            if progress_label:
                progress_label.setVisible(False)
        
        def show_analysis_complete_message(results):
            """분석 완료 메시지 표시"""
            metadata = results.get('integration_metadata', {})
            total_findings = metadata.get('total_rule_findings', 0)
            total_issues = metadata.get('total_ai_issues', 0)
            
            msg_box = QtWidgets.QMessageBox()
            msg_box.setIcon(QtWidgets.QMessageBox.Icon.Information)
            msg_box.setWindowTitle("분석 완료")
            msg_box.setText("🎉 EDR 보안 분석이 완료되었습니다!")
            msg_box.setInformativeText(
                f"• 룰 기반 탐지: {total_findings}개 발견\n"
                f"• AI 보안 이슈: {total_issues}개 발견\n"
                f"• 결과는 output/ 폴더에 저장되었습니다."
            )
            msg_box.exec()
        
        # 버튼 클릭 이벤트 연결
        btn.clicked.connect(on_start_analysis)

    # UI 로드 후
    ReportViewer.attach_live_result_time(win)  # 날짜/시간 실시간

    btn_html = win.findChild(QtWidgets.QPushButton, "btnHTML")
    if btn_html:
        btn_html.clicked.connect(lambda: ReportViewer.show_html_report(win))  # 생성 성공 팝업


    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
