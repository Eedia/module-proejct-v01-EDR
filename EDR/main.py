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

    # 스크립트가 있는 디렉토리를 기준으로 UI 파일 경로 설정
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ui_file = os.path.join(script_dir, "ui", "main_window.ui")
    
    if not os.path.exists(ui_file):
        print(f"❌ UI 파일을 찾을 수 없습니다: {ui_file}")
        print(f"현재 작업 디렉토리: {os.getcwd()}")
        print(f"스크립트 디렉토리: {script_dir}")
        sys.exit(1)
    
    try:
        win = uic.loadUi(ui_file)
    except Exception as e:
        print(f"❌ UI 파일 로드 실패: {e}")
        sys.exit(1)
    setup_chat_ui(win)

    # 초기 점수
    score_label = win.findChild(QtWidgets.QLabel, "scoreValue")
    value = parse_score_from_label(score_label.text(), 0) if score_label else 0

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
                rule_analysis = results.get('rule_based_analysis', {})
                
                # 룰 기반 분석에서 계산된 점수 우선 사용
                if 'total_score' in rule_analysis:
                    rule_score = rule_analysis['total_score']
                    logger.info(f"룰 기반 점수: {rule_score}")
                elif 'overall_score' in rule_analysis:
                    rule_score = rule_analysis['overall_score']
                    logger.info(f"룰 기반 점수: {rule_score}")

                else:
                    # 스캔 요약에서 점수 찾기
                    rule_score = rule_analysis.get('scan_summary', {}).get('total_score')
                    if rule_score is not None:
                        logger.info(f"스캔 요약 점수 사용: {rule_score}")
                    else:
                        rule_score = 100  # 최후의 기본값
                        logger.warning("점수를 찾을 수 없어 기본값 100사용")
                  
                ai_analysis = results.get('ai_analysis', {})
                ai_risk_level = ai_analysis.get('risk_level', 'low')
                logger.info(f"AI 위험도: {ai_risk_level}")
                
                # 리스크 레벨에 따른 점수 조정
                risk_penalty = {'high': 20, 'medium': 10, 'low': 0}.get(ai_risk_level, 0)
                final_score = max(rule_score - risk_penalty, 0)
                
                logger.info(f"최종 보안 점수: {final_score} (기본: {rule_score}, 페널티: {risk_penalty})")
                
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
                
                # 7. HTML 리포트 버튼 활성화
                btn_html = win.findChild(QtWidgets.QPushButton, "btnHTML")
                if btn_html:
                    btn_html.setEnabled(True)
                    btn_html.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
                    btn_html.setToolTip("최신 통합 보고서를 브라우저에서 확인하세요")
                
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
                rule_findings = results.get("rule_based_analysis", {}).get(
                    "findings", []
                )
                ai_issues = results.get("ai_analysis", {}).get("detected_issues", [])

                logger.info(
                    "🔍 결과 요약: 룰 기반 %d개, AI 분석 %d개",
                    len(rule_findings),
                    len(ai_issues),
                )

                # 발견 사항 카운트 (AI 기반)
                
                # 발견 사항 카운트
                high_risk_count = 0

                
                for issue in ai_issues:
                    if issue.get("severity", "").lower() in ["high", "critical"]:
                        high_risk_count += 1
                
               
                # total_checks = len(rule_findings) + len(ai_issues)
                total_checks = len(ai_issues)
                safe_count = max(total_checks - high_risk_count, 0)

                # UI 라벨 업데이트
                safe_label = window.findChild(QtWidgets.QLabel, "lblSafeCount")
                if safe_label:
                    safe_label.setText(f"{safe_count}건")

                weak_label = window.findChild(QtWidgets.QLabel, "lblWeakCount")
                if weak_label:
                    weak_label.setText(f"{high_risk_count}건")

                unable_label = window.findChild(QtWidgets.QLabel, "lblUnableCount")
                if unable_label:
                    unable_label.setText("0건")

                safe_bar = window.findChild(QtWidgets.QProgressBar, "safeBar")
                if safe_bar:
                    percent = int((safe_count / total_checks) * 100) if total_checks else 0
                    safe_bar.setMaximum(100)
                    safe_bar.setValue(percent)

                # 결과 시간 업데이트
                time_label = window.findChild(QtWidgets.QLabel, "lblResultTime")
                if time_label:
                    ts = results.get("integration_metadata", {}).get("timestamp")
                    try:
                        dt = datetime.fromisoformat(ts.replace('Z', '')) if ts else datetime.now()
                    except Exception:
                        dt = datetime.now()
                    time_label.setText(
                        dt.strftime("%Y. %m. %d. %H:%M (결과 전송 완료)")
                    )

                logger.info(
                    f"최근 점검 결과 업데이트 (AI 기반): 안전 {safe_count}건, 취약 {high_risk_count}건, 총 {total_checks}건"
                )

            except Exception as e:
                logger.error(f"최근 점검 결과 업데이트 실패: {e}")

                # UI 라벨 업데이트
                safe_label = window.findChild(QtWidgets.QLabel, "lblSafeCount")
                if safe_label:
                    safe_label.setText(f"{safe_count}건")

                weak_label = window.findChild(QtWidgets.QLabel, "lblWeakCount")
                if weak_label:
                    weak_label.setText(f"{high_risk_count}건")

                unable_label = window.findChild(QtWidgets.QLabel, "lblUnableCount")
                if unable_label:
                    unable_label.setText("0건")

                safe_bar = window.findChild(QtWidgets.QProgressBar, "safeBar")
                if safe_bar:
                    percent = (
                        int((safe_count / total_checks) * 100) if total_checks else 0
                    )
                    safe_bar.setMaximum(100)
                    safe_bar.setValue(percent)

                # 결과 시간 업데이트
                time_label = window.findChild(QtWidgets.QLabel, "lblResultTime")
                if time_label:
                    ts = results.get("integration_metadata", {}).get("timestamp")
                    try:
                        dt = datetime.fromisoformat(ts.replace('Z', '')) if ts else datetime.now()
                    except Exception:
                        dt = datetime.now()
                    
                    time_label.setText(
                        dt.strftime("%Y. %m. %d. %H:%M (결과 전송 완료)")
                    )

                logger.info(
                    f"최근 점검 결과 업데이트 (AI 기반): 안전 {safe_count}건, 취약 {high_risk_count}건, 총 {total_checks}건"
                )

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
            metadata = results.get("integration_metadata", {})
            total_findings = metadata.get("total_rule_findings", 0)
            total_issues = metadata.get("total_ai_issues", 0)
            
            msg_box = QtWidgets.QMessageBox()
            msg_box.setIcon(QtWidgets.QMessageBox.Icon.Information)
            msg_box.setWindowTitle("분석 완료")
            msg_box.setText("🎉 EDR 보안 분석이 완료되었습니다!")
            timestamp_iso = results.get("ai_analysis", {}).get("timestamp")
            if timestamp_iso:
                ts = datetime.fromisoformat(timestamp_iso.replace("Z", "")).strftime(
                    "%Y%m%d_%H%M%S"
                )
                report_path = f"output/reports/{ts}"
            else:
                report_path = "output/reports"
            msg_box.setInformativeText(
                f"• 룰 기반 탐지: {total_findings}개 발견\n"
                f"• AI 보안 이슈: {total_issues}개 발견\n"
                f"• 결과는 {report_path}/ 폴더에 저장되었습니다.",
            )
            msg_box.exec()
        
        # 버튼 클릭 이벤트 연결
        btn.clicked.connect(on_start_analysis)

    # UI 로드 후
    ReportViewer.attach_live_result_time(win)  # 날짜/시간 실시간

    btn_html = win.findChild(QtWidgets.QPushButton, "btnHTML")
    if btn_html:
        # 초기에는 비활성화
        btn_html.setEnabled(False)
        btn_html.setToolTip("분석 완료 후 종합 보고서를 확인할 수 있습니다")
        
        
        def open_comprehensive_report():
            """가장 최신 통합 리포트를 브라우저에서 열기"""
            try:
                import glob
                import webbrowser
                import os
                
                # 가장 최신 통합 리포트 찾기
                report_pattern = "output/reports/*/integrated_report.html"
                reports = glob.glob(report_pattern)
                
                if not reports:
                    # 분석 결과가 없는 경우
                    msg_box = QtWidgets.QMessageBox()
                    msg_box.setIcon(QtWidgets.QMessageBox.Icon.Information)
                    msg_box.setWindowTitle("보고서 없음")
                    msg_box.setText("아직 분석 보고서가 생성되지 않았습니다.")
                    msg_box.setInformativeText(
                        "'분석 시작' 버튼을 클릭하여 보안 분석을 먼저 실행해주세요."
                    )
                    msg_box.exec()
                    return
                
                # 가장 최신 파일 (생성 시간 기준)
                latest_report = max(reports, key=os.path.getctime)
                
                # 브라우저로 열기
                abs_path = os.path.abspath(latest_report)
                webbrowser.open(f"file://{abs_path}")
                
                logger.info(f"통합 보고서 열기: {latest_report}")
                
            except Exception as e:
                logger.error(f"보고서 열기 실패: {e}")
                msg_box = QtWidgets.QMessageBox()
                msg_box.setIcon(QtWidgets.QMessageBox.Icon.Critical)
                msg_box.setWindowTitle("오류")
                msg_box.setText("보고서를 열 수 없습니다.")
                msg_box.setDetailedText(str(e))
                msg_box.exec()

        btn_html.clicked.connect(open_comprehensive_report)
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

