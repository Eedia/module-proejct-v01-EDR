"""
EDR 분석 백그라운드 워커
UI 블로킹 없이 분석 실행
"""

import sys
import os
from PyQt6.QtCore import QThread, pyqtSignal
import logging

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger(__name__)

class EDRAnalysisWorker(QThread):
    """EDR 분석을 백그라운드에서 실행하는 워커"""
    
    # 시그널 정의
    progress_updated = pyqtSignal(int, str)      # 진행률(%), 메시지
    analysis_completed = pyqtSignal(dict)        # 분석 결과
    error_occurred = pyqtSignal(str)             # 에러 메시지
    
    def __init__(self):
        super().__init__()
        self.is_cancelled = False
    
    def run(self):
        """워커 스레드 메인 실행 함수"""
        try:
            logger.info("🚀 EDR 분석 워커 시작")
            
            # 진행률 업데이트
            self.progress_updated.emit(5, "분석 초기화 중...")
            
            # core 모듈에서 통합 분석 함수 import
            from core.integrated_analyzer import run_integrated_scan
            
            if self.is_cancelled:
                return
                
            self.progress_updated.emit(10, "이벤트 로그 수집 시작...")
            
            # 실제 EDR 분석 실행
            logger.info("통합 EDR 분석 실행 중...")
            results = run_integrated_scan()
            
            if self.is_cancelled:
                return
                
            self.progress_updated.emit(100, "분석 완료!")
            
            # 결과 전달
            logger.info("분석 완료, 결과 전달")
            self.analysis_completed.emit(results)
            
        except ImportError as e:
            error_msg = f"모듈 임포트 실패: {e}"
            logger.error(error_msg)
            self.error_occurred.emit(error_msg)
            
        except Exception as e:
            error_msg = f"분석 중 오류 발생: {e}"
            logger.error(error_msg)
            self.error_occurred.emit(error_msg)
    
    def cancel_analysis(self):
        """분석 취소"""
        self.is_cancelled = True
        logger.info("분석 취소 요청됨")


class ProgressTracker:
    """분석 진행률 추적 헬퍼"""
    
    STAGES = [
        (5, "분석 초기화"),
        (15, "이벤트 로그 수집"),
        (30, "레지스트리 분석"), 
        (45, "보안 설정 점검"),
        (60, "룰 기반 탐지 실행"),
        (75, "AI 보안 분석"),
        (90, "결과 통합 중"),
        (100, "분석 완료")
    ]
    
    @classmethod
    def get_stage_info(cls, stage_index):
        """스테이지 인덱스로 진행률과 메시지 반환"""
        if 0 <= stage_index < len(cls.STAGES):
            return cls.STAGES[stage_index]
        return (100, "완료")
