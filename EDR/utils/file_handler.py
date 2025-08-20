"""
utils/file_handler.py
파일 입출력 및 리포트 생성 처리
"""

import json
import os
import csv
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FileHandler:
    """파일 입출력 처리 클래스"""
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.ensure_output_directories()
    
    def ensure_output_directories(self):
        """출력 디렉토리 생성"""
        directories = [
            self.output_dir,
            self.output_dir / "scan_results",
            self.output_dir / "reports", 
            self.output_dir / "scripts"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def save_findings_json(self, scan_results: Dict[str, Any], scan_id: str = None) -> str:
        """findings.json 파일 저장"""
        if not scan_id:
            scan_id = scan_results.get("scan_metadata", {}).get("scan_id", "unknown")
        
        filename = f"{scan_id}_findings.json"
        filepath = self.output_dir / "scan_results" / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Findings saved to: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error saving findings JSON: {e}")
            raise
    
    def load_findings_json(self, filepath: str) -> Dict[str, Any]:
        """findings.json 파일 로드"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading findings JSON: {e}")
            raise
    
    def export_findings_to_csv(self, findings: List[Dict[str, Any]], scan_id: str) -> str:
        """Finding 목록을 CSV로 내보내기"""
        filename = f"{scan_id}_findings.csv"
        filepath = self.output_dir / "scan_results" / filename
        
        if not findings:
            logger.warning("No findings to export to CSV")
            return str(filepath)
        
        # CSV 헤더 정의
        headers = [
            "Finding ID", "Rule ID", "Severity", "Category", "Title", 
            "Description", "Confidence", "Score Impact", "Timestamp",
            "Evidence Source", "Evidence Details"
        ]
        
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                
                for finding in findings:
                    # 증거 정보 추출
                    evidence = finding.get("evidence", {})
                    primary_event = evidence.get("primary_event", {})
                    
                    evidence_details = ""
                    if primary_event:
                        evidence_details = f"Event ID: {primary_event.get('event_id', 'N/A')}, " \
                                         f"Process: {primary_event.get('process_name', 'N/A')}, " \
                                         f"User: {primary_event.get('user', 'N/A')}"
                    
                    row = [
                        finding.get("finding_id", ""),
                        finding.get("rule_id", ""),
                        finding.get("severity", ""),
                        finding.get("category", ""),
                        finding.get("title", ""),
                        finding.get("description", "")[:100] + "..." if len(finding.get("description", "")) > 100 else finding.get("description", ""),
                        finding.get("confidence", ""),
                        finding.get("score_impact", ""),
                        primary_event.get("timestamp", ""),
                        primary_event.get("source", ""),
                        evidence_details
                    ]
                    writer.writerow(row)
            
            logger.info(f"Findings CSV exported to: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error exporting findings to CSV: {e}")
            raise
    
    def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """HTML 리포트 생성"""
        scan_id = scan_results.get("scan_metadata", {}).get("scan_id", "unknown")
        filename = f"{scan_id}_report.html"
        filepath = self.output_dir / "reports" / filename
        
        # 데이터 추출
        metadata = scan_results.get("scan_metadata", {})
        summary = scan_results.get("scan_summary", {})
        findings = scan_results.get("findings", [])
        ai_recommendations = scan_results.get("ai_recommendations", {})
        
        # Finding HTML 생성
        findings_html = ""
        for i, finding in enumerate(findings):
            evidence = finding.get("evidence", {})
            primary_event = evidence.get("primary_event", {})
            
            # 증거 테이블 생성
            evidence_html = "<table class='evidence-table'>"
            evidence_html += "<tr><th>항목</th><th>값</th></tr>"
            
            if primary_event:
                evidence_html += f"<tr><td>이벤트 ID</td><td>{primary_event.get('event_id', 'N/A')}</td></tr>"
                evidence_html += f"<tr><td>시간</td><td>{primary_event.get('timestamp', 'N/A')}</td></tr>"
                evidence_html += f"<tr><td>컴퓨터</td><td>{primary_event.get('computer', 'N/A')}</td></tr>"
                evidence_html += f"<tr><td>프로세스</td><td>{primary_event.get('process_name', 'N/A')}</td></tr>"
                evidence_html += f"<tr><td>명령줄</td><td>{primary_event.get('command_line', 'N/A')}</td></tr>"
                evidence_html += f"<tr><td>사용자</td><td>{primary_event.get('user', 'N/A')}</td></tr>"
            
            evidence_html += "</table>"
            
            finding_html = f"""
            <div class="finding severity-{finding.get('severity', 'info')}">
                <div class="finding-header" onclick="toggleFinding({i})">
                    <div class="finding-title">{finding.get('title', '')}</div>
                    <div class="finding-meta">
                        {finding.get('severity', '').upper()} | {finding.get('category', '')} | 
                        신뢰도: {finding.get('confidence', 0)}% | 점수영향: {finding.get('score_impact', 0)}점
                    </div>
                </div>
                <div class="finding-details" id="details-{i}">
                    <p><strong>설명:</strong> {finding.get('description', '')}</p>
                    <p><strong>룰 ID:</strong> {finding.get('rule_id', '')}</p>
                    <h4>증거 정보</h4>
                    {evidence_html}
                </div>
            </div>
            """
            findings_html += finding_html
        
        # AI 추천사항 HTML 생성
        ai_recommendations_html = ""
        if ai_recommendations:
            ai_recommendations_html = """
            <div class="ai-recommendations">
                <h3>AI 추천 조치사항</h3>
            """
            
            for category, actions in ai_recommendations.items():
                if actions:
                    ai_recommendations_html += f"<h4>{category.replace('_', ' ').title()}</h4>"
                    for action in actions:
                        ai_recommendations_html += f'<div class="recommendation-item">• {action}</div>'
            
            ai_recommendations_html += "</div>"
        
        # 심각도별 카운트
        severity_counts = summary.get("findings_by_severity", {})
        
        # HTML 생성
        html_content = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EDR 스캔 리포트 - {scan_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ border-bottom: 3px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #007bff; margin: 0; }}
        .header .meta {{ color: #666; margin-top: 10px; }}
        .score-card {{ background: {self._get_risk_color(summary.get('total_score', 0))}; color: white; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 30px; }}
        .score-card .score {{ font-size: 48px; font-weight: bold; }}
        .score-card .level {{ font-size: 24px; margin-top: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-item {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .summary-item .number {{ font-size: 32px; font-weight: bold; color: #007bff; }}
        .summary-item .label {{ color: #666; margin-top: 5px; }}
        .findings {{ margin-top: 30px; }}
        .finding {{ background: #fff; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 15px; }}
        .finding-header {{ padding: 15px; background: #f8f9fa; border-bottom: 1px solid #dee2e6; cursor: pointer; }}
        .finding-header:hover {{ background: #e9ecef; }}
        .finding-title {{ font-weight: bold; margin-bottom: 5px; }}
        .finding-meta {{ color: #666; font-size: 14px; }}
        .severity-critical {{ border-left: 5px solid #dc3545; }}
        .severity-high {{ border-left: 5px solid #fd7e14; }}
        .severity-medium {{ border-left: 5px solid #ffc107; }}
        .severity-low {{ border-left: 5px solid #20c997; }}
        .severity-info {{ border-left: 5px solid #6f42c1; }}
        .finding-details {{ padding: 15px; display: none; }}
        .evidence-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        .evidence-table th, .evidence-table td {{ padding: 8px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        .evidence-table th {{ background-color: #f8f9fa; }}
        .ai-recommendations {{ background: #e3f2fd; padding: 15px; border-radius: 8px; margin-top: 30px; }}
        .ai-recommendations h3 {{ color: #1976d2; margin-top: 0; }}
        .recommendation-item {{ margin-bottom: 10px; padding: 10px; background: white; border-radius: 4px; }}
    </style>
    <script>
        function toggleFinding(id) {{
            var details = document.getElementById('details-' + id);
            if (details.style.display === 'none' || details.style.display === '') {{
                details.style.display = 'block';
            }} else {{
                details.style.display = 'none';
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EDR 보안 스캔 리포트</h1>
            <div class="meta">
                <strong>스캔 ID:</strong> {scan_id}<br>
                <strong>호스트명:</strong> {metadata.get('hostname', 'Unknown')}<br>
                <strong>스캔 시간:</strong> {metadata.get('timestamp', 'Unknown')}<br>
                <strong>스캔 소요시간:</strong> {metadata.get('scan_duration_seconds', 0):.1f}초
            </div>
        </div>
        
        <div class="score-card">
            <div class="score">{summary.get('total_score', 0)}점</div>
            <div class="level">위험도: {summary.get('risk_level', '알 수 없음')}</div>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="number">{summary.get('total_findings', 0)}</div>
                <div class="label">총 탐지 항목</div>
            </div>
            <div class="summary-item">
                <div class="number">{severity_counts.get('critical', 0)}</div>
                <div class="label">심각</div>
            </div>
            <div class="summary-item">
                <div class="number">{severity_counts.get('high', 0)}</div>
                <div class="label">높음</div>
            </div>
            <div class="summary-item">
                <div class="number">{severity_counts.get('medium', 0)}</div>
                <div class="label">중간</div>
            </div>
            <div class="summary-item">
                <div class="number">{severity_counts.get('low', 0)}</div>
                <div class="label">낮음</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>탐지 결과 상세</h2>
            {findings_html}
        </div>
        
        {ai_recommendations_html}
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #666; text-align: center;">
            <small>Generated by EDR-Scanner v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
        </div>
    </div>
</body>
</html>"""
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            raise
    
    def _get_risk_color(self, score: int) -> str:
        """점수를 기반으로 색상 코드 반환"""
        if score >= 90:
            return "#28a745"  # 녹색
        elif score >= 70:
            return "#ffc107"  # 노랑
        else:
            return "#dc3545"  # 빨강
    
    def save_powershell_script(self, script_content: str, scan_id: str, script_type: str = "remediation") -> str:
        """PowerShell 스크립트 저장"""
        filename = f"{scan_id}_{script_type}.ps1"
        filepath = self.output_dir / "scripts" / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(script_content)
            
            logger.info(f"PowerShell script saved: {filepath}")
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error saving PowerShell script: {e}")
            raise

# 전역 파일 핸들러 인스턴스
file_handler = FileHandler()

def save_findings_json(scan_results: Dict[str, Any], scan_id: str = None) -> str:
    """전역 함수로 findings.json 저장"""
    return file_handler.save_findings_json(scan_results, scan_id)

def load_findings_json(filepath: str) -> Dict[str, Any]:
    """전역 함수로 findings.json 로드"""
    return file_handler.load_findings_json(filepath)

def generate_html_report(scan_results: Dict[str, Any]) -> str:
    """전역 함수로 HTML 리포트 생성"""
    return file_handler.generate_html_report(scan_results)
