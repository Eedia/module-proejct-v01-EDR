"""
evtx/collector.py
Windows 이벤트 로그 수집기

"""

import subprocess
import json
import re
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
import locale

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EventLogCollector:
    """Windows 이벤트 로그 수집기"""
    
    def __init__(self, time_range_hours: int = 24):
        self.time_range_hours = time_range_hours
        self.target_channels = {
            "Security": [4688, 4624, 4625, 4634, 4647, 4672, 4697, 4719],
            "System": [7045, 7036, 1100, 1102, 104],
            "Microsoft-Windows-PowerShell/Operational": [4104, 4103],
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": [21, 24, 25, 40, 41, 42],
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": [261, 1149]
        }
        
        # 수집 시작 시간 계산
        self.start_time = datetime.now() - timedelta(hours=time_range_hours)
        
    def collect_security_events(self) -> List[Dict[str, Any]]:
        """Security 채널에서 주요 이벤트 수집"""
        logger.info("Collecting Security events...")
        
        target_event_ids = self.target_channels.get("Security", [])
        return self._collect_events_by_channel("Security", target_event_ids)
    
    def collect_system_events(self) -> List[Dict[str, Any]]:
        """System 채널에서 서비스 관련 이벤트 수집"""
        logger.info("Collecting System events...")
        
        target_event_ids = self.target_channels.get("System", [])
        return self._collect_events_by_channel("System", target_event_ids)
    
    def collect_powershell_events(self) -> List[Dict[str, Any]]:
        """PowerShell 채널에서 의심 활동 수집"""
        logger.info("Collecting PowerShell events...")
        
        target_event_ids = self.target_channels.get("Microsoft-Windows-PowerShell/Operational", [])
        return self._collect_events_by_channel("Microsoft-Windows-PowerShell/Operational", target_event_ids)
    
    def collect_rdp_events(self) -> List[Dict[str, Any]]:
        """RDP 관련 이벤트 수집"""
        logger.info("Collecting RDP events...")
        
        rdp_events = []
        
        # Terminal Services Local Session Manager
        local_session_events = self._collect_events_by_channel(
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            self.target_channels.get("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", [])
        )
        rdp_events.extend(local_session_events)
        
        # Terminal Services Remote Connection Manager
        remote_connection_events = self._collect_events_by_channel(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            self.target_channels.get("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", [])
        )
        rdp_events.extend(remote_connection_events)
        
        return rdp_events
    
    def collect_all_target_events(self) -> List[Dict[str, Any]]:
        """모든 대상 이벤트를 수집"""
        logger.info(f"Starting event collection for last {self.time_range_hours} hours...")
        
        all_events = []
        
        try:
            # Security 이벤트
            all_events.extend(self.collect_security_events())
            
            # System 이벤트  
            all_events.extend(self.collect_system_events())
            
            # PowerShell 이벤트
            all_events.extend(self.collect_powershell_events())
            
            # RDP 이벤트
            all_events.extend(self.collect_rdp_events())
            
            logger.info(f"Total events collected: {len(all_events)}")
            
            # 시간순으로 정렬
            all_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            return all_events
            
        except Exception as e:
            logger.error(f"Error collecting events: {e}")
            return []
    def _decode_output(self, data: bytes) -> str:
        """wevtutil 출력의 인코딩을 자동으로 감지하여 문자열로 반환"""
        if not data:
            return ""

        encodings = ["utf-16le", locale.getpreferredencoding(False), "utf-8"]
        for enc in encodings:
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="ignore")

    def _collect_events_by_channel(self, channel: str, event_ids: List[int]) -> List[Dict[str, Any]]:
        """특정 채널에서 이벤트 ID 목록으로 이벤트 수집"""
        if not event_ids:
            return []
        
        events = []
        
        try:
            # 시간 필터 생성 (최근 N시간)
            start_time_str = self.start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            # 이벤트 ID 필터 생성
            event_id_filter = " or ".join([f"EventID={eid}" for eid in event_ids])
            
            # wevtutil 쿼리 구성
            query = f"*[System[TimeCreated[@SystemTime>='{start_time_str}'] and ({event_id_filter})]]"
            
            # wevtutil 명령어 실행
            cmd = [
                'wevtutil', 'qe', channel,
                f'/q:"{query}"',
                '/f:xml',
                '/rd:true'
            ]
 
            print("********Executing command:", ' '.join(cmd))

            logger.debug(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True, text=True, timeout=300)

            # stdout = result.stdout.decode("utf-16le", errors="ignore") if result.stdout else ""
            # stderr = result.stderr.decode("utf-16le", errors="ignore") if result.stderr else ""
            print("stdout:", result.stdout)
            print("stderr:", result.stderr)
            stdout = self._decode_output(result.stdout)
            stderr = self._decode_output(result.stderr)
            if result.returncode != 0:
                logger.warning(f"wevtutil returned error for {channel}: {stderr or None}")
                return []
            
            if not stdout.strip():
                logger.info(f"No events found in {channel}")
                return []
            
            # XML 파싱
            events = self._parse_events_xml(stdout, channel)

            logger.info(f"Collected {len(events)} events from {channel}")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout while collecting events from {channel}")
        except Exception as e:
            logger.error(f"Error collecting events from {channel}: {e}")
        
        return events
    
    def _parse_events_xml(self, xml_content: str, channel: str) -> List[Dict[str, Any]]:
        """XML 이벤트 데이터를 파싱하여 정규화된 딕셔너리로 변환"""
        events = []
        
        try:
            # XML 래핑 (wevtutil 출력은 루트 엘리먼트가 없음)
            wrapped_xml = f"<Events>{xml_content}</Events>"
            
            root = ET.fromstring(wrapped_xml)
            
            for event_elem in root.findall('.//Event'):
                try:
                    event_data = self._parse_single_event(event_elem, channel)
                    if event_data:
                        events.append(event_data)
                except Exception as e:
                    logger.warning(f"Error parsing individual event: {e}")
                    continue
        
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing events: {e}")
        
        return events
    
    def _parse_single_event(self, event_elem: ET.Element, channel: str) -> Optional[Dict[str, Any]]:
        """단일 이벤트 XML을 파싱"""
        try:
            # System 정보 추출
            system = event_elem.find('.//System')
            if system is None:
                return None
            
            # 기본 정보
            event_id = system.find('EventID').text if system.find('EventID') is not None else "0"
            
            time_created = system.find('TimeCreated')
            timestamp = time_created.get('SystemTime') if time_created is not None else ""
            
            computer = system.find('Computer').text if system.find('Computer') is not None else ""
            
            # EventData 추출
            event_data_elem = event_elem.find('.//EventData')
            event_data = {}
            
            if event_data_elem is not None:
                for data in event_data_elem.findall('Data'):
                    name = data.get('Name', f'Data_{len(event_data)}')
                    value = data.text if data.text else ""
                    event_data[name] = value
            
            # UserData 추출 (일부 이벤트에서 사용)
            user_data_elem = event_elem.find('.//UserData')
            if user_data_elem is not None:
                for child in user_data_elem:
                    if child.tag and child.text:
                        event_data[child.tag] = child.text
            
            # 정규화된 이벤트 객체 생성
            normalized_event = {
                "channel": channel,
                "event_id": int(event_id),
                "timestamp": self._format_timestamp(timestamp),
                "computer": computer,
                "raw_xml": ET.tostring(event_elem, encoding='unicode'),
                "event_data": event_data
            }
            
            # 이벤트 유형별 특수 처리
            self._enrich_event_data(normalized_event)
            
            return normalized_event
            
        except Exception as e:
            logger.warning(f"Error parsing single event: {e}")
            return None
    
    def _enrich_event_data(self, event: Dict[str, Any]):
        """이벤트 유형별 데이터 보강"""
        event_id = event.get("event_id")
        event_data = event.get("event_data", {})
        
        # 프로세스 생성 이벤트 (4688)
        if event_id == 4688:
            event["process_name"] = event_data.get("NewProcessName", "")
            event["command_line"] = event_data.get("CommandLine", "")
            event["parent_process"] = event_data.get("ParentProcessName", "")
            event["user"] = event_data.get("SubjectUserName", "")
            event["process_id"] = event_data.get("NewProcessId", "")
            event["parent_process_id"] = event_data.get("ProcessId", "")
        
        # 로그온 이벤트 (4624, 4625)
        elif event_id in [4624, 4625]:
            event["user"] = event_data.get("TargetUserName", "")
            event["logon_type"] = event_data.get("LogonType", "")
            event["source_ip"] = event_data.get("IpAddress", "")
            event["workstation"] = event_data.get("WorkstationName", "")
            event["logon_process"] = event_data.get("LogonProcessName", "")
        
        # 서비스 설치 이벤트 (7045)
        elif event_id == 7045:
            event["service_name"] = event_data.get("ServiceName", "")
            event["service_file_name"] = event_data.get("ImagePath", "")
            event["service_type"] = event_data.get("ServiceType", "")
            event["service_start_type"] = event_data.get("StartType", "")
            event["account_name"] = event_data.get("AccountName", "")
        
        # PowerShell 스크립트 블록 (4104)
        elif event_id == 4104:
            event["script_block"] = event_data.get("ScriptBlockText", "")
            event["script_id"] = event_data.get("ScriptBlockId", "")
            event["path"] = event_data.get("Path", "")
        
        # RDP 세션 이벤트 (21, 24, 25)
        elif event_id in [21, 24, 25]:
            event["session_id"] = event_data.get("SessionID", "")
            event["user"] = event_data.get("User", "")
            event["source_ip"] = event_data.get("Address", "")
    
    def _format_timestamp(self, timestamp_str: str) -> str:
        """타임스탬프를 ISO 8601 형식으로 변환"""
        if not timestamp_str:
            return ""
        
        try:
            # Windows 이벤트 로그 타임스탬프 파싱
            if 'T' in timestamp_str and 'Z' in timestamp_str:
                return timestamp_str
            else:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        except Exception as e:
            logger.warning(f"Error formatting timestamp {timestamp_str}: {e}")
            return timestamp_str
    
    def get_collection_statistics(self) -> Dict[str, Any]:
        """수집 통계 정보 반환"""
        stats = {
            "time_range_hours": self.time_range_hours,
            "start_time": self.start_time.isoformat(),
            "target_channels": list(self.target_channels.keys()),
            "total_target_event_ids": sum(len(ids) for ids in self.target_channels.values())
        }
        return stats

# 전역 수집기 인스턴스
event_collector = EventLogCollector()

def collect_security_events(time_range_hours: int = 24) -> List[Dict[str, Any]]:
    """전역 함수로 Security 이벤트 수집"""
    collector = EventLogCollector(time_range_hours)
    return collector.collect_security_events()

def collect_system_events(time_range_hours: int = 24) -> List[Dict[str, Any]]:
    """전역 함수로 System 이벤트 수집"""
    collector = EventLogCollector(time_range_hours)
    return collector.collect_system_events()

def collect_powershell_events(time_range_hours: int = 24) -> List[Dict[str, Any]]:
    """전역 함수로 PowerShell 이벤트 수집"""
    collector = EventLogCollector(time_range_hours)
    return collector.collect_powershell_events()

def collect_all_target_events(time_range_hours: int = 24) -> List[Dict[str, Any]]:
    """전역 함수로 모든 대상 이벤트 수집"""
    collector = EventLogCollector(time_range_hours)
    return collector.collect_all_target_events()
