import re
import json
from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict
import logging

class LogAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = {
            'timestamp': r'\[(.*?)\]',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'error': r'error|exception|failed|failure|warning',
            'auth': r'login|logout|auth|authentication|password',
            'attack': r'attack|exploit|injection|xss|csrf|overflow'
        }
        
    def analyze_log(self, content: str, options=None) -> Dict[str, Any]:
        try:
            # Initialize result structure
            result = {
                'total_lines': 0,
                'patterns_found': {'error': []},
                'threats_detected': {},
                'timeline': [],
                'statistics': {
                    'hourly_activity': defaultdict(int),
                    'error_types': defaultdict(int),
                    'auth_events': defaultdict(int)
                }
            }

            lines = content.splitlines()
            result['total_lines'] = len(lines)

            # Process each line
            for line in lines:
                # Skip empty lines
                if not line.strip():
                    continue

                # Find errors
                if re.search(self.patterns['error'], line, re.IGNORECASE):
                    result['patterns_found']['error'].append(line.strip())

                # Detect threats
                threats = self._detect_threats([line])
                for threat_type, threat_list in threats.items():
                    if threat_type not in result['threats_detected']:
                        result['threats_detected'][threat_type] = []
                    result['threats_detected'][threat_type].extend(threat_list)

                # Extract timestamp and build timeline
                timestamp = self._extract_timestamp(line)
                if timestamp:
                    result['timeline'].append({
                        'timestamp': timestamp.isoformat(),
                        'message': line.strip(),
                        'type': self._classify_event(line)
                    })

                    # Update hourly activity
                    hour = timestamp.strftime('%H:00')
                    result['statistics']['hourly_activity'][hour] += 1

                # Update statistics
                if re.search(self.patterns['error'], line, re.IGNORECASE):
                    error_type = self._classify_error(line)
                    result['statistics']['error_types'][error_type] += 1

                if re.search(self.patterns['auth'], line, re.IGNORECASE):
                    auth_type = self._classify_auth_event(line)
                    result['statistics']['auth_events'][auth_type] += 1

            # Sort timeline
            result['timeline'].sort(key=lambda x: x['timestamp'])

            # Convert defaultdict to regular dict for JSON serialization
            result['statistics']['hourly_activity'] = dict(result['statistics']['hourly_activity'])
            result['statistics']['error_types'] = dict(result['statistics']['error_types'])
            result['statistics']['auth_events'] = dict(result['statistics']['auth_events'])

            return result

        except Exception as e:
            self.logger.error(f"Log analysis failed: {str(e)}")
            raise

    def _gather_statistics(self, lines: List[str]) -> Dict[str, Any]:
        stats = {
            'ip_addresses': defaultdict(int),
            'error_types': defaultdict(int),
            'auth_events': defaultdict(int),
            'hourly_activity': defaultdict(int)
        }
        
        for line in lines:
            # IP addresses
            ips = re.findall(self.patterns['ip_address'], line)
            for ip in ips:
                stats['ip_addresses'][ip] += 1
            
            # Error types
            if re.search(self.patterns['error'], line, re.I):
                error_type = self._classify_error(line)
                stats['error_types'][error_type] += 1
            
            # Auth events
            if re.search(self.patterns['auth'], line, re.I):
                event_type = self._classify_auth_event(line)
                stats['auth_events'][event_type] += 1
            
            # Hourly activity
            timestamp = self._extract_timestamp(line)
            if timestamp:
                hour = timestamp.strftime('%H:00')
                stats['hourly_activity'][hour] += 1
        
        return stats

    def _detect_threats(self, lines: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        threats = defaultdict(list)
        
        for line in lines:
            # SQL Injection attempts
            if re.search(r"('|--|\b(select|insert|update|delete)\b.*\b(from|into|where)\b)", line, re.I):
                threats['sql_injection'].append({
                    'line': line,
                    'timestamp': self._extract_timestamp(line)
                })
            
            # XSS attempts
            if re.search(r"(<script>|javascript:|onerror=|onload=)", line, re.I):
                threats['xss'].append({
                    'line': line,
                    'timestamp': self._extract_timestamp(line)
                })
            
            # Brute force attempts
            if re.search(r"(failed login|invalid password|authentication failure)", line, re.I):
                threats['brute_force'].append({
                    'line': line,
                    'timestamp': self._extract_timestamp(line)
                })
        
        return threats

    def _create_timeline(self, lines: List[str]) -> List[Dict[str, Any]]:
        timeline = []
        
        for line in lines:
            timestamp = self._extract_timestamp(line)
            if not timestamp:
                continue
                
            event_type = self._classify_event(line)
            timeline.append({
                'timestamp': timestamp.isoformat(),
                'type': event_type,
                'message': line
            })
        
        return sorted(timeline, key=lambda x: x['timestamp'])

    def _extract_timestamp(self, line: str) -> datetime:
        match = re.search(self.patterns['timestamp'], line)
        if match:
            try:
                return datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return None
        return None

    def _classify_event(self, line: str) -> str:
        if re.search(self.patterns['error'], line, re.I):
            return 'error'
        if re.search(self.patterns['auth'], line, re.I):
            return 'auth'
        if re.search(self.patterns['attack'], line, re.I):
            return 'attack'
        return 'info'

    def _classify_error(self, line: str) -> str:
        if 'login' in line.lower():
            return 'login_error'
        if 'sql' in line.lower():
            return 'sql_error'
        if 'database' in line.lower():
            return 'database_error'
        if 'xss' in line.lower():
            return 'xss_error'
        return 'general_error'

    def _classify_auth_event(self, line: str) -> str:
        if 'login successful' in line.lower():
            return 'successful_login'
        if 'failed login' in line.lower():
            return 'failed_login'
        if 'logout' in line.lower():
            return 'logout'
        return 'other_auth'
