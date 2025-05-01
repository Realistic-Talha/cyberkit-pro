import socket
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import json
import nmap
import re
from typing import Dict, List, Union, Tuple

class PortScanner:
    def __init__(self):
        self.target = None
        self.ports = []
        self.results = []
        self.nm = nmap.PortScanner()
        self.common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
            3306: 'MYSQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }

    def validate_target(self, target: str) -> bool:
        """Validate target IP address or hostname."""
        # IP address pattern
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        
        return bool(re.match(ip_pattern, target) or re.match(hostname_pattern, target))

    def validate_port_range(self, port_range: str) -> Tuple[int, int]:
        """Validate and parse port range string."""
        try:
            start_port, end_port = map(int, port_range.split('-'))
            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                raise ValueError("Ports must be between 0 and 65535")
            if start_port > end_port:
                raise ValueError("Start port must be less than end port")
            return start_port, end_port
        except ValueError as e:
            raise ValueError(f"Invalid port range format: {str(e)}")

    def _check_port(self, port: int) -> dict:
        """Check if a port is open and get basic service info."""
        result = {
            'port': port,
            'state': 'closed',
            'service': 'unknown',
            'version': '',
            'product': ''
        }

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)  # Increased timeout for more reliable results
        
        try:
            conn_result = sock.connect_ex((self.target, port))
            if conn_result == 0:
                result['state'] = 'open'
                result['service'] = self.common_ports.get(port, 'unknown')
                print(f"Port {port} is open")  # Add logging
        except (socket.timeout, socket.error) as e:
            print(f"Error checking port {port}: {str(e)}")  # Add logging
        finally:
            sock.close()
        
        return result

    def _scan_with_nmap(self, open_ports: List[int]) -> Dict:
        """Perform detailed scan of open ports using nmap."""
        if not open_ports:
            return {}

        ports_str = ','.join(map(str, open_ports))
        try:
            self.nm.scan(self.target, ports_str, arguments='-sV -sS --version-intensity 5')
            return self.nm[self.target].get('tcp', {})
        except Exception as e:
            print(f"Nmap scan failed: {str(e)}")
            return {}

    def scan(self, target: str, port_range: str) -> Dict:
        """Scan target IP/domain for open ports."""
        try:
            print(f"Starting scan for {target} on ports {port_range}")  # Add logging
            self.results = []  # Reset results for new scan
            
            # Validate input
            if not self.validate_target(target):
                raise ValueError(f"Invalid target format: {target}")
            
            start_port, end_port = self.validate_port_range(port_range)
            
            # Resolve domain to IP
            try:
                self.target = socket.gethostbyname(target)
                print(f"Resolved target to {self.target}")  # Add logging
            except socket.gaierror:
                raise ValueError(f"Could not resolve hostname: {target}")

            # Initial fast TCP scan
            open_ports_info = []
            with ThreadPoolExecutor(max_workers=min(50, end_port - start_port + 1)) as executor:
                print(f"Scanning ports {start_port}-{end_port}")  # Add logging
                port_results = list(executor.map(
                    self._check_port, 
                    range(start_port, end_port + 1)
                ))
                open_ports_info = [r for r in port_results if r['state'] == 'open']
                open_ports = [r['port'] for r in open_ports_info]
                print(f"Found {len(open_ports)} open ports")  # Add logging

            # Detailed scan with nmap for open ports
            if open_ports:
                print(f"Running nmap scan on open ports")  # Add logging
                nmap_results = self._scan_with_nmap(open_ports)
            else:
                nmap_results = {}

            # Merge TCP and nmap results
            for port_info in open_ports_info:
                port = port_info['port']
                if port in nmap_results:
                    nmap_service = nmap_results[port]
                    port_info.update({
                        'service': nmap_service.get('name', port_info['service']),
                        'version': nmap_service.get('version', ''),
                        'product': nmap_service.get('product', '')
                    })
                self.results.append(port_info)

            scan_result = {
                'target': self.target,
                'ports_scanned': end_port - start_port + 1,
                'open_ports': len(open_ports),
                'scan_results': self.results
            }
            print(f"Scan completed: {scan_result}")  # Add logging
            return scan_result

        except ValueError as e:
            print(f"Validation error: {str(e)}")  # Add logging
            raise
        except Exception as e:
            print(f"Scan error: {str(e)}")  # Add logging
            raise RuntimeError(f"Scan failed: {str(e)}")
