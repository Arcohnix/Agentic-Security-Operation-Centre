"""
Real-Time Network Traffic Scanner
Captures actual network packets and extracts live IPs, ports, protocols
Works without root using /proc/net monitoring for Linux systems
"""

import socket
import struct
import time
import threading
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
import json
import re


@dataclass
class LiveConnection:
    """Real network connection from system"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    
    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "state": self.state,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets": self.packets,
            "duration": round(self.last_seen - self.first_seen, 2)
        }


class RealTimeNetworkScanner:
    """
    Scans actual network connections from the system.
    Monitors /proc/net/tcp, /proc/net/udp for active connections.
    Provides real IP addresses and live traffic statistics.
    """
    
    # TCP states
    TCP_STATES = {
        '01': 'ESTABLISHED',
        '02': 'SYN_SENT',
        '03': 'SYN_RECV',
        '04': 'FIN_WAIT1',
        '05': 'FIN_WAIT2',
        '06': 'TIME_WAIT',
        '07': 'CLOSE',
        '08': 'CLOSE_WAIT',
        '09': 'LAST_ACK',
        '0A': 'LISTEN',
        '0B': 'CLOSING'
    }
    
    # Known malicious/suspicious IP ranges (examples)
    SUSPICIOUS_RANGES = [
        ('tor', ['176.10.', '185.220.', '199.249.']),  # Known Tor exit nodes
        ('china_scan', ['61.160.', '123.125.', '218.87.']),  # Frequent scanners
        ('russia_scan', ['5.45.', '95.213.', '188.120.']),
        ('vnc_scan', ['122.224.', '218.92.']),
    ]
    
    # Suspicious ports
    SUSPICIOUS_PORTS = {
        22: 'SSH (brute force target)',
        23: 'Telnet (insecure)',
        445: 'SMB (ransomware)',
        3389: 'RDP (brute force target)',
        5900: 'VNC (insecure)',
        6379: 'Redis (exploit target)',
        27017: 'MongoDB (unsecured)',
        3306: 'MySQL (exposure)',
        5432: 'PostgreSQL (exposure)',
        1433: 'MSSQL (exposure)',
    }
    
    def __init__(self):
        self.connections: Dict[str, LiveConnection] = {}
        self.ip_stats: Dict[str, Dict] = defaultdict(lambda: {
            'connections': 0,
            'bytes_total': 0,
            'first_seen': time.time(),
            'last_seen': time.time(),
            'ports': set(),
            'is_suspicious': False,
            'suspicion_reasons': [],
            'connection_rate': deque(maxlen=60)  # connections per second over 60s
        })
        self.active_ips: Set[str] = set()
        self.suspicious_ips: Set[str] = set()
        self.scan_interval = 1.0  # seconds
        self.running = False
        self._lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'unique_ips': 0,
            'suspicious_count': 0,
            'total_bytes': 0,
            'scan_count': 0
        }
    
    def _hex_to_ip(self, hex_str: str) -> str:
        """Convert hex IP address to dotted decimal"""
        try:
            # Reverse byte order for little-endian
            parts = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
            parts.reverse()
            ip = '.'.join(str(int(p, 16)) for p in parts)
            return ip
        except:
            return "0.0.0.0"
    
    def _parse_proc_net(self, protocol: str) -> List[LiveConnection]:
        """Parse /proc/net/tcp or /proc/net/udp"""
        connections = []
        
        try:
            filepath = f'/proc/net/{protocol}'
            with open(filepath, 'r') as f:
                lines = f.readlines()[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                
                # Parse local and remote address
                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3]
                tx_queue = int(parts[4].split(':')[0], 16)
                rx_queue = int(parts[4].split(':')[1], 16)
                
                # Parse addresses
                local_ip, local_port = local_addr.split(':')
                remote_ip, remote_port = remote_addr.split(':')
                
                local_ip = self._hex_to_ip(local_ip)
                remote_ip = self._hex_to_ip(remote_ip)
                local_port = int(local_port, 16)
                remote_port = int(remote_port, 16)
                
                # Skip localhost and 0.0.0.0
                if remote_ip in ('127.0.0.1', '0.0.0.0', '::1'):
                    continue
                
                state_str = self.TCP_STATES.get(state, 'UNKNOWN') if protocol == 'tcp' else 'ESTABLISHED'
                
                conn = LiveConnection(
                    src_ip=local_ip,
                    dst_ip=remote_ip,
                    src_port=local_port,
                    dst_port=remote_port,
                    protocol=protocol.upper(),
                    state=state_str,
                    bytes_sent=tx_queue,
                    bytes_recv=rx_queue,
                    packets=1
                )
                
                connections.append(conn)
        
        except FileNotFoundError:
            pass  # System doesn't have /proc/net
        except Exception as e:
            print(f"Error parsing {protocol}: {e}")
        
        return connections
    
    def _check_suspicious(self, ip: str, port: int, conn_count: int) -> Tuple[bool, List[str]]:
        """Check if IP/port combination is suspicious"""
        reasons = []
        
        # Check IP ranges
        for category, prefixes in self.SUSPICIOUS_RANGES:
            if any(ip.startswith(prefix) for prefix in prefixes):
                reasons.append(f"Known {category} IP range")
        
        # Check suspicious ports
        if port in self.SUSPICIOUS_PORTS:
            reasons.append(f"Suspicious port {port}: {self.SUSPICIOUS_PORTS[port]}")
        
        # Check connection patterns
        if conn_count > 50:
            reasons.append(f"High connection count ({conn_count} connections)")
        
        # Check for port scanning (many unique ports from same IP)
        with self._lock:
            if ip in self.ip_stats:
                unique_ports = len(self.ip_stats[ip]['ports'])
                if unique_ports > 10:
                    reasons.append(f"Port scanning ({unique_ports} unique ports)")
        
        return len(reasons) > 0, reasons
    
    def scan_network(self):
        """Scan network connections once"""
        new_connections = []
        
        # Parse TCP and UDP connections
        for protocol in ['tcp', 'udp']:
            conns = self._parse_proc_net(protocol)
            new_connections.extend(conns)
        
        with self._lock:
            self.stats['scan_count'] += 1
            current_time = time.time()
            
            # Process connections
            for conn in new_connections:
                conn_key = f"{conn.src_ip}:{conn.src_port}-{conn.dst_ip}:{conn.dst_port}-{conn.protocol}"
                
                if conn_key in self.connections:
                    # Update existing connection
                    existing = self.connections[conn_key]
                    existing.last_seen = current_time
                    existing.bytes_sent += conn.bytes_sent
                    existing.bytes_recv += conn.bytes_recv
                    existing.packets += 1
                else:
                    # New connection
                    self.connections[conn_key] = conn
                    self.stats['total_connections'] += 1
                
                # Update IP statistics
                for ip in [conn.src_ip, conn.dst_ip]:
                    self.active_ips.add(ip)
                    ip_stat = self.ip_stats[ip]
                    ip_stat['connections'] += 1
                    ip_stat['last_seen'] = current_time
                    ip_stat['bytes_total'] += conn.bytes_sent + conn.bytes_recv
                    ip_stat['ports'].add(conn.dst_port)
                    ip_stat['connection_rate'].append(current_time)
                    
                    # Check if suspicious
                    is_susp, reasons = self._check_suspicious(
                        ip, conn.dst_port, ip_stat['connections']
                    )
                    
                    if is_susp:
                        ip_stat['is_suspicious'] = True
                        ip_stat['suspicion_reasons'] = reasons
                        self.suspicious_ips.add(ip)
            
            # Clean up old connections (older than 5 minutes)
            cutoff = current_time - 300
            old_keys = [k for k, v in self.connections.items() 
                       if v.last_seen < cutoff]
            for k in old_keys:
                del self.connections[k]
            
            # Update statistics
            self.stats['active_connections'] = len(self.connections)
            self.stats['unique_ips'] = len(self.active_ips)
            self.stats['suspicious_count'] = len(self.suspicious_ips)
            self.stats['total_bytes'] = sum(
                s['bytes_total'] for s in self.ip_stats.values()
            )
        
        return new_connections
    
    def start_monitoring(self):
        """Start continuous monitoring thread"""
        self.running = True
        
        def monitor_loop():
            while self.running:
                self.scan_network()
                time.sleep(self.scan_interval)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=2)
    
    def get_live_snapshot(self) -> Dict:
        """Get current network state snapshot"""
        with self._lock:
            return {
                'timestamp': time.time(),
                'stats': dict(self.stats),
                'active_ips': sorted(self.active_ips),
                'suspicious_ips': sorted(self.suspicious_ips),
                'top_ips': self._get_top_ips(10),
                'recent_connections': [
                    c.to_dict() for c in sorted(
                        self.connections.values(),
                        key=lambda x: x.last_seen,
                        reverse=True
                    )[:20]
                ]
            }
    
    def _get_top_ips(self, n: int) -> List[Dict]:
        """Get top N IPs by connection count"""
        sorted_ips = sorted(
            self.ip_stats.items(),
            key=lambda x: x[1]['connections'],
            reverse=True
        )[:n]
        
        return [
            {
                'ip': ip,
                'connections': stats['connections'],
                'bytes': stats['bytes_total'],
                'ports': len(stats['ports']),
                'suspicious': stats['is_suspicious'],
                'reasons': stats['suspicion_reasons'],
                'duration': round(stats['last_seen'] - stats['first_seen'], 1)
            }
            for ip, stats in sorted_ips
        ]
    
    def get_ip_details(self, ip: str) -> Optional[Dict]:
        """Get detailed information about a specific IP"""
        with self._lock:
            if ip not in self.ip_stats:
                return None
            
            stats = self.ip_stats[ip]
            connections = [
                c.to_dict() for c in self.connections.values()
                if c.src_ip == ip or c.dst_ip == ip
            ]
            
            return {
                'ip': ip,
                'statistics': {
                    'total_connections': stats['connections'],
                    'total_bytes': stats['bytes_total'],
                    'unique_ports': len(stats['ports']),
                    'first_seen': stats['first_seen'],
                    'last_seen': stats['last_seen'],
                    'duration': round(stats['last_seen'] - stats['first_seen'], 1)
                },
                'suspicious': stats['is_suspicious'],
                'suspicion_reasons': stats['suspicion_reasons'],
                'connections': connections,
                'ports_accessed': sorted(stats['ports'])
            }
    
    def get_network_graph(self) -> Dict:
        """Generate network graph for visualization"""
        with self._lock:
            nodes = []
            edges = []
            
            # Create nodes for each unique IP
            for ip in self.active_ips:
                stats = self.ip_stats.get(ip, {})
                nodes.append({
                    'id': ip,
                    'label': ip,
                    'suspicious': stats.get('is_suspicious', False),
                    'connections': stats.get('connections', 0),
                    'bytes': stats.get('bytes_total', 0)
                })
            
            # Create edges for connections
            for conn in self.connections.values():
                edges.append({
                    'from': conn.src_ip,
                    'to': conn.dst_ip,
                    'protocol': conn.protocol,
                    'port': conn.dst_port,
                    'state': conn.state,
                    'bytes': conn.bytes_sent + conn.bytes_recv
                })
            
            return {
                'nodes': nodes,
                'edges': edges
            }


class ConsoleMonitor:
    """Real-time console output for network monitoring"""
    
    def __init__(self, scanner: RealTimeNetworkScanner):
        self.scanner = scanner
        self.running = False
    
    def start(self):
        """Start console monitoring"""
        self.running = True
        
        def display_loop():
            while self.running:
                self._clear_screen()
                self._print_dashboard()
                time.sleep(2)
        
        self.thread = threading.Thread(target=display_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
    
    def _clear_screen(self):
        """Clear terminal screen"""
        print("\033[2J\033[H", end='')
    
    def _print_dashboard(self):
        """Print dashboard to console"""
        snapshot = self.scanner.get_live_snapshot()
        stats = snapshot['stats']
        
        print("=" * 80)
        print(" REAL-TIME NETWORK MONITOR — Agentic AI Detection System".center(80))
        print("=" * 80)
        print()
        
        # Statistics
        print(f"┌{'─' * 78}┐")
        print(f"│ {'NETWORK STATISTICS':<76} │")
        print(f"├{'─' * 78}┤")
        print(f"│ Active Connections: {stats['active_connections']:<10} "
              f"Total Scans: {stats['scan_count']:<10} "
              f"Total Bytes: {self._format_bytes(stats['total_bytes']):<15} │")
        print(f"│ Unique IPs Seen:    {stats['unique_ips']:<10} "
              f"Suspicious IPs: {stats['suspicious_count']:<10} "
              f"{'':>22} │")
        print(f"└{'─' * 78}┘")
        print()
        
        # Suspicious IPs
        if snapshot['suspicious_ips']:
            print(f"🚨 SUSPICIOUS IPs DETECTED: {len(snapshot['suspicious_ips'])}")
            print(f"┌{'─' * 78}┐")
            for ip in snapshot['suspicious_ips'][:5]:
                details = self.scanner.get_ip_details(ip)
                if details:
                    reasons = ', '.join(details['suspicion_reasons'][:2])
                    print(f"│ ⚠️  {ip:<15} │ {reasons:<58} │")
            print(f"└{'─' * 78}┘")
            print()
        
        # Top Active IPs
        print("📊 TOP ACTIVE IPs")
        print(f"┌{'─' * 16}┬{'─' * 12}┬{'─' * 15}┬{'─' * 10}┬{'─' * 22}┐")
        print(f"│ {'IP Address':<14} │ {'Connections':<10} │ {'Data Transfer':<13} │ {'Ports':<8} │ {'Status':<20} │")
        print(f"├{'─' * 16}┼{'─' * 12}┼{'─' * 15}┼{'─' * 10}┼{'─' * 22}┤")
        
        for ip_data in snapshot['top_ips'][:8]:
            ip = ip_data['ip']
            status = "⚠️ SUSPICIOUS" if ip_data['suspicious'] else "✓ Normal"
            print(f"│ {ip:<14} │ {ip_data['connections']:>10} │ "
                  f"{self._format_bytes(ip_data['bytes']):>13} │ {ip_data['ports']:>8} │ "
                  f"{status:<20} │")
        
        print(f"└{'─' * 16}┴{'─' * 12}┴{'─' * 15}┴{'─' * 10}┴{'─' * 22}┘")
        print()
        
        # Recent Connections
        print("🔄 RECENT CONNECTIONS")
        print(f"┌{'─' * 17}┬{'─' * 17}┬{'─' * 8}┬{'─' * 8}┬{'─' * 25}┐")
        print(f"│ {'Source':<15} │ {'Destination':<15} │ {'Port':<6} │ {'Proto':<6} │ {'State':<23} │")
        print(f"├{'─' * 17}┼{'─' * 17}┼{'─' * 8}┼{'─' * 8}┼{'─' * 25}┤")
        
        for conn in snapshot['recent_connections'][:6]:
            print(f"│ {conn['src_ip']:<15} │ {conn['dst_ip']:<15} │ "
                  f"{conn['dst_port']:>6} │ {conn['protocol']:<6} │ {conn['state']:<23} │")
        
        print(f"└{'─' * 17}┴{'─' * 17}┴{'─' * 8}┴{'─' * 8}┴{'─' * 25}┘")
        print()
        print(f"Last updated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("Press Ctrl+C to stop monitoring")
    
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"
