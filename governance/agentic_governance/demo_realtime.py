#!/usr/bin/env python3
"""
Quick Demo - Real-Time Network Monitoring
Shows live network traffic detection without full monitoring loop
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from realtime.network_scanner import RealTimeNetworkScanner

def main():
    print("=" * 70)
    print(" REAL-TIME NETWORK SCANNER - Quick Demo".center(70))
    print("=" * 70)
    print()
    
    scanner = RealTimeNetworkScanner()
    
    print("[1/3] Scanning network connections...")
    connections = scanner.scan_network()
    print(f"      Found {len(connections)} active connections\n")
    
    print("[2/3] Analyzing IP statistics...")
    snapshot = scanner.get_live_snapshot()
    stats = snapshot['stats']
    
    print(f"      Active Connections: {stats['active_connections']}")
    print(f"      Unique IPs:         {stats['unique_ips']}")
    print(f"      Suspicious IPs:     {stats['suspicious_count']}")
    print(f"      Total Bytes:        {stats['total_bytes']:,}")
    print()
    
    print("[3/3] Displaying results...\n")
    
    if snapshot['active_ips']:
        print("📍 ACTIVE IP ADDRESSES:")
        print("-" * 70)
        for ip in sorted(snapshot['active_ips'])[:15]:
            details = scanner.get_ip_details(ip)
            if details:
                status = "⚠️ SUSPICIOUS" if details['suspicious'] else "✓ Normal"
                conns = details['statistics']['total_connections']
                ports = details['statistics']['unique_ports']
                print(f"  {ip:16s} │ {conns:3d} connections │ {ports:2d} ports │ {status}")
        print()
    
    if snapshot['suspicious_ips']:
        print("🚨 SUSPICIOUS IPs DETECTED:")
        print("-" * 70)
        for ip in snapshot['suspicious_ips']:
            details = scanner.get_ip_details(ip)
            if details:
                reasons = ', '.join(details['suspicion_reasons'])
                print(f"  {ip:16s} │ {reasons}")
        print()
    
    if snapshot['recent_connections']:
        print("🔄 RECENT CONNECTIONS:")
        print("-" * 70)
        print(f"  {'Source':16s} {'→':3s} {'Destination':16s} │ {'Port':6s} │ {'Protocol':8s}")
        print("-" * 70)
        for conn in snapshot['recent_connections'][:10]:
            print(f"  {conn['src_ip']:16s} → {conn['dst_ip']:16s} │ "
                  f"{conn['dst_port']:6d} │ {conn['protocol']:8s}")
        print()
    
    if not snapshot['active_ips']:
        print("⚠️  No active network connections found.")
        print("\nTo see live data:")
        print("  1. Open a web browser and visit some websites")
        print("  2. Run: ping google.com")
        print("  3. Run: curl https://api.github.com")
        print("  4. Start any network application")
        print("\nThen run this demo again to see real-time traffic!")
        print()
    
    print("=" * 70)
    print(" For full monitoring, run: python realtime/monitor.py")
    print("=" * 70)


if __name__ == "__main__":
    main()
