"""
Real-Time Network Monitoring - Main Entry Point
Launches network scanner, console monitor, and web dashboard
Shows live IPs, detects suspicious activity, visualizes network graph
"""

import sys
import os
import time
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_scanner import RealTimeNetworkScanner, ConsoleMonitor
from dashboard import start_dashboard_server


def main():
    print("=" * 80)
    print(" AGENTIC AI REAL-TIME NETWORK MONITOR".center(80))
    print(" Live IP Detection | Suspicious Activity | Network Visualization".center(80))
    print("=" * 80)
    print()
    
    # Initialize scanner
    print("[+] Initializing network scanner...")
    scanner = RealTimeNetworkScanner()
    
    # Start monitoring
    print("[+] Starting network traffic monitoring...")
    scanner.start_monitoring()
    
    # Wait for initial scan
    time.sleep(2)
    
    # Check if we have data
    initial_snapshot = scanner.get_live_snapshot()
    if initial_snapshot['stats']['unique_ips'] == 0:
        print("\n⚠️  No network connections detected yet.")
        print("    This system monitors /proc/net/tcp and /proc/net/udp")
        print("    Try:")
        print("    - Opening a web browser and visiting some websites")
        print("    - Running: ping google.com")
        print("    - Running: curl https://api.github.com")
        print("    - Starting any network application\n")
    
    # Ask user for interface preference
    print("\nSelect monitoring interface:")
    print("  1. Console Dashboard (text-based, live updates)")
    print("  2. Web Dashboard (browser-based, network graph)")
    print("  3. Both (recommended)")
    
    choice = input("\nEnter choice (1/2/3) [default: 3]: ").strip() or "3"
    
    console = None
    server = None
    
    if choice in ['1', '3']:
        print("\n[+] Starting console monitor...")
        console = ConsoleMonitor(scanner)
        console.start()
    
    if choice in ['2', '3']:
        print("\n[+] Starting web dashboard server...")
        server = start_dashboard_server(scanner, port=8080)
    
    # Setup graceful shutdown
    def signal_handler(sig, frame):
        print("\n\n[!] Shutting down...")
        scanner.stop_monitoring()
        if console:
            console.stop()
        print("[✓] Shutdown complete")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Main loop
    try:
        if choice == '1':
            # Console only - just wait
            while True:
                time.sleep(1)
        elif choice == '2':
            # Web only - print stats periodically
            while True:
                snapshot = scanner.get_live_snapshot()
                stats = snapshot['stats']
                print(f"\r[{time.strftime('%H:%M:%S')}] "
                      f"Active: {stats['active_connections']:3d} | "
                      f"IPs: {stats['unique_ips']:3d} | "
                      f"Suspicious: {stats['suspicious_count']:2d} | "
                      f"Scans: {stats['scan_count']:4d}", end='', flush=True)
                time.sleep(2)
        else:
            # Both - console handles display
            while True:
                time.sleep(1)
    
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
