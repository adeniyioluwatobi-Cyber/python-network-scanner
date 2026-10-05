#!/usr/bin/env python3

import socket
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# Expanded common port-to-service mapping
COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "syslog",
    515: "LPD",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP",
    8443: "HTTPS",
}


def get_service(port):
    """Return the known service name for a port."""
    return COMMON_SERVICES.get(port, "Unknown")


def grab_banner(target, port, timeout):
    """Try to collect a service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))

            service = get_service(port)

            # Send a simple HTTP request to HTTP services
            if service in ("HTTP", "HTTPS"):
                request = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode())

            else:
                # Give services that send their own banner a chance
                sock.settimeout(1)

            data = sock.recv(1024)

            if data:
                banner = data.decode("utf-8", errors="ignore")
                banner = banner.replace("\r", " ").replace("\n", " ")
                return banner[:300].strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return "No banner detected"


def scan_port(target, port, timeout):
    """Scan a single TCP port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:
                service = get_service(port)
                banner = grab_banner(target, port, timeout)

                return {
                    "port": port,
                    "status": "OPEN",
                    "service": service,
                    "banner": banner,
                }

            return {
                "port": port,
                "status": "CLOSED",
                "service": get_service(port),
                "banner": None,
            }

    except socket.timeout:
        return {
            "port": port,
            "status": "TIMEOUT",
            "service": get_service(port),
            "banner": None,
        }

    except OSError as error:
        return {
            "port": port,
            "status": "ERROR",
            "service": get_service(port),
            "banner": str(error),
        }


def save_results(results, filename="scan_results.json"):
    """Save scan results as JSON."""
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)


def save_text_results(results, filename="scan_results.txt"):
    """Save scan results as readable text."""
    with open(filename, "w") as file:
        file.write("PYTHON NETWORK SCANNER RESULTS\n")
        file.write("=" * 50 + "\n\n")

        for result in results["open_ports"]:
            file.write(f"Port: {result['port']}\n")
            file.write(f"Status: {result['status']}\n")
            file.write(f"Service: {result['service']}\n")
            file.write(f"Banner: {result['banner']}\n")
            file.write("-" * 50 + "\n")

        file.write("\nSCAN SUMMARY\n")
        file.write("=" * 50 + "\n")
        file.write(f"Ports scanned: {results['ports_scanned']}\n")
        file.write(f"Open: {results['open']}\n")
        file.write(f"Closed: {results['closed']}\n")
        file.write(f"Timeouts: {results['timeouts']}\n")
        file.write(f"Errors: {results['errors']}\n")
        file.write(f"Time taken: {results['time_taken']} seconds\n")


def main():
    parser = argparse.ArgumentParser(
        description="Python Network Scanner with Banner Grabbing"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Starting port (default: 1)"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="Ending port (default: 1024)"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds (default: 0.5)"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Number of scanning workers (default: 50)"
    )

    args = parser.parse_args()

    if args.start < 1 or args.end > 65535:
        print("[-] Port range must be between 1 and 65535.")
        return

    if args.start > args.end:
        print("[-] Start port cannot be greater than end port.")
        return

    print("=" * 50)
    print("       PYTHON NETWORK SCANNER v1.1")
    print("=" * 50)
    print(f"Target:  {args.target}")
    print(f"Ports:   {args.start}-{args.end}")
    print(f"Timeout: {args.timeout}s")
    print(f"Workers: {args.workers}")
    print()

    start_time = time.time()

    ports = range(args.start, args.end + 1)
    results_list = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:

        futures = {
            executor.submit(
                scan_port,
                args.target,
                port,
                args.timeout
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()
            results_list.append(result)

    results_list.sort(key=lambda x: x["port"])

    open_ports = [
        result for result in results_list
        if result["status"] == "OPEN"
    ]

    closed_ports = [
        result for result in results_list
        if result["status"] == "CLOSED"
    ]

    timeout_ports = [
        result for result in results_list
        if result["status"] == "TIMEOUT"
    ]

    error_ports = [
        result for result in results_list
        if result["status"] == "ERROR"
    ]

    elapsed = time.time() - start_time

    results = {
        "target": args.target,
        "port_range": f"{args.start}-{args.end}",
        "timeout": args.timeout,
        "workers": args.workers,
        "ports_scanned": len(results_list),
        "open": len(open_ports),
        "closed": len(closed_ports),
        "timeouts": len(timeout_ports),
        "errors": len(error_ports),
        "time_taken": round(elapsed, 4),
        "open_ports": open_ports,
    }

    print("OPEN PORTS")
    print("-" * 50)

    if open_ports:
        for result in open_ports:
            print(f"[+] Port {result['port']} OPEN")
            print(f"    Service: {result['service']}")
            print(f"    Banner:  {result['banner']}")
            print()
    else:
        print("No open ports found.")

    print("=" * 50)
    print("SCAN SUMMARY")
    print("-" * 50)
    print(f"Ports scanned: {len(results_list)}")
    print(f"Open:          {len(open_ports)}")
    print(f"Closed:        {len(closed_ports)}")
    print(f"Timeouts:      {len(timeout_ports)}")
    print(f"Errors:        {len(error_ports)}")
    print("-" * 50)
    print(f"Time taken:    {elapsed:.4f} seconds")
    print("=" * 50)

    save_results(results)
    save_text_results(results)

    print()
    print("Results saved to:")
    print("  scan_results.txt")
    print("  scan_results.json")


if __name__ == "__main__":
    main()
