import socket
import sys
import time
import argparse
import json
from concurrent.futures import ThreadPoolExecutor


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP"
}


HTTP_PORTS = [80, 443, 8000, 8008, 8080, 8081, 8443]


def get_http_banner(target, port, timeout):
    s = socket.socket()
    s.settimeout(timeout)

    try:
        s.connect((target, port))

        request = b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
        s.sendall(request)

        response = s.recv(1024)
        decoded = response.decode(errors="ignore")

        if decoded.startswith("HTTP/"):
            return decoded

        return ""

    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""

    finally:
        s.close()


def extract_server(banner):
    for line in banner.splitlines():
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()

    return ""


def identify_service(port, banner):
    if banner.startswith("HTTP/"):
        return "HTTP"

    return COMMON_PORTS.get(port, "Unknown")


def scan_port(target, port, timeout):
    result = {
        "port": port,
        "status": "ERROR",
        "service": "",
        "server": "",
        "error": ""
    }

    s = socket.socket()
    s.settimeout(timeout)

    try:
        s.connect((target, port))

        result["status"] = "OPEN"

        banner = ""

        if port in HTTP_PORTS:
            banner = get_http_banner(target, port, timeout)

        result["service"] = identify_service(port, banner)

        if banner:
            result["server"] = extract_server(banner)

    except socket.timeout:
        result["status"] = "TIMEOUT"

    except ConnectionRefusedError:
        result["status"] = "CLOSED"

    except OSError as e:
        result["status"] = "ERROR"
        result["error"] = str(e)

    finally:
        s.close()

    return result


def main():

    parser = argparse.ArgumentParser(
        description="Python Network Port Scanner & Service Enumeration Tool"
    )

    parser.add_argument(
        "target",
        help="Target IPv4 address"
    )

    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Starting port"
    )

    parser.add_argument(
        "--end",
        type=int,
        default=8080,
        help="Ending port"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout in seconds"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Number of concurrent workers"
    )

    parser.add_argument(
        "--common",
        action="store_true",
        help="Scan common service ports"
    )

    args = parser.parse_args()

    target = args.target

    # Validate IP address
    try:
        socket.inet_aton(target)
    except socket.error:
        print(f"Invalid IP address: {target}")
        sys.exit(1)

    # Validate port range
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Invalid port range.")
        print("Ports must be between 1 and 65535.")
        sys.exit(1)

    # Select ports
    if args.common:
        ports = list(COMMON_PORTS.keys())
        port_description = "Common service ports"
    else:
        ports = range(args.start, args.end + 1)
        port_description = f"{args.start}-{args.end}"

    print("=" * 50)
    print("       PYTHON NETWORK SCANNER")
    print("=" * 50)
    print(f"Target:  {target}")
    print(f"Ports:   {port_description}")
    print(f"Timeout: {args.timeout}s")
    print(f"Workers: {args.workers}")
    print()

    start_time = time.time()

    results = []

    # Concurrent scanning
    with ThreadPoolExecutor(max_workers=args.workers) as executor:

        tasks = [
            executor.submit(scan_port, target, port, args.timeout)
            for port in ports
        ]

        for task in tasks:
            result = task.result()
            results.append(result)

    end_time = time.time()

    # Sort results by port
    results.sort(key=lambda x: x["port"])

    # Count statuses
    open_count = sum(
        1 for r in results if r["status"] == "OPEN"
    )

    closed_count = sum(
        1 for r in results if r["status"] == "CLOSED"
    )

    timeout_count = sum(
        1 for r in results if r["status"] == "TIMEOUT"
    )

    error_count = sum(
        1 for r in results if r["status"] == "ERROR"
    )

    scan_time = end_time - start_time

    # Display open ports
    print("OPEN PORTS")
    print("-" * 50)

    for result in results:

        if result["status"] == "OPEN":

            print(f"[+] Port {result['port']} OPEN")

            if result["service"]:
                print(f"    Service: {result['service']}")

            if result["server"]:
                print(f"    Server: {result['server']}")

    # Summary
    print()
    print("=" * 50)
    print("SCAN SUMMARY")
    print("-" * 50)

    print(f"Ports scanned: {len(results)}")
    print(f"Open:          {open_count}")
    print(f"Closed:        {closed_count}")
    print(f"Timeouts:      {timeout_count}")
    print(f"Errors:        {error_count}")

    print("-" * 50)
    print(f"Time taken:    {scan_time:.2f} seconds")
    print("=" * 50)

    # Save TXT report
    with open("scan_results.txt", "w") as file:

        file.write("PYTHON NETWORK SCANNER\n")
        file.write("=" * 50 + "\n")
        file.write(f"Target: {target}\n")
        file.write(f"Ports: {port_description}\n")
        file.write(f"Timeout: {args.timeout}s\n")
        file.write(f"Workers: {args.workers}\n\n")

        file.write("OPEN PORTS\n")
        file.write("-" * 50 + "\n")

        for result in results:

            if result["status"] == "OPEN":

                file.write(
                    f"Port {result['port']} OPEN\n"
                )

                if result["service"]:
                    file.write(
                        f"Service: {result['service']}\n"
                    )

                if result["server"]:
                    file.write(
                        f"Server: {result['server']}\n"
                    )

                file.write("\n")

        file.write("SCAN SUMMARY\n")
        file.write("-" * 50 + "\n")
        file.write(f"Ports scanned: {len(results)}\n")
        file.write(f"Open: {open_count}\n")
        file.write(f"Closed: {closed_count}\n")
        file.write(f"Timeouts: {timeout_count}\n")
        file.write(f"Errors: {error_count}\n")
        file.write(f"Time taken: {scan_time:.2f} seconds\n")

    # Create JSON report
    json_report = {
        "scanner": "Python Network Port Scanner",
        "target": target,
        "ports": port_description,
        "timeout": args.timeout,
        "workers": args.workers,
        "scan_summary": {
            "ports_scanned": len(results),
            "open": open_count,
            "closed": closed_count,
            "timeouts": timeout_count,
            "errors": error_count,
            "time_taken_seconds": round(scan_time, 2)
        },
        "results": results
    }

    with open("scan_results.json", "w") as file:
        json.dump(json_report, file, indent=4)

    print()
    print("Results saved to:")
    print("  scan_results.txt")
    print("  scan_results.json")


if __name__ == "__main__":
    main()
