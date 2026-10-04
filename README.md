# Python Network Scanner

A beginner-to-intermediate cybersecurity project developed in Python on Kali Linux.

## Project Overview

This project is a TCP network scanner designed to identify open and closed ports on a target system in an authorized testing environment.

The scanner can:

- Scan a custom TCP port range
- Detect open and closed ports
- Identify common services
- Grab service banners
- Use multiple worker threads for faster scanning
- Measure scan duration
- Generate TXT scan reports
- Generate JSON scan reports
- Provide basic scan statistics

## Technologies Used

- Python 3
- Kali Linux
- TCP/IP networking
- Python socket library
- ThreadPoolExecutor
- JSON
- Linux terminal

## Features

### 1. Port Scanning

The scanner attempts TCP connections to ports within the selected range.

Example:

```bash
python3 scanner.py 127.0.0.1 --start 8000 --end 8100
