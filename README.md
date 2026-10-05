# Python Network Scanner

A beginner-to-intermediate cybersecurity project developed in Python on Kali Linux.

## Project Overview

Python Network Scanner is a TCP network scanning tool developed to help understand network reconnaissance, TCP connections, service identification, banner grabbing, multithreaded scanning, and basic security reporting.

The project was built as a practical cybersecurity learning project and tested in controlled environments, including a local Kali Linux system and an intentionally vulnerable Metasploitable 2 virtual machine.

> **Ethical Use:** This scanner should only be used against systems that you own or systems for which you have explicit permission to perform security testing.

---

## Project Objectives

The main objectives of this project are to:

- Understand TCP port scanning
- Identify open and closed ports
- Identify common network services
- Collect basic service banners
- Improve Python networking skills
- Implement multithreaded scanning
- Generate structured scan reports
- Practice cybersecurity reconnaissance in a controlled environment

---

## Technologies Used

- Python 3
- Kali Linux
- TCP/IP networking
- Python `socket` library
- `ThreadPoolExecutor`
- JSON
- Linux Terminal
- Git
- GitHub

---

## Features

### 1. TCP Port Scanning

The scanner attempts TCP connections to ports within a selected range.

Example:

```bash
python3 scanner.py 127.0.0.1 --start 8000 --end 8100
