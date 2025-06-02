Vanta: Lightweight Behavioral Packet Analyzer

Author: lixiasky
Version: 1.0
License: Apache 2.0


---

Project Overview

Vanta is a lightweight, fast, command-line-based network behavior analyzer. It reconstructs protocol-level flows and extracts structured activity from captured data.

Unlike full-featured GUI tools like Wireshark, Vanta focuses on clarity, structure, and simplicity — ideal for custom scripting and minimal setups.


---

Features

Protocol-Level Parsing

Supports HTTP, DNS, TLS (with partial fingerprinting)


Connection Tracking

Automatically reconstructs bidirectional flows


Behavior Exporting

Outputs clean JSON-formatted summaries


Portable & Dependency-Free

Single binary, no external dependencies




---

Quick Start (See usage/ folder for full guide)

go run main.go

Refer to the usage folder for complete usage documentation in Chinese.


---

Development Environment

OS: macOS 15.5 (Apple Silicon)

Editor: Visual Studio Code

Language: Go

Go Module: go 1.23.0

Toolchain: go1.24.3

Terminal: zsh (macOS default)


> Developed and tested entirely on a MacBook Air M1 by an undergraduate student, as a personal expression of thanks.




---

Project Structure


## Project Structure

- `main.go` — Main entry point
- `capture.json` — Example input file
- `internal/`
  - `core/` — Packet capture and flow reassembly
  - `decoder/` — Protocol decoders
  - `fuzz/` — Fuzzing module (experimental)
  - `export/` — Behavior exporting logic
- `usage/` — Usage documentation
---

Why I Built This

This project is not just code — it's a response. Amid political pressure, some universities like Harvard, MIT, and CMU stood up for international students.

> I’m just an ordinary undergraduate with no resources or background. This is my way of responding — not by petition, but through code. Vanta may be small, but it’s real, and it’s mine.



I know Vanta is a "toy version" of Wireshark — I still use Wireshark myself in real scenarios. 


---

Thanks to Professors and Schools

Thank you for standing up for students.

This project might not be perfect, but it is heartfelt.

If you are willing to review, share, or offer feedback:

Email: lixiasky@protonmail.com
GitHub: github.com/lixiasky
