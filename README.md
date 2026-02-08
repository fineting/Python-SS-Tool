# Python SS Tool

A lightweight, vibecoded Python-based tool.

This project is **not intended to be used for screensharing or inspecting someone else**.  
It exists purely as an *experimental / educational tool*.

---

## Requirements

- Windows
- Python 3.12+ *(optional — auto-installed if missing)*

---

## Quick Run (Python Already Installed)

Run the tool directly with:

```bash
python -c "import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/fineting/Python-SS-Tool/main/scanner.py').read().decode())"
One-Command Setup (Installs Python if Missing)
This single command will:

Install Python silently if it is not installed

Run the tool immediately

Run from Command Prompt (cmd.exe):

powershell -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Get-Command python -ErrorAction SilentlyContinue)) { iwr https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe -OutFile $env:TEMP\py.exe; Start-Process $env:TEMP\py.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait }; python -c \"import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/fineting/Python-SS-Tool/main/scanner.py').read().decode())\""
Disclaimer
This tool is not meant for misuse, monitoring others, or bypassing privacy.
Use responsibly and only on systems you own or have permission to test.

Credits
Inspired by PowerShell scripts from:
https://github.com/HadronCollision/PowershellScripts
