# Python SS Tool 
Run With  **python -c "import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/fineting/Python-SS-Tool/main/scanner.py').read().decode())"**

Isnt Meant to be used for ssing someone just using this tool , this is just a vibecoded one.

New Command to install python if not installed

**powershell -Command "if (-not (Get-Command python -ErrorAction SilentlyContinue)) { iwr https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe -OutFile $env:TEMP\py.exe; Start-Process $env:TEMP\py.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait }; python -c \"import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/fineting/Python-SS-Tool/main/scanner.py').read().decode())\""**
