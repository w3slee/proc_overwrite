# Process Overwriting Implementation in Golang 🛡️

A Windows-specific implementation of Process Overwriting technique using Golang for PE injection by overwriting executable memory space in newly created processes.

**Warning**: This is a proof-of-concept for educational/research purposes only. Use responsibly and comply with all applicable laws.

## Features ✨
- Creates suspended processes with CFG bypass
- Performs PE image overwriting in memory
- Handles base relocations automatically
- Updates thread entry points dynamically
- Supports payloads up to original image size

## Prerequisites 📋
- Windows 7/10/11 (x64)
- Golang 1.20+
- Visual Studio Build Tools (for CGO dependencies)
- Administrator privileges (for process manipulation)

## Installation ⚙️
```bash
git clone https://github.com/yourusername/process-overwriting-go.git
cd process-overwriting-go
go mod download
go build -ldflags="-H=windowsgui" -o process-overwriter.exe
