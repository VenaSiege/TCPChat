# Technology Stack

## Language & Runtime

- Python 3.6+
- Standard library only (no external dependencies)

## Core Libraries

- `socket`: TCP networking
- `threading`: Concurrent client handling
- `datetime`: Message timestamps

## Architecture

- Server: Multi-threaded TCP server with broadcast pattern
- Client: Dual-threaded (send/receive) TCP client
- Protocol: Plain text over TCP, UTF-8 encoding
- Buffer size: 1024 bytes
- Default port: 5000

## Common Commands

### Running the Application

**Start Server:**
```bash
python server.py
```

**Start Client:**
```bash
python client.py
```

**Windows Shortcuts:**
- `run_server.bat` or `run_server.ps1` - Launch server
- `run_client.bat` or `run_client.ps1` - Launch client

### Configuration

Configuration values are documented in `config.ini` (currently not loaded by code, serves as reference).

## Platform Notes

- Cross-platform (Windows/Linux/macOS)
- Windows users may need `chcp 65001` for UTF-8 support in cmd
- PowerShell recommended for better Unicode handling
