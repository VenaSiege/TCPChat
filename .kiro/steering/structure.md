# Project Structure

## File Organization

```
/
├── server.py           # TCP chat server implementation
├── client.py           # TCP chat client implementation
├── config.ini          # Configuration reference (not loaded by code)
├── README.md           # Comprehensive documentation
├── QUICKSTART.txt      # Quick start guide
├── run_server.bat      # Windows batch script for server
├── run_server.ps1      # PowerShell script for server
├── run_client.bat      # Windows batch script for client
└── run_client.ps1      # PowerShell script for client
```

## Code Architecture

### server.py

- `ChatServer` class: Main server implementation
  - `start()`: Initialize and accept connections
  - `handle_client()`: Per-client thread handler
  - `broadcast()`: Send message to all clients
  - `remove_client()`: Clean up disconnected clients
  - `shutdown()`: Graceful server shutdown

### client.py

- `ChatClient` class: Main client implementation
  - `connect()`: Establish server connection
  - `set_username()`: User identification
  - `receive_messages()`: Background thread for incoming messages
  - `send_messages()`: Main thread for user input
  - `run()`: Orchestrate client lifecycle
  - `disconnect()`: Clean up connection

## Conventions

- Chinese language used in UI strings and comments
- Thread-safe operations use `threading.Lock()`
- Daemon threads for background tasks
- Graceful error handling with try/except blocks
- Timestamp format: `HH:MM:SS`
- Message format: `[timestamp] username: message`
- System messages: `【系统】message`
