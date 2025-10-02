#!/bin/bash
# PesapalHTTP Server Launcher
# Quick script to start the server with common options

echo "🚀 PesapalHTTP Server Launcher"
echo "=============================="
echo

# Default values
HOST="localhost"
PORT="8080"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--host HOST] [--port PORT]"
            echo
            echo "Options:"
            echo "  --host HOST    Server host (default: localhost)"
            echo "  --port PORT    Server port (default: 8080)"
            echo "  --help, -h     Show this help message"
            echo
            echo "Examples:"
            echo "  $0                           # Run on localhost:8080"
            echo "  $0 --port 3000             # Run on localhost:3000"
            echo "  $0 --host 0.0.0.0 --port 80 # Run on all interfaces, port 80"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "Starting PesapalHTTP Server..."
echo "Host: $HOST"
echo "Port: $PORT"
echo
echo "📁 Files in current directory:"
ls -la *.py 2>/dev/null || echo "No Python files found!"
echo

# Check if server file exists
if [[ ! -f "pesapal_http_server.py" ]]; then
    echo "❌ Error: pesapal_http_server.py not found!"
    echo "   Make sure you're in the correct directory."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1)
echo "🐍 Python version: $PYTHON_VERSION"

# Start the server
echo "🚀 Starting server on http://$HOST:$PORT"
echo "   Press Ctrl+C to stop"
echo

python3 pesapal_http_server.py --host "$HOST" --port "$PORT"
