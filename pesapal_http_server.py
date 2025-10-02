#!/usr/bin/env python3
"""
PesapalHTTP - HTTP Server from Scratch

A complete HTTP server implementation built from scratch in Python without
using external libraries for HTTP parsing or response generation.

Features:
- Parses HTTP requests from raw bytes
- Supports HTTP/1.0 and HTTP/1.1
- Extracts all required HTTP components
- Handles request bodies with Content-Length
- Proper error handling and HTTP status codes
- Thread-based connection handling
- Robust parsing with security considerations

Usage:
    python pesapal_http_server.py [port]

Example:
    python pesapal_http_server.py 8080
"""

import socket
import threading
import re
import json
import time
import logging
import signal
import sys
from typing import Optional, Dict, Any, Union, Tuple
from enum import Enum

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class HTTPMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"


class HTTPVersion(Enum):
    HTTP_1_0 = "HTTP/1.0"
    HTTP_1_1 = "HTTP/1.1"


class HTTPStatus(Enum):
    OK = (200, "OK")
    CREATED = (201, "Created")
    BAD_REQUEST = (400, "Bad Request")
    NOT_FOUND = (404, "Not Found")
    METHOD_NOT_ALLOWED = (405, "Method Not Allowed")
    INTERNAL_SERVER_ERROR = (500, "Internal Server Error")

    def __init__(self, code: int, phrase: str):
        self.code = code
        self.phrase = phrase


class HTTPRequest:
    """
    Encapsulates an HTTP request with all parsed components.

    This class provides access to HTTP request components as required:
    - HTTP method
    - HTTP version  
    - Host header (if present)
    - Request path
    - Content-Type (if present)
    - User-Agent (if present)
    - Content-Length (if present)
    - Complete body (as string or byte array)
    """

    def __init__(self):
        self.method: Optional[str] = None
        self.path: Optional[str] = None
        self.version: Optional[str] = None
        self.headers: Dict[str, str] = {}
        self.body: Union[str, bytes] = b""
        self.raw_request: bytes = b""

    @property
    def host(self) -> Optional[str]:
        """Get Host header if present."""
        return self.headers.get('host')

    @property
    def content_type(self) -> Optional[str]:
        """Get Content-Type header if present."""
        return self.headers.get('content-type')

    @property
    def user_agent(self) -> Optional[str]:
        """Get User-Agent header if present."""
        return self.headers.get('user-agent')

    @property
    def content_length(self) -> Optional[int]:
        """Get Content-Length header if present, parsed as integer."""
        content_length = self.headers.get('content-length')
        if content_length is not None:
            try:
                return int(content_length)
            except ValueError:
                return None
        return None

    def get_body_as_string(self) -> str:
        """Get request body as string."""
        if isinstance(self.body, bytes):
            try:
                return self.body.decode('utf-8')
            except UnicodeDecodeError:
                return self.body.decode('latin1', errors='replace')
        return self.body

    def get_body_as_bytes(self) -> bytes:
        """Get request body as bytes."""
        if isinstance(self.body, str):
            return self.body.encode('utf-8')
        return self.body


class HTTPRequestParser:
    """
    Parses HTTP requests from raw bytes or plaintext.

    This parser handles HTTP/1.0 and HTTP/1.1 requests and extracts all required
    components as specified in the requirements.
    """

    # Maximum sizes to prevent DoS attacks
    MAX_REQUEST_LINE_SIZE = 8192  # 8KB for request line
    MAX_HEADER_SIZE = 65536       # 64KB for headers
    MAX_BODY_SIZE_WITHOUT_LENGTH = 8192  # 8KB if no Content-Length specified

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset parser state for new request."""
        self.state = 'request_line'
        self.buffer = b''
        self.request = HTTPRequest()
        self.headers_complete = False
        self.body_length = 0
        self.body_received = 0

    def parse(self, data: bytes) -> Optional[HTTPRequest]:
        """
        Parse HTTP request data incrementally.

        Args:
            data: Raw bytes from socket

        Returns:
            HTTPRequest object if complete request is parsed, None otherwise

        Raises:
            ValueError: If request is malformed
        """
        self.buffer += data
        self.request.raw_request += data

        while self.buffer or self.state == 'complete':
            if self.state == 'request_line':
                if not self._parse_request_line():
                    break

            elif self.state == 'headers':
                if not self._parse_headers():
                    break

            elif self.state == 'body':
                if not self._parse_body():
                    break

            elif self.state == 'complete':
                # Request is complete, return it
                complete_request = self.request
                self.reset()
                return complete_request

        return None

    def _parse_request_line(self) -> bool:
        """Parse the HTTP request line."""
        # Look for CRLF to end request line
        line_end = self.buffer.find(b'\r\n')
        if line_end == -1:
            # Check if buffer is too large
            if len(self.buffer) > self.MAX_REQUEST_LINE_SIZE:
                raise ValueError("Request line too long")
            return False

        # Extract request line
        request_line = self.buffer[:line_end].decode('ascii', errors='ignore')
        self.buffer = self.buffer[line_end + 2:]

        # Parse request line: METHOD PATH HTTP/VERSION
        parts = request_line.strip().split()
        if len(parts) != 3:
            raise ValueError(f"Invalid request line format: {request_line}")

        method, path, version = parts

        # Validate HTTP method
        if not re.match(r'^[A-Z]+$', method):
            raise ValueError(f"Invalid HTTP method: {method}")

        # Validate HTTP version
        if not re.match(r'^HTTP/1\.[01]$', version):
            raise ValueError(f"Unsupported HTTP version: {version}")

        # Store parsed values
        self.request.method = method
        self.request.path = path
        self.request.version = version

        # Move to headers parsing
        self.state = 'headers'
        return True

    def _parse_headers(self) -> bool:
        """Parse HTTP headers."""
        while True:
            # Look for end of current header line
            line_end = self.buffer.find(b'\r\n')
            if line_end == -1:
                # Check if headers section is too large
                if len(self.buffer) > self.MAX_HEADER_SIZE:
                    raise ValueError("Headers section too large")
                return False

            # Check for empty line (end of headers)
            if line_end == 0:
                self.buffer = self.buffer[2:]  # Remove CRLF
                self.headers_complete = True

                # Determine if we need to read body
                content_length = self.request.content_length
                if content_length is not None:
                    if content_length < 0:
                        raise ValueError("Invalid Content-Length: negative value")
                    if content_length > 0:
                        self.body_length = content_length
                        self.state = 'body'
                    else:
                        # Content-Length is 0, no body expected
                        self.state = 'complete'
                else:
                    # No Content-Length specified
                    # For methods that typically don't have body (GET, HEAD, DELETE, OPTIONS)
                    # assume no body. For POST, PUT, PATCH assume body up to limit
                    if self.request.method in ['GET', 'HEAD', 'DELETE', 'OPTIONS']:
                        self.state = 'complete'
                    else:
                        # Methods that may have body, read up to limit
                        self.body_length = self.MAX_BODY_SIZE_WITHOUT_LENGTH
                        if len(self.buffer) == 0:
                            # No more data available, complete request
                            self.state = 'complete'
                        else:
                            self.state = 'body'

                return True

            # Parse header line
            header_line = self.buffer[:line_end].decode('ascii', errors='ignore')
            self.buffer = self.buffer[line_end + 2:]

            # Parse header: Name: Value
            if ':' not in header_line:
                raise ValueError(f"Invalid header format: {header_line}")

            name, value = header_line.split(':', 1)
            name = name.strip().lower()
            value = value.strip()

            # Validate header name (RFC 7230)
            if not re.match(r'^[!#$%&\'*+\-.0-9A-Z^_`a-z|~]+$', name):
                raise ValueError(f"Invalid header name: {name}")

            # Store header (handle duplicates by keeping first occurrence)
            if name not in self.request.headers:
                self.request.headers[name] = value
            else:
                # For critical headers like Content-Length, reject duplicates
                if name in ['content-length', 'transfer-encoding', 'host']:
                    raise ValueError(f"Duplicate critical header: {name}")

    def _parse_body(self) -> bool:
        """Parse request body."""
        if self.request.content_length is not None:
            # Use Content-Length to determine body size
            remaining = self.body_length - self.body_received
            if len(self.buffer) >= remaining:
                # We have the complete body
                body_data = self.buffer[:remaining]
                self.buffer = self.buffer[remaining:]
                self.request.body += body_data
                self.body_received += len(body_data)
                self.state = 'complete'
                return True
            else:
                # Partial body
                self.request.body += self.buffer
                self.body_received += len(self.buffer)
                self.buffer = b''
                return False
        else:
            # No Content-Length, read available data up to limit
            available_space = self.body_length - len(self.request.body)
            if available_space <= 0:
                # Reached limit, truncate
                self.state = 'complete'
                return True

            if len(self.buffer) > 0:
                # Read up to available space
                to_read = min(len(self.buffer), available_space)
                body_data = self.buffer[:to_read]
                self.buffer = self.buffer[to_read:]
                self.request.body += body_data

                if to_read >= available_space:
                    # Reached limit
                    self.state = 'complete'
                    return True

            # If no more data in buffer and we haven't reached limit,
            # wait for more data (return False)
            return False


class HTTPResponse:
    """
    Represents an HTTP response that can be sent to clients.

    Handles proper HTTP response formatting with status line, headers, and body.
    Automatically calculates and sets Content-Length header.
    """

    def __init__(self, status: HTTPStatus = HTTPStatus.OK, 
                 body: Union[str, bytes] = "", 
                 headers: Optional[Dict[str, str]] = None,
                 version: str = "HTTP/1.1"):
        self.status = status
        self.version = version
        self.headers = headers or {}
        self.body = body

        # Set default headers
        if 'server' not in [k.lower() for k in self.headers.keys()]:
            self.headers['Server'] = 'PesapalHTTP/1.0'

        if 'date' not in [k.lower() for k in self.headers.keys()]:
            self.headers['Date'] = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())

    def set_header(self, name: str, value: str) -> None:
        """Set a response header."""
        self.headers[name] = value

    def set_body(self, body: Union[str, bytes]) -> None:
        """Set response body."""
        self.body = body

    def to_bytes(self) -> bytes:
        """
        Convert response to bytes for transmission.

        Automatically calculates and sets Content-Length header.
        """
        # Convert body to bytes if necessary
        if isinstance(self.body, str):
            body_bytes = self.body.encode('utf-8')
        else:
            body_bytes = self.body

        # Set Content-Length header
        self.headers['Content-Length'] = str(len(body_bytes))

        # Build status line
        status_line = f"{self.version} {self.status.code} {self.status.phrase}\r\n"

        # Build headers
        header_lines = ""
        for name, value in self.headers.items():
            header_lines += f"{name}: {value}\r\n"

        # Combine all parts
        response = status_line + header_lines + "\r\n"
        response_bytes = response.encode('utf-8') + body_bytes

        return response_bytes


def create_text_response(text: str, status: HTTPStatus = HTTPStatus.OK) -> HTTPResponse:
    """Create a text/plain response."""
    response = HTTPResponse(status=status, body=text)
    response.set_header('Content-Type', 'text/plain; charset=utf-8')
    return response


def create_html_response(html: str, status: HTTPStatus = HTTPStatus.OK) -> HTTPResponse:
    """Create a text/html response."""
    response = HTTPResponse(status=status, body=html)
    response.set_header('Content-Type', 'text/html; charset=utf-8')
    return response


def create_json_response(data: Any, status: HTTPStatus = HTTPStatus.OK) -> HTTPResponse:
    """Create an application/json response."""
    json_data = json.dumps(data, indent=2)
    response = HTTPResponse(status=status, body=json_data)
    response.set_header('Content-Type', 'application/json; charset=utf-8')
    return response


def create_error_response(status: HTTPStatus, message: str = None) -> HTTPResponse:
    """Create an error response with HTML body."""
    error_message = message or status.phrase
    html_body = f"""<!DOCTYPE html>
<html>
<head>
    <title>{status.code} {status.phrase}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
        h1 {{ color: #d32f2f; }}
        .error-code {{ font-size: 4em; font-weight: bold; color: #f44336; }}
        .message {{ background: #ffebee; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        hr {{ margin: 40px 0; border: none; border-top: 1px solid #ddd; }}
    </style>
</head>
<body>
    <div class="error-code">{status.code}</div>
    <h1>{status.phrase}</h1>
    <div class="message">
        <p>{error_message}</p>
    </div>
    <hr>
    <p><small>PesapalHTTP/1.0 - HTTP Server from Scratch</small></p>
</body>
</html>"""
    return create_html_response(html_body, status)


class HTTPServer:
    """
    HTTP Server implementation from scratch.

    Features:
    - Handles HTTP/1.0 and HTTP/1.1 requests
    - Parses requests without external libraries
    - Supports custom request handlers
    - Proper error handling and responses
    - Thread-based connection handling
    """

    def __init__(self, host: str = 'localhost', port: int = 8080, 
                 max_connections: int = 10):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.server_socket = None
        self.running = False
        self.handlers = {}
        self.default_handler = self._default_handler

        # Register default routes
        self.register_handler('GET', '/', self._handle_root)
        self.register_handler('GET', '/health', self._handle_health)
        self.register_handler('POST', '/echo', self._handle_echo)
        self.register_handler('GET', '/demo', self._handle_demo)

    def register_handler(self, method: str, path: str, handler):
        """Register a handler for a specific method and path."""
        key = f"{method.upper()} {path}"
        self.handlers[key] = handler
        logger.info(f"Registered handler: {key}")

    def start(self) -> None:
        """Start the HTTP server."""
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind to address
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)

            self.running = True
            logger.info(f" PesapalHTTP Server started on http://{self.host}:{self.port}")
            logger.info(" Available endpoints:")
            logger.info("   • GET  /       - Server information page")
            logger.info("   • GET  /health - Health check endpoint")  
            logger.info("   • POST /echo   - Echo request data")
            logger.info("   • GET  /demo   - API demonstration")
            logger.info("  Press Ctrl+C to stop the server")

            # Set up signal handler for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)

            # Main server loop
            while self.running:
                try:
                    # Accept client connection
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f" Connection from {client_address}")

                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()

                except OSError:
                    if self.running:
                        logger.error("Socket error occurred")
                    break

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the HTTP server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("  Server stopped")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signal."""
        logger.info("\n Received interrupt signal, shutting down gracefully")
        self.stop()
        sys.exit(0)

    def _handle_client(self, client_socket: socket.socket, client_address) -> None:
        """Handle individual client connection."""
        try:
            parser = HTTPRequestParser()
            client_socket.settimeout(30.0)  # 30 second timeout

            while True:
                try:
                    # Receive data
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    # Parse request
                    request = parser.parse(data)
                    if request:
                        logger.info(f" {request.method} {request.path} from {client_address}")

                        # Process request and generate response
                        response = self._process_request(request)

                        # Send response
                        response_bytes = response.to_bytes()
                        client_socket.sendall(response_bytes)

                        logger.info(f" {response.status.code} {response.status.phrase} to {client_address}")

                        # For HTTP/1.0 or Connection: close, break after response
                        if (request.version == "HTTP/1.0" or 
                            request.headers.get('connection', '').lower() == 'close'):
                            break

                        # Reset parser for next request on same connection
                        parser.reset()

                except socket.timeout:
                    logger.warning(f" Timeout for client {client_address}")
                    break
                except ValueError as e:
                    logger.warning(f" Bad request from {client_address}: {e}")
                    error_response = create_error_response(HTTPStatus.BAD_REQUEST, str(e))
                    client_socket.sendall(error_response.to_bytes())
                    break
                except Exception as e:
                    logger.error(f" Error processing request from {client_address}: {e}")
                    error_response = create_error_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                    try:
                        client_socket.sendall(error_response.to_bytes())
                    except:
                        pass
                    break

        finally:
            try:
                client_socket.close()
            except:
                pass
            logger.info(f" Connection closed for {client_address}")

    def _process_request(self, request: HTTPRequest) -> HTTPResponse:
        """Process HTTP request and return response."""
        try:
            # Find handler
            handler_key = f"{request.method} {request.path}"
            if handler_key in self.handlers:
                return self.handlers[handler_key](request)
            else:
                return self.default_handler(request)

        except Exception as e:
            logger.error(f"Handler error: {e}")
            return create_error_response(HTTPStatus.INTERNAL_SERVER_ERROR)

    def _default_handler(self, request: HTTPRequest) -> HTTPResponse:
        """Default handler for unregistered routes."""
        return create_error_response(HTTPStatus.NOT_FOUND, 
                                   f"Resource '{request.path}' not found")

    def _handle_root(self, request: HTTPRequest) -> HTTPResponse:
        """Handle GET / requests."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PesapalHTTP Server</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 40px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .logo {{ font-size: 3em; font-weight: bold; color: #2196F3; margin-bottom: 10px; }}
        .tagline {{ color: #666; font-size: 1.2em; }}
        .info {{ background: #e3f2fd; padding: 25px; border-radius: 8px; margin: 30px 0; }}
        .info h2 {{ margin-top: 0; color: #1565C0; }}
        .request-info {{ background: #f3e5f5; padding: 25px; border-radius: 8px; margin: 30px 0; }}
        .request-info h2 {{ margin-top: 0; color: #7B1FA2; }}
        pre {{ background: #263238; color: #fff; padding: 20px; border-radius: 5px; overflow-x: auto; }}
        .endpoints {{ background: #e8f5e8; padding: 25px; border-radius: 8px; }}
        .endpoints h2 {{ margin-top: 0; color: #2E7D32; }}
        .endpoints ul {{ list-style: none; padding: 0; }}
        .endpoints li {{ margin: 15px 0; }}
        .endpoints a {{ color: #1976D2; text-decoration: none; font-weight: 500; }}
        .endpoints a:hover {{ text-decoration: underline; }}
        .badge {{ background: #FF9800; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; margin-left: 10px; }}
        .feature {{ margin: 20px 0; }}
        .feature strong {{ color: #1565C0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo"> PesapalHTTP</div>
            <div class="tagline">HTTP Server Built from Scratch</div>
        </div>

        <div class="info">
            <h2> Server Information</h2>
            <div class="feature"><strong>Server:</strong> PesapalHTTP/1.0</div>
            <div class="feature"><strong>Language:</strong> Python 3 (no external HTTP libraries)</div>
            <div class="feature"><strong>Time:</strong> {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</div>
            <div class="feature"><strong>Protocol:</strong> HTTP/1.0, HTTP/1.1</div>
            <div class="feature"><strong>Architecture:</strong> Multi-threaded</div>
        </div>

        <div class="request-info">
            <h2> Your Request Details</h2>
            <pre>Method: {request.method}
Path: {request.path}
Version: {request.version}
Host: {request.host or 'Not provided'}
User-Agent: {request.user_agent or 'Not provided'}
Content-Type: {request.content_type or 'Not provided'}
Content-Length: {request.content_length or 'Not provided'}
Headers Count: {len(request.headers)}</pre>
        </div>

        <div class="endpoints">
            <h2> Available Endpoints</h2>
            <ul>
                <li><strong>GET</strong> <a href="/">/ </a> - This server information page</li>
                <li><strong>GET</strong> <a href="/health">/health</a> - Health check endpoint <span class="badge">JSON</span></li>
                <li><strong>POST</strong> /echo - Echo request data back <span class="badge">JSON</span></li>
                <li><strong>GET</strong> <a href="/demo">/demo</a> - API demonstration page</li>
            </ul>
        </div>

        <div class="info">
            <h2> Key Features</h2>
            <div class="feature">• <strong>Raw HTTP Parsing:</strong> Parses HTTP requests from raw bytes without external libraries</div>
            <div class="feature">• <strong>Standards Compliant:</strong> Follows RFC 7230 HTTP/1.1 specification</div>
            <div class="feature">• <strong>Robust Error Handling:</strong> Proper HTTP status codes and error responses</div>
            <div class="feature">• <strong>Content-Length Support:</strong> Correctly handles request bodies with Content-Length</div>
            <div class="feature">• <strong>Security Conscious:</strong> Input validation and size limits</div>
            <div class="feature">• <strong>Multi-threaded:</strong> Handles multiple concurrent connections</div>
        </div>
    </div>
</body>
</html>"""
        return create_html_response(html)

    def _handle_health(self, request: HTTPRequest) -> HTTPResponse:
        """Handle GET /health requests."""
        health_data = {
            "status": "healthy",
            "server": "PesapalHTTP/1.0",
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            "version": "1.0.0",
            "uptime": "Server is running",
            "endpoints": {
                "GET /": "Server information page",
                "GET /health": "Health check endpoint",
                "POST /echo": "Echo request data",
                "GET /demo": "API demonstration"
            },
            "capabilities": [
                "HTTP/1.0 support",
                "HTTP/1.1 support", 
                "Raw byte parsing",
                "Content-Length handling",
                "Multi-threaded connections",
                "Proper error responses"
            ]
        }
        return create_json_response(health_data)

    def _handle_echo(self, request: HTTPRequest) -> HTTPResponse:
        """Handle POST /echo requests - echo back request information."""
        echo_data = {
            "message": "Request successfully echoed",
            "request_info": {
                "method": request.method,
                "path": request.path,
                "version": request.version,
                "host": request.host,
                "user_agent": request.user_agent,
                "content_type": request.content_type,
                "content_length": request.content_length
            },
            "headers": dict(request.headers),
            "body": {
                "raw": request.get_body_as_string(),
                "length": len(request.get_body_as_bytes()),
                "type": "string" if isinstance(request.body, str) else "bytes"
            },
            "server_info": {
                "server": "PesapalHTTP/1.0",
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "processed_by": "Raw HTTP parser (no external libraries)"
            }
        }
        return create_json_response(echo_data)

    def _handle_demo(self, request: HTTPRequest) -> HTTPResponse:
        """Handle GET /demo requests - API demonstration page."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>PesapalHTTP - API Demo</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 40px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 40px; }
        .demo-section { margin: 30px 0; padding: 25px; border-radius: 8px; }
        .demo-section h3 { margin-top: 0; }
        .get-demo { background: #e8f5e8; border-left: 5px solid #4CAF50; }
        .post-demo { background: #fff3e0; border-left: 5px solid #FF9800; }
        .response-area { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-top: 20px; }
        button { background: #2196F3; color: white; border: none; padding: 12px 24px; border-radius: 5px; cursor: pointer; font-size: 16px; }
        button:hover { background: #1976D2; }
        textarea { width: 100%; height: 100px; margin: 10px 0; padding: 10px; border-radius: 5px; border: 1px solid #ddd; }
        .code { font-family: 'Courier New', monospace; background: #263238; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto; }
        pre { margin: 0; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1> PesapalHTTP API Demonstration</h1>
            <p>Interactive testing of our HTTP server endpoints</p>
        </div>

        <div class="demo-section get-demo">
            <h3> GET /health - Health Check</h3>
            <p>Test the health endpoint to see server status and capabilities:</p>
            <button onclick="testHealth()">Test Health Endpoint</button>
            <div id="health-response" class="response-area" style="display:none;">
                <h4>Response:</h4>
                <div class="code"><pre id="health-output"></pre></div>
            </div>
        </div>

        <div class="demo-section post-demo">
            <h3> POST /echo - Echo Request</h3>
            <p>Send JSON data to test request body parsing and echo functionality:</p>
            <textarea id="echo-input" placeholder="Enter JSON data to send">{
  "name": "Collins Nyagaka",
  "position": "Software Engineer",
  "company": "Pesapal",
  "message": "Hello from PesapalHTTP server!",
  "features": ["Raw HTTP parsing", "No external libraries", "RFC compliant"]
}</textarea>
            <br>
            <button onclick="testEcho()">Send Echo Request</button>
            <div id="echo-response" class="response-area" style="display:none;">
                <h4>Response:</h4>
                <div class="code"><pre id="echo-output"></pre></div>
            </div>
        </div>

        <div class="demo-section">
            <h3> Technical Details</h3>
            <p>This HTTP server demonstrates:</p>
            <ul>
                <li><strong>Raw HTTP Parsing:</strong> Parses requests from raw socket bytes</li>
                <li><strong>Content-Length Handling:</strong> Correctly reads request bodies</li>
                <li><strong>Header Processing:</strong> Extracts all required HTTP headers</li>
                <li><strong>Error Handling:</strong> Proper HTTP status codes and responses</li>
                <li><strong>Standards Compliance:</strong> Follows RFC 7230 specifications</li>
            </ul>
        </div>
    </div>

    <script>
        function testHealth() {
            fetch('/health')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('health-output').textContent = JSON.stringify(data, null, 2);
                    document.getElementById('health-response').style.display = 'block';
                })
                .catch(error => {
                    document.getElementById('health-output').textContent = 'Error: ' + error.message;
                    document.getElementById('health-response').style.display = 'block';
                });
        }

        function testEcho() {
            const inputData = document.getElementById('echo-input').value;
            fetch('/echo', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: inputData
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('echo-output').textContent = JSON.stringify(data, null, 2);
                document.getElementById('echo-response').style.display = 'block';
            })
            .catch(error => {
                document.getElementById('echo-output').textContent = 'Error: ' + error.message;
                document.getElementById('echo-response').style.display = 'block';
            });
        }
    </script>
</body>
</html>"""
        return create_html_response(html)


def main():
    """Main entry point for the server."""
    import argparse

    parser = argparse.ArgumentParser(description='PesapalHTTP - HTTP Server from Scratch')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--port', type=int, default=8080, help='Port to bind to (default: 8080)')
    parser.add_argument('--max-connections', type=int, default=10, help='Max concurrent connections (default: 10)')

    args = parser.parse_args()

    # Create and start server
    server = HTTPServer(host=args.host, port=args.port, max_connections=args.max_connections)

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("\n Server interrupted by user")
    except Exception as e:
        logger.error(f" Server error: {e}")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
