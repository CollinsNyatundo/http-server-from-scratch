#!/usr/bin/env python3
"""
Test Client for PesapalHTTP Server
=================================

Simple client to test and demonstrate the HTTP server functionality.
Uses only Python standard library - no external dependencies.

Usage:
    python test_client.py [host] [port]

Example:
    python test_client.py localhost 8080
"""

import socket
import json
import sys
import time
from typing import Tuple, Dict, Any


class HTTPTestClient:
    """Simple HTTP client for testing the PesapalHTTP server."""

    def __init__(self, host: str = 'localhost', port: int = 8080):
        self.host = host
        self.port = port

    def send_request(self, method: str, path: str, headers: Dict[str, str] = None, 
                    body: str = None) -> Tuple[int, Dict[str, str], str]:
        """
        Send HTTP request and return response.

        Returns:
            Tuple of (status_code, headers, body)
        """
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)

        try:
            # Connect to server
            sock.connect((self.host, self.port))

            # Build request
            request_lines = [f"{method} {path} HTTP/1.1"]

            # Add headers
            if headers:
                for name, value in headers.items():
                    request_lines.append(f"{name}: {value}")

            # Add default headers
            request_lines.append(f"Host: {self.host}:{self.port}")
            request_lines.append("Connection: close")

            # Add body if provided
            if body:
                body_bytes = body.encode('utf-8')
                request_lines.append(f"Content-Length: {len(body_bytes)}")
                request_lines.append("")  # Empty line before body
                request = "\r\n".join(request_lines) + "\r\n" + body
            else:
                request_lines.append("")  # Empty line to end headers
                request = "\r\n".join(request_lines) + "\r\n"

            # Send request
            sock.send(request.encode('utf-8'))

            # Receive response
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk

            return self._parse_response(response_data.decode('utf-8', errors='ignore'))

        finally:
            sock.close()

    def _parse_response(self, response: str) -> Tuple[int, Dict[str, str], str]:
        """Parse HTTP response."""
        lines = response.split('\r\n')

        # Parse status line
        status_line = lines[0]
        status_code = int(status_line.split()[1])

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()

        # Get body
        body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else ""

        return status_code, headers, body

    def test_get_root(self) -> bool:
        """Test GET / endpoint."""
        print("🧪 Testing GET / endpoint...")
        try:
            status, headers, body = self.send_request("GET", "/")
            if status == 200 and "PesapalHTTP" in body:
                print(f"  ✅ Success: {status} - Server information page loaded")
                return True
            else:
                print(f"  ❌ Failed: {status}")
                return False
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return False

    def test_health_endpoint(self) -> bool:
        """Test GET /health endpoint."""
        print("🧪 Testing GET /health endpoint...")
        try:
            status, headers, body = self.send_request("GET", "/health")
            if status == 200:
                # Try to parse JSON
                try:
                    data = json.loads(body)
                    if data.get("status") == "healthy":
                        print(f"  ✅ Success: {status} - Health check passed")
                        print(f"  📊 Server: {data.get('server')}")
                        print(f"  ⏰ Timestamp: {data.get('timestamp')}")
                        return True
                    else:
                        print(f"  ❌ Failed: Invalid health status")
                        return False
                except json.JSONDecodeError:
                    print(f"  ❌ Failed: Invalid JSON response")
                    return False
            else:
                print(f"  ❌ Failed: {status}")
                return False
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return False

    def test_echo_endpoint(self) -> bool:
        """Test POST /echo endpoint."""
        print("🧪 Testing POST /echo endpoint...")
        try:
            test_data = {
                "name": "Collins Nyagaka",
                "test": "PesapalHTTP Server",
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                "data": [1, 2, 3, "hello", True]
            }

            headers = {"Content-Type": "application/json"}
            body = json.dumps(test_data)

            status, resp_headers, resp_body = self.send_request("POST", "/echo", headers, body)

            if status == 200:
                try:
                    data = json.loads(resp_body)
                    if (data.get("message") == "Request successfully echoed" and 
                        data.get("request_info", {}).get("method") == "POST"):
                        print(f"  ✅ Success: {status} - Echo request successful")
                        print(f"  📦 Body length: {len(body)} bytes")
                        print(f"  📋 Headers count: {len(data.get('headers', {}))}")
                        return True
                    else:
                        print(f"  ❌ Failed: Invalid echo response format")
                        return False
                except json.JSONDecodeError:
                    print(f"  ❌ Failed: Invalid JSON response")
                    return False
            else:
                print(f"  ❌ Failed: {status}")
                return False
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return False

    def test_not_found(self) -> bool:
        """Test 404 Not Found response."""
        print("🧪 Testing 404 Not Found...")
        try:
            status, headers, body = self.send_request("GET", "/nonexistent")
            if status == 404:
                print(f"  ✅ Success: {status} - Not Found response correct")
                return True
            else:
                print(f"  ❌ Failed: Expected 404, got {status}")
                return False
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return False

    def test_malformed_request(self) -> bool:
        """Test malformed request handling."""
        print("🧪 Testing malformed request handling...")
        try:
            # Send malformed request directly
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((self.host, self.port))

            # Send invalid HTTP request
            sock.send(b"INVALID REQUEST LINE\r\n\r\n")

            # Try to receive response
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            if "400" in response or "Bad Request" in response:
                print(f"  ✅ Success: Bad Request handled correctly")
                return True
            else:
                print(f"  ❌ Failed: Expected 400 Bad Request")
                return False
        except Exception as e:
            print(f"  ❌ Error: {e}")
            return False

    def run_all_tests(self) -> Dict[str, bool]:
        """Run all tests and return results."""
        print(f"🚀 Starting PesapalHTTP Server Tests")
        print(f"🔗 Target: {self.host}:{self.port}")
        print("=" * 50)

        tests = [
            ("GET Root", self.test_get_root),
            ("Health Check", self.test_health_endpoint),
            ("Echo Endpoint", self.test_echo_endpoint),
            ("404 Not Found", self.test_not_found),
            ("Malformed Request", self.test_malformed_request)
        ]

        results = {}
        passed = 0
        total = len(tests)

        for test_name, test_func in tests:
            try:
                result = test_func()
                results[test_name] = result
                if result:
                    passed += 1
                print()
            except Exception as e:
                print(f"  💥 Test '{test_name}' crashed: {e}")
                results[test_name] = False
                print()

        # Summary
        print("=" * 50)
        print(f"📊 Test Results: {passed}/{total} tests passed")

        if passed == total:
            print("🎉 All tests passed! Server is working correctly.")
        else:
            print("⚠️  Some tests failed. Check server implementation.")
            for test_name, result in results.items():
                status = "✅" if result else "❌"
                print(f"  {status} {test_name}")

        return results


def main():
    """Main entry point."""
    # Parse command line arguments
    host = sys.argv[1] if len(sys.argv) > 1 else 'localhost'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

    print(f"PesapalHTTP Test Client")
    print(f"Target: {host}:{port}")
    print()

    # Create client and run tests
    client = HTTPTestClient(host, port)

    try:
        results = client.run_all_tests()

        # Exit with appropriate code
        if all(results.values()):
            sys.exit(0)  # Success
        else:
            sys.exit(1)  # Some tests failed

    except ConnectionError:
        print(f"❌ Cannot connect to {host}:{port}")
        print("   Make sure the PesapalHTTP server is running!")
        sys.exit(1)
    except Exception as e:
        print(f"💥 Test client error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
