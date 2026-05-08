#!/usr/bin/env python3
"""
IE2102 - Network Programming Assignment
Student  : IT24102514
File     : client_2514.py
"""

import socket
import sys

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 50514
BUFFER_SIZE  = 8192

def send_framed(sock, message):
    payload = message.encode("utf-8")
    n       = len(payload)
    header  = f"LEN:{n}\n".encode("utf-8")
    sock.sendall(header + payload)

def recv_response(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8").strip()

def main():
    host = DEFAULT_HOST
    port = DEFAULT_PORT

    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])

    print(f"[CLIENT] Connecting to {host}:{port} ...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except ConnectionRefusedError:
        print("[ERROR] Cannot connect - is the server running?")
        sys.exit(1)

    print("[CLIENT] Connected!\n")

    welcome = recv_response(sock)
    print(f"[SERVER] {welcome}\n")

    print("=" * 55)
    print(" IE2102 Client  |  Registration: IT24102514")
    print("=" * 55)
    print(" Commands:")
    print("   REGISTER <username> <password>")
    print("   LOGIN    <username> <password>")
    print("   LOGOUT")
    print("   ECHO     <any message>")
    print("   QUIT")
    print("=" * 55)

    session_token = None

    while True:
        try:
            user_input = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[CLIENT] Disconnecting...")
            break

        if not user_input:
            continue

        parts = user_input.split(maxsplit=1)
        cmd   = parts[0].upper()

        if len(user_input.encode("utf-8")) > 4096:
            print("[CLIENT ERROR] Message too long (max 4096 bytes)")
            continue

        try:
            send_framed(sock, user_input)
        except BrokenPipeError:
            print("[CLIENT] Server closed the connection.")
            break

        try:
            response = recv_response(sock)
        except Exception as e:
            print(f"[CLIENT ERROR] {e}")
            break

        print(f"[SERVER] {response}")

        if cmd == "LOGIN" and response.startswith("OK"):
            for part in response.split():
                if part.startswith("TOKEN:"):
                    session_token = part[len("TOKEN:"):]
                    print(f"[CLIENT] Token saved: {session_token[:8]}...")

        if cmd == "LOGOUT":
            session_token = None
            print("[CLIENT] Session token cleared.")

        if cmd in ("QUIT", "EXIT"):
            break

    sock.close()
    print("[CLIENT] Connection closed.")

if __name__ == "__main__":
    main()
