"""Inspectable adversarial fixture, executed only in disposable M08 LPACs."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import winreg


def run():
    mode, *args = sys.argv[1:]
    if mode == "read":
        print(Path(args[0]).read_text(), flush=True)
    elif mode == "write":
        with open(args[0], "a", encoding="utf-8") as output:
            output.write("M08-WRITE\n")
    elif mode == "environment":
        print(json.dumps(dict(os.environ)), flush=True)
    elif mode == "registry":
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, args[0]) as key:
            print(winreg.QueryValueEx(key, "canary")[0], flush=True)
    elif mode in ("tcp", "udp"):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if mode == "tcp" else socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            endpoint = (args[0], int(args[1]))
            if mode == "tcp":
                client.connect(endpoint)
                client.sendall(b"GET /worker HTTP/1.0\r\n\r\n")
            else:
                client.sendto(b"M08-SYNTHETIC", endpoint)
    elif mode == "tree":
        target, depth, detached = args
        child = None
        if int(depth):
            child = subprocess.Popen([sys.executable, "-I", "-S", "-B", __file__, "tree", target,
                                      str(int(depth) - 1), detached],
                                     creationflags=(subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP) if detached == "yes" else subprocess.CREATE_NO_WINDOW,
                                     close_fds=True)
        with open(target, "a", encoding="utf-8") as output:
            output.write("STARTED " + str(os.getpid()) + "\n"); output.flush()
            time.sleep(12)
            output.write("LATE " + str(os.getpid()) + "\n"); output.flush()
        if child:
            child.wait(timeout=20)
    elif mode == "breakaway":
        subprocess.Popen([sys.executable, "-I", "-S", "-B", __file__, "write", args[0]],
                         creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB | subprocess.CREATE_NO_WINDOW,
                         close_fds=True).wait(timeout=5)
    else:
        raise ValueError("Unknown fixture mode")


if __name__ == "__main__":
    try:
        run()
    except OSError as exc:
        print(json.dumps({"error": type(exc).__name__, "errno": exc.errno, "winerror": getattr(exc, "winerror", None)}), flush=True)
        sys.exit(13)
