"""Loopback-only local HTTP surface. Not remote identity/authentication."""
from contextlib import closing, contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from . import board_commands, board_read
from .domain import ACPError, require
from .runtime import Runtime
from .store import SCHEMA_VERSION, data_directory

ASSETS = Path(__file__).with_name('board_assets')
BODY_LIMIT = 65536


class BoardServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, data_dir, port=8765, host='127.0.0.1'):
        require(host == '127.0.0.1', 'Control Board permits IPv4 loopback only')
        require(type(port) is int and 0 <= port <= 65535, 'Invalid port')
        self.data_dir = data_directory(data_dir)
        self.sessions = {}
        self.session_lock = threading.Lock()
        # Startup never initializes or migrates canonical state.
        with self.runtime():pass
        super().__init__((host, port), Handler)

    @contextmanager
    def runtime(self):
        path=self.data_dir/'acp.sqlite3'
        require(path.is_file() and not path.is_symlink(), 'Canonical SQLite unavailable; initialize explicitly using CLI')
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as check:
            require(check.execute('PRAGMA user_version').fetchone()[0]==SCHEMA_VERSION, 'Canonical schema unavailable; migrate explicitly with CLI')
        with Runtime(self.data_dir, existing_only=True) as runtime:yield runtime

    def session(self, cookie):
        jar=SimpleCookie()
        try:jar.load(cookie or '')
        except Exception:return None
        value=jar.get('acp_board')
        with self.session_lock:
            session=self.sessions.get(value.value if value else '')
            return session if session and session['expires']>time.monotonic() else None

    def new_session(self):
        sid=secrets.token_urlsafe(32)
        with self.session_lock:
            self.sessions={k:v for k,v in self.sessions.items() if v['expires']>time.monotonic()}
            require(len(self.sessions)<64, 'Local session capacity reached')
            self.sessions[sid]={'csrf':secrets.token_urlsafe(32),'expires':time.monotonic()+3600,'confirmations':{}}
        return sid,self.sessions[sid]


class Handler(BaseHTTPRequestHandler):
    server_version='ACP-Local-Board'
    def log_message(self, *_):pass  # No goal, packet, credential or token logging.

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def send(self, status, content, kind='application/json; charset=utf-8', cookie=None):
        raw=content if isinstance(content,bytes) else json.dumps(content,ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(raw)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if cookie:self.send_header('Set-Cookie',f'acp_board={cookie}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600')
        self.end_headers()
        self.wfile.write(raw)

    def local(self):
        port=self.server.server_address[1]
        allowed={f'127.0.0.1:{port}',f'localhost:{port}'}
        require(self.headers.get('Host') in allowed, 'Invalid local Host / DNS rebinding rejected')
        require(self.headers.get('Sec-Fetch-Site') not in {'cross-site'}, 'Cross-site requests rejected')
        require(not self.headers.get('Origin') or self.headers['Origin']==f"http://{self.headers['Host']}", 'Cross-origin request rejected')

    def do_GET(self):
        try:
            self.local()
            if self.path=='/':
                sid,session=self.server.new_session()
                page=(ASSETS/'index.html').read_bytes()
                self.send(200,page,'text/html; charset=utf-8',sid)
                return
            if self.path in {'/board.js','/board.css'}:
                kind='text/javascript' if self.path.endswith('.js') else 'text/css'
                self.send(200,(ASSETS/self.path[1:]).read_bytes(),kind+'; charset=utf-8')
                return
            session=self.server.session(self.headers.get('Cookie'))
            require(session,'Local browser session required; reload board')
            if self.path=='/api/session':self.send(200,{'csrf':session['csrf']});return
            if self.path=='/api/state':
                with self.server.runtime() as runtime:
                    with runtime.store.transaction():
                        state=board_read.snapshot(runtime)
                        state['actions']=board_commands.available(runtime)
                self.send(200,state);return
            self.send(404,{'error':'Unknown read route; mutations require POST'})
        except ACPError as exc:self.send(403,{'error':str(exc)})
        except (OSError,sqlite3.Error,ValueError,KeyError):self.send(503,{'error':'Control-plane unavailable; no current success or authority can be inferred.'})

    def do_POST(self):
        try:
            self.local()
            require(self.headers.get('Origin')==f"http://{self.headers['Host']}", 'Exact local Origin required')
            session=self.server.session(self.headers.get('Cookie'))
            require(session and secrets.compare_digest(self.headers.get('X-ACP-CSRF',''),session['csrf']), 'Session-bound CSRF token required')
            require(self.headers.get('Content-Type')=='application/json', 'JSON mutation required')
            require(not self.headers.get('Transfer-Encoding'), 'Chunked mutations not supported')
            length=int(self.headers.get('Content-Length','0'))
            require(0<length<=BODY_LIMIT,'Mutation body limit exceeded')
            def unique(pairs):
                data={}
                for k,v in pairs:
                    require(k not in data,'Duplicate JSON key');data[k]=v
                return data
            value=json.loads(self.rfile.read(length),object_pairs_hook=unique)
            require(isinstance(value,dict),'Object request required')
            if self.path=='/api/confirm':
                require(set(value)=={'action','payload','version'}, 'Malformed confirmation request')
                with self.server.runtime() as runtime:
                    with runtime.store.transaction():packet=board_commands.describe(runtime,value['action'],value['payload'],value['version'])
                token=secrets.token_urlsafe(32)
                with self.server.session_lock:
                    session['confirmations']={k:v for k,v in session['confirmations'].items() if v['expires']>time.monotonic()}
                    require(len(session['confirmations'])<16,'Too many pending confirmations')
                    session['confirmations'][token]={'command':value,'expires':time.monotonic()+120}
                self.send(200,{'confirmation':token,'packet':packet});return
            if self.path=='/api/command':
                require(set(value)=={'confirmation'},'Only confirmed command token accepted')
                with self.server.session_lock: saved=session['confirmations'].pop(value['confirmation'],None)
                require(saved and saved['expires']>time.monotonic(),'Expired/consumed confirmation; review current state')
                command=saved['command']
                with self.server.runtime() as runtime:
                    result=board_commands.execute(runtime,command['action'],command['payload'],command['version'])
                self.send(200,result);return
            self.send(404,{'error':'Unknown command route'})
        except ACPError as exc:
            self.send(409 if 'STALE_STATE' in str(exc) else 403,{'error':str(exc),'applied':False,'next':'Refresh current state and review the decision packet again.'})
        except (OSError,sqlite3.Error,ValueError,KeyError,TypeError):self.send(503,{'error':'Control-plane/request unavailable. Read current canonical state before retrying; never assume success.'})


def serve(data_dir=None, port=8765):
    with BoardServer(data_dir,port) as server:
        print(f'ACP local Control Board: http://127.0.0.1:{server.server_address[1]} (Ctrl+C to stop)',flush=True)
        try:server.serve_forever()
        except KeyboardInterrupt:pass
