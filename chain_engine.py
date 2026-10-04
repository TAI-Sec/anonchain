"""ANONCHAIN chain engine — HTTP/SOCKS5/UDP multi-hop relay."""
import socket, struct, select, base64, threading, time, random
from collections import deque

class Hop:
    __slots__ = ("kind","host","port","user","pwd","latency")
    def __init__(self, kind, host, port, user=None, pwd=None, latency=9999):
        self.kind=kind.lower(); self.host=host; self.port=int(port)
        self.user=user; self.pwd=pwd; self.latency=latency
    def __repr__(self): return f"<{self.kind} {self.host}:{self.port} {self.latency}ms>"

def parse_hop(line):
    s=line.strip(); kind="http"
    if "://" in s:
        scheme,s=s.split("://",1); scheme=scheme.lower()
        kind={"http":"http","https":"http","socks5":"socks5",
              "socks5h":"socks5","socks4":"socks5"}.get(scheme,"http")
    user=pwd=None
    if "@" in s:
        cred,s=s.rsplit("@",1)
        if ":" in cred: user,pwd=cred.split(":",1)
        else: user=cred
    if ":" not in s: raise ValueError(f"missing port: {line!r}")
    host,port=s.rsplit(":",1)
    return Hop(kind,host.strip("[]"),int(port),user,pwd)

def _recv_exact(s,n):
    b=b""
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c: raise IOError("closed")
        b+=c
    return b

class PushedBackSocket:
    __slots__=("_s","_pb")
    def __init__(self,s,pb): self._s=s; self._pb=bytearray(pb)
    def recv(self,n):
        if self._pb:
            o=bytes(self._pb[:n]); del self._pb[:n]; return o
        return self._s.recv(n)
    def sendall(self,d): return self._s.sendall(d)
    def send(self,d): return self._s.send(d)
    def settimeout(self,t): return self._s.settimeout(t)
    def fileno(self): return self._s.fileno()
    def close(self):
        try: self._s.close()
        except Exception: pass

def _http_connect(sock,hop,dh,dp,timeout=15):
    h=(f"CONNECT {dh}:{dp} HTTP/1.1\r\nHost: {dh}:{dp}\r\n"
       f"Proxy-Connection: keep-alive\r\n")
    if hop.user is not None:
        c=base64.b64encode(f"{hop.user}:{hop.pwd or ''}".encode()).decode()
        h+=f"Proxy-Authorization: Basic {c}\r\n"
    h+="\r\n"; sock.sendall(h.encode())
    buf=b""
    while b"\r\n\r\n" not in buf:
        c=sock.recv(4096)
        if not c: raise IOError("http closed")
        buf+=c
        if len(buf)>65536: raise IOError("hdr too big")
    hd,_,rest=buf.partition(b"\r\n\r\n")
    st=hd.split(b"\r\n",1)[0].split(b" ",2)
    if len(st)<2 or not st[1].startswith(b"2"):
        raise IOError("http refused")
    return PushedBackSocket(sock,rest)

def _socks5_connect(sock,hop,dh,dp,timeout=15):
    if hop.user is not None: sock.sendall(b"\x05\x02\x00\x02")
    else: sock.sendall(b"\x05\x01\x00")
    r=_recv_exact(sock,2)
    if r[0]!=5: raise IOError("socks5 ver")
    if r[1]==2:
        u=(hop.user or "").encode(); p=(hop.pwd or "").encode()
        sock.sendall(b"\x01"+bytes([len(u)])+u+bytes([len(p)])+p)
        ar=_recv_exact(sock,2)
        if ar[1]!=0: raise IOError("socks5 auth")
    elif r[1]!=0: raise IOError(f"socks5 method {r[1]}")
    hb=dh.encode()
    if len(hb)>255: raise IOError("host too long")
    sock.sendall(b"\x05\x01\x00\x03"+bytes([len(hb)])+hb+struct.pack(">H",dp))
    h=_recv_exact(sock,4)
    if h[0]!=5: raise IOError("socks5 rply ver")
    if h[1]!=0:
        codes={1:"general",2:"deny",3:"net",4:"host",5:"refuse",
               6:"ttl",7:"cmd",8:"atype"}
        raise IOError(f"socks5 {codes.get(h[1],h[1])}")
    a=h[3]
    if a==1: _recv_exact(sock,6)
    elif a==3:
        l=_recv_exact(sock,1)[0]; _recv_exact(sock,l+2)
    elif a==4: _recv_exact(sock,18)
    else: raise IOError("atyp")
    return sock

def _tunnel(sock,hop,dh,dp,timeout=15):
    if hop.kind=="http": return _http_connect(sock,hop,dh,dp,timeout)
    if hop.kind=="socks5": return _socks5_connect(sock,hop,dh,dp,timeout)
    raise ValueError(f"kind {hop.kind}")

def build_chain(hops,dh,dp,timeout=15):
    if not hops: return socket.create_connection((dh,dp),timeout=timeout)
    f=hops[0]
    s=socket.create_connection((f.host,f.port),timeout=timeout)
    s.settimeout(timeout)
    for i in range(len(hops)-1):
        nx=hops[i+1]
        s=_tunnel(s,hops[i],nx.host,nx.port,timeout)
    s=_tunnel(s,hops[-1],dh,dp,timeout)
    s.settimeout(None)
    return s

def udp_associate(hops,target_host,target_port,timeout=15):
    """SOCKS5 UDP ASSOCIATE through hops[-1] (first hop must be socks5)."""
    if not hops or hops[0].kind!="socks5":
        raise IOError("UDP requires SOCKS5 first hop")
    s=socket.create_connection((hops[0].host,hops[0].port),timeout=timeout)
    s.settimeout(timeout)
    # auth
    if hops[0].user is not None: s.sendall(b"\x05\x02\x00\x02")
    else: s.sendall(b"\x05\x01\x00")
    r=_recv_exact(s,2)
    if r[1]==2:
        u=(hops[0].user or "").encode(); p=(hops[0].pwd or "").encode()
        s.sendall(b"\x01"+bytes([len(u)])+u+bytes([len(p)])+p)
        if _recv_exact(s,2)[1]!=0: raise IOError("udp auth")
    s.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    h=_recv_exact(s,4)
    if h[1]!=0: raise IOError("udp assoc refuse")
    a=h[3]
    if a==1: relay_ip=socket.inet_ntoa(_recv_exact(s,4))
    elif a==3:
        l=_recv_exact(s,1)[0]; relay_ip=_recv_exact(s,l).decode()
    elif a==4: relay_ip=socket.inet_ntop(socket.AF_INET6,_recv_exact(s,16))
    else: raise IOError("udp atyp")
    relay_port=struct.unpack(">H",_recv_exact(s,2))[0]
    return s,relay_ip,relay_port

# ── hybrid local server ────────────────────────────────────
class ChainProxyServer:
    def __init__(self,hops,port=9050,host="127.0.0.1",on_event=None,
                 doh=None,udp=False,failover_pool=None):
        self.hops=list(hops); self.host=host; self.port=port
        self.on_event=on_event or (lambda *a,**k: None)
        self.doh=doh; self.udp=udp; self.failover_pool=failover_pool or []
        self._srv=None; self._running=False; self._thread=None
        self._lock=threading.Lock()
        self.stats={"connections":0,"upstream_ok":0,"upstream_fail":0,
                    "bytes_c2u":0,"bytes_u2c":0,"http":0,"socks5":0,
                    "udp":0,"failovers":0}
        self.capture=deque(maxlen=1000)
        self._current_hops=list(self.hops)

    def start(self):
        srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        srv.bind((self.host,self.port)); srv.listen(128); srv.settimeout(1.0)
        self._srv=srv; self._running=True
        self._thread=threading.Thread(target=self._accept,daemon=True,
                                      name="anonchain-accept")
        self._thread.start()
        self.on_event("OK",f"listener {self.host}:{self.port}")
        return self

    def stop(self):
        self._running=False
        try:
            if self._srv: self._srv.close()
        except Exception: pass
        if self._thread: self._thread.join(timeout=2)
        self.on_event("OK","listener stopped")

    @property
    def running(self): return self._running

    def _accept(self):
        while self._running:
            try: c,_=self._srv.accept()
            except socket.timeout: continue
            except OSError: break
            threading.Thread(target=self._handle,args=(c,),daemon=True).start()

    def _handle(self,cli):
        try:
            cli.settimeout(20)
            first=cli.recv(1)
            if not first: return
            with self._lock: self.stats["connections"]+=1
            if first==b"\x05":
                with self._lock: self.stats["socks5"]+=1
                self._h_socks5(cli)
            else:
                with self._lock: self.stats["http"]+=1
                self._h_http(cli,first)
        except Exception as e:
            self.on_event("ERR",f"handler {e}")
        finally:
            try: cli.close()
            except Exception: pass

    def _try_chain(self,dh,dp,timeout=15):
        hops=self._current_hops
        try:
            s=build_chain(hops,dh,dp,timeout)
            return s,hops
        except Exception as e:
            if not self.failover_pool: raise
            with self._lock: self.stats["failovers"]+=1
            self.on_event("WARN",f"failover: {e}")
            cand=list(self.failover_pool); random.shuffle(cand)
            for alt in cand[:8]:
                try:
                    new=[alt]+hops[1:] if len(hops)>1 else [alt]
                    s=build_chain(new,dh,dp,timeout)
                    self._current_hops=new
                    self.on_event("OK",f"new path via {alt.host}")
                    return s,new
                except Exception: continue
            raise

    def _h_http(self,cli,first):
        data=first
        while b"\r\n\r\n" not in data:
            c=cli.recv(4096)
            if not c: return
            data+=c
            if len(data)>65536: return
        hd,_,extra=data.partition(b"\r\n\r\n")
        try:
            l0=hd.split(b"\r\n",1)[0].decode("latin-1")
            m,t,_=l0.split(" ",2)
        except Exception:
            cli.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"); return
        if m.upper()!="CONNECT":
            cli.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\n\r\n"); return
        if t.startswith("["): host,_,ps=t[1:].partition("]:")
        else: host,_,ps=t.rpartition(":")
        try:
            port=int(ps)
            if not (0<port<65536): raise ValueError
        except Exception:
            cli.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"); return
        self.on_event("INFO",f"CONNECT {host}:{port}")
        try: up,_=self._try_chain(host,port)
        except Exception as e:
            with self._lock: self.stats["upstream_fail"]+=1
            self.on_event("ERR",f"chain fail {host}:{port} — {e}")
            try: cli.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            except Exception: pass
            return
        with self._lock:
            self.stats["upstream_ok"]+=1
            self.capture.append({"t":time.time(),"proto":"http",
                                 "host":host,"port":port})
        if extra:
            try: up.sendall(extra)
            except Exception: pass
        cli.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        cli.settimeout(None)
        self._pump(cli,up,host,port)

    def _h_socks5(self,cli):
        nm=_recv_exact(cli,1)[0]
        _recv_exact(cli,nm)
        cli.sendall(b"\x05\x00")
        req=_recv_exact(cli,4)
        if req[0]!=5: return
        cmd,atyp=req[1],req[3]
        if cmd==1:
            if atyp==1: host=socket.inet_ntoa(_recv_exact(cli,4))
            elif atyp==3:
                l=_recv_exact(cli,1)[0]
                host=_recv_exact(cli,l).decode("utf-8","ignore")
            elif atyp==4: host=socket.inet_ntop(socket.AF_INET6,_recv_exact(cli,16))
            else: return
            port=struct.unpack(">H",_recv_exact(cli,2))[0]
            dh=host
            if self.doh and atyp==3:
                try: dh=self.doh.resolve(host)
                except Exception as e:
                    self.on_event("ERR",f"DoH {host} — {e}")
                    cli.sendall(b"\x05\x04\x00\x01"+b"\x00"*6); return
            self.on_event("INFO",f"SOCKS5 {host}:{port}")
            try: up,_=self._try_chain(dh,port)
            except Exception as e:
                with self._lock: self.stats["upstream_fail"]+=1
                self.on_event("ERR",f"chain {host}:{port} — {e}")
                cli.sendall(b"\x05\x05\x00\x01"+b"\x00"*6); return
            with self._lock:
                self.stats["upstream_ok"]+=1
                self.capture.append({"t":time.time(),"proto":"socks5",
                                     "host":host,"port":port})
            cli.sendall(b"\x05\x00\x00\x01"+b"\x00"*6)
            cli.settimeout(None)
            self._pump(cli,up,host,port)
        elif cmd==3 and self.udp:
            # minimal UDP-assoc echo (delegated to engine)
            cli.sendall(b"\x05\x00\x00\x01"+b"\x00"*6)
            with self._lock: self.stats["udp"]+=1
        else:
            cli.sendall(b"\x05\x07\x00\x01"+b"\x00"*6)

    def _pump(self,a,b,host,port):
        try:
            while self._running:
                r,_,x=select.select([a,b],[],[a,b],30)
                if x: return
                if not r: continue
                for s in r:
                    o=b if s is a else a
                    try: buf=s.recv(65536)
                    except Exception: return
                    if not buf: return
                    try: o.sendall(buf)
                    except Exception: return
                    with self._lock:
                        if s is a: self.stats["bytes_c2u"]+=len(buf)
                        else: self.stats["bytes_u2c"]+=len(buf)
        finally:
            for s in (a,b):
                try: s.close()
                except Exception: pass
            self.on_event("OK",f"closed {host}:{port}")
