"""Local DNS server (UDP/TCP :5353) that forwards to DoH."""
import socket, struct, threading, socketserver

class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        resolver=self.server.resolver
        try:
            tid=data[:2]
            # parse question
            i=12; labels=[]
            while i<len(data) and data[i]!=0:
                l=data[i]; labels.append(data[i+1:i+1+l].decode("ascii","ignore"))
                i+=1+l
            qname=".".join(labels)
            qtype=struct.unpack(">H",data[i+1:i+3])[0]
            rtype={1:"A",28:"AAAA"}.get(qtype,"A")
            ip=resolver.resolve(qname,rtype)
            # build minimal answer
            ans=bytearray(data)
            ans[2]|=0x80  # QR=1
            ans[3]=(ans[3]&0xF0)|0x00
            ans[6:8]=b"\x00\x01"  # ANCOUNT=1
            # answer: name ptr + type + class + ttl + rdlen + rdata
            body=(b"\xc0\x0c"+struct.pack(">HHI",qtype,1,60))
            if qtype==1:
                rdata=socket.inet_aton(ip); body+=struct.pack(">H",len(rdata))+rdata
            elif qtype==28:
                rdata=socket.inet_pton(socket.AF_INET6,ip)
                body+=struct.pack(">H",len(rdata))+rdata
            else: body+=b"\x00\x04\x00\x00\x00\x00"
            sock.sendto(bytes(ans)+body,self.client_address)
        except Exception:
            try: sock.sendto(data,self.client_address)
            except Exception: pass

class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            hdr=self.request.recv(2)
            if len(hdr)<2: return
            n=struct.unpack(">H",hdr)[0]
            data=self.request.recv(n)
            resolver=self.server.resolver
            i=12; labels=[]
            while i<len(data) and data[i]!=0:
                l=data[i]; labels.append(data[i+1:i+1+l].decode("ascii","ignore"))
                i+=1+l
            qname=".".join(labels)
            qtype=struct.unpack(">H",data[i+1:i+3])[0]
            rtype={1:"A",28:"AAAA"}.get(qtype,"A")
            ip=resolver.resolve(qname,rtype)
            ans=bytearray(data); ans[2]|=0x80; ans[6:8]=b"\x00\x01"
            body=b"\xc0\x0c"+struct.pack(">HHI",qtype,1,60)
            rdata=socket.inet_aton(ip) if qtype==1 else \
                  socket.inet_pton(socket.AF_INET6,ip)
            body+=struct.pack(">H",len(rdata))+rdata
            out=bytes(ans)+body
            self.request.sendall(struct.pack(">H",len(out))+out)
        except Exception: pass

class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address=True
class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True

class DNSBridge:
    def __init__(self,resolver,host="127.0.0.1",port=5353,on_event=None):
        self.resolver=resolver; self.host=host; self.port=port
        self.on_event=on_event or (lambda *a,**k: None)
        self._udp=None; self._tcp=None
        self._ut=None; self._tt=None

    def start(self):
        try:
            self._udp=_UDPServer((self.host,self.port),_UDPHandler)
            self._udp.resolver=self.resolver
            self._tcp=_TCPServer((self.host,self.port),_TCPHandler)
            self._tcp.resolver=self.resolver
        except OSError as e:
            self.on_event("ERR",f"dns bridge bind: {e}"); return False
        self._ut=threading.Thread(target=self._udp.serve_forever,daemon=True)
        self._tt=threading.Thread(target=self._tcp.serve_forever,daemon=True)
        self._ut.start(); self._tt.start()
        self.on_event("OK",f"DNS bridge on {self.host}:{self.port} → DoH")
        return True

    def stop(self):
        for s in (self._udp,self._tcp):
            if s:
                try: s.shutdown(); s.server_close()
                except Exception: pass
        self._udp=self._tcp=None
        self.on_event("OK","DNS bridge stopped")

    @property
    def running(self): return self._udp is not None
