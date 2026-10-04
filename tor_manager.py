"""Spawn tor, pump logs, request NEWNYM via control port."""
import os,socket,subprocess,tempfile,threading,time,shutil,atexit

class TorManager:
    def __init__(self,socks_port=9051,control_port=9052,on_event=None):
        self.socks_port=socks_port; self.control_port=control_port
        self.on_event=on_event or (lambda *a,**k: None)
        self.proc=None; self.tor_bin=shutil.which("tor")
        self.datadir=tempfile.mkdtemp(prefix="anonchain-tor-")
        self._lock=threading.Lock(); self.running=False
        atexit.register(self.stop)

    def available(self): return self.tor_bin is not None

    def start(self,wait=True,timeout=30):
        with self._lock:
            if self.running: return True
            if not self.tor_bin:
                self.on_event("ERR","tor binary not found — apt install tor")
                return False
            args=[self.tor_bin,
                  "--SocksPort",f"127.0.0.1:{self.socks_port}",
                  "--ControlPort",f"127.0.0.1:{self.control_port}",
                  "--CookieAuthentication","0",
                  "--DataDirectory",self.datadir,
                  "--ClientOnly","1","--AvoidDiskWrites","1",
                  "--Log","notice stdout"]
            try:
                self.proc=subprocess.Popen(args,stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           text=True,bufsize=1)
            except Exception as e:
                self.on_event("ERR",f"tor spawn: {e}"); return False
            self.running=True
        if wait and not self._wait(timeout):
            self.on_event("ERR","tor socks did not come up"); self.stop(); return False
        threading.Thread(target=self._pump,daemon=True).start()
        self.on_event("OK",f"tor up · socks :{self.socks_port} ctrl :{self.control_port}")
        return True

    def _wait(self,timeout):
        t0=time.time()
        while time.time()-t0<timeout:
            try:
                s=socket.create_connection(("127.0.0.1",self.socks_port),1)
                s.close(); return True
            except Exception: time.sleep(0.3)
        return False

    def _pump(self):
        try:
            for line in self.proc.stdout:
                line=line.rstrip()
                if not line: continue
                if "Bootstrapped 100" in line: self.on_event("OK","tor 100%")
                elif "Bootstrapped" in line: self.on_event("INFO",line[:90])
        except Exception: pass

    def new_circuit(self):
        try:
            s=socket.create_connection(("127.0.0.1",self.control_port),3)
            s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n')
            time.sleep(0.4); s.close()
            self.on_event("OK","new tor circuit"); return True
        except Exception as e:
            self.on_event("ERR",f"newnym: {e}"); return False

    def stop(self):
        with self._lock:
            if not self.running: return
            self.running=False
            if self.proc:
                try: self.proc.terminate()
                except Exception: pass
                try: self.proc.wait(timeout=5)
                except Exception:
                    try: self.proc.kill()
                    except Exception: pass
            self.proc=None
            self.on_event("OK","tor stopped")
