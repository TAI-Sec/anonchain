"""Transparent mode: network namespace + iptables REDIRECT."""
import os,subprocess,shutil,signal,atexit,threading

class NetNS:
    def __init__(self,name="anonchain",table="100",port=9050,on_event=None):
        self.name=name; self.table=table; self.port=port
        self.on_event=on_event or (lambda *a,**k: None)
        self.active=False
        self._lock=threading.Lock()
        self._ip=shutil.which("iptables")
        self._ipns=shutil.which("ip")
        atexit.register(self.stop)

    def _run(self,cmd):
        return subprocess.run(cmd,capture_output=True,text=True)

    def available(self):
        return os.geteuid()==0 and self._ip and self._ipns

    def start(self):
        with self._lock:
            if self.active: return True
            if not self.available():
                self.on_event("ERR","netns requires root + ip + iptables")
                return False
            # enable ip_forward
            self._run(["sysctl","-w","net.ipv4.ip_forward=1"])
            # route tcp from foreign sources to our proxy via REDIRECT
            self._run([self._ip,"-t","nat","-N","ANONCHAIN"])
            self._run([self._ip,"-t","nat","-F","ANONCHAIN"])
            self._run([self._ip,"-t","nat","-A","ANONCHAIN",
                       "-p","tcp","-j","REDIRECT","--to-port",str(self.port)])
            if self._run([self._ip,"-t","nat","-C","OUTPUT","-j","ANONCHAIN"]
                         ).returncode!=0:
                self._run([self._ip,"-t","nat","-I","OUTPUT","1","-j","ANONCHAIN"])
            self.active=True
            self.on_event("OK",f"transparent mode ACTIVE (: {self.port})")
            return True

    def stop(self):
        with self._lock:
            if not self.active: return
            try:
                self._run([self._ip,"-t","nat","-D","OUTPUT","-j","ANONCHAIN"])
            except Exception: pass
            self._run([self._ip,"-t","nat","-F","ANONCHAIN"])
            self._run([self._ip,"-t","nat","-X","ANONCHAIN"])
            self.active=False
            self.on_event("OK","transparent mode stopped")

    @property
    def running(self): return self.active
