"""iptables kill-switch. Blocks all egress except whitelisted proxy IPs."""
import os,signal,atexit,subprocess,shutil,tempfile,threading

class KillSwitch:
    def __init__(self,allow_ips,on_event=None):
        self.allow_ips=[ip for ip in allow_ips if ip]
        self.on_event=on_event or (lambda *a,**k: None)
        self.active=False
        self._ip=shutil.which("iptables")
        self._save=shutil.which("iptables-save")
        self._restore=shutil.which("iptables-restore")
        self._backup=None; self._lock=threading.Lock(); self._done=False

    def _ok(self): return all([self._ip,self._save,self._restore])
    def _run(self,args): return subprocess.run([self._ip]+args,
                                               capture_output=True,text=True)

    def _backup_rules(self):
        fd,path=tempfile.mkstemp(prefix="anonchain-ipt-",suffix=".rules")
        os.close(fd)
        with open(path,"w") as f:
            r=subprocess.run([self._save],stdout=f,text=True)
            if r.returncode!=0: raise RuntimeError("iptables-save failed")
        self._backup=path

    def _restore_rules(self):
        if not self._backup or not os.path.exists(self._backup): return
        with open(self._backup) as f:
            subprocess.run([self._restore],stdin=f)
        os.unlink(self._backup); self._backup=None

    def _register(self):
        if self._done: return
        atexit.register(self._atexit)
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
            try: signal.signal(sig,self._sig)
            except Exception: pass
        self._done=True

    def _atexit(self):
        if self.active: self.disarm(silent=True)

    def _sig(self,signum,frame):
        self.disarm(silent=True); os._exit(128+signum)

    def arm(self):
        with self._lock:
            if self.active: return True,"already armed"
            if os.geteuid()!=0: return False,"requires root"
            if not self._ok(): return False,"iptables tools missing"
            if not self.allow_ips: return False,"no whitelist IPs"
            try: self._backup_rules()
            except Exception as e: return False,f"backup: {e}"
            self._run(["-N","ANONCHAIN"]); self._run(["-F","ANONCHAIN"])
            self._run(["-A","ANONCHAIN","-o","lo","-j","RETURN"])
            self._run(["-A","ANONCHAIN","-m","conntrack","--ctstate",
                       "ESTABLISHED,RELATED","-j","RETURN"])
            for ip in self.allow_ips:
                self._run(["-A","ANONCHAIN","-d",ip,"-j","RETURN"])
            self._run(["-A","ANONCHAIN","-j","DROP"])
            if self._run(["-C","OUTPUT","-j","ANONCHAIN"]).returncode!=0:
                self._run(["-I","OUTPUT","1","-j","ANONCHAIN"])
            self.active=True; self._register()
            self.on_event("WARN",f"KILL-SWITCH ARMED · {', '.join(self.allow_ips)}")
            return True,"armed"

    def disarm(self,silent=False):
        with self._lock:
            if not self.active: return True,"not active"
            try: self._run(["-D","OUTPUT","-j","ANONCHAIN"])
            except Exception: pass
            try: self._restore_rules()
            except Exception: pass
            self._run(["-F","ANONCHAIN"]); self._run(["-X","ANONCHAIN"])
            self.active=False
            if not silent: self.on_event("OK","KILL-SWITCH DISARMED")
            return True,"disarmed"

    def status(self): return "ARMED" if self.active else "off"
