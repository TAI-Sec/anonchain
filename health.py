"""Background health monitor: re-tests hops, promotes fastest, drops dead."""
import threading,time

class HealthMonitor:
    def __init__(self,state,interval=60,on_event=None):
        self.state=state; self.interval=interval
        self.on_event=on_event or (lambda *a,**k: None)
        self._stop=threading.Event(); self._t=None

    def start(self):
        if self._t and self._t.is_alive(): return
        self._stop.clear()
        self._t=threading.Thread(target=self._loop,daemon=True,name="anonchain-health")
        self._t.start()
        self.on_event("OK",f"health monitor every {self.interval}s")

    def stop(self):
        self._stop.set()
        if self._t: self._t.join(timeout=2)
        self.on_event("OK","health monitor stopped")

    @property
    def running(self): return self._t is not None and self._t.is_alive()

    def _loop(self):
        from concurrent.futures import ThreadPoolExecutor
        import requests
        while not self._stop.wait(self.interval):
            s=self.state
            pool=list(s.working) or list(s.proxies)
            if not pool: continue
            alive=[]
            def probe(p):
                cfg={"http":f"http://{p}","https":f"http://{p}"}
                try:
                    t0=time.time()
                    r=requests.get("http://httpbin.org/ip",proxies=cfg,
                                   timeout=6,verify=False)
                    if r.status_code==200:
                        return p,int((time.time()-t0)*1000)
                except Exception: pass
                return None
            with ThreadPoolExecutor(max_workers=min(40,len(pool))) as ex:
                for r in ex.map(probe,pool):
                    if r: alive.append(r)
            alive.sort(key=lambda x:x[1])
            dead=len(pool)-len(alive)
            with s.lock:
                s.working=[p for p,_ in alive]
            self.on_event("INFO",f"health: {len(alive)} ok · {dead} dropped")
            # if active chain hop died, trigger failover
            if s.chain_server and s.chain_strings:
                act=set(s.chain_strings)
                if act and not act.issubset({p for p,_ in alive}):
                    self.on_event("WARN","chain hop died — failing over")
