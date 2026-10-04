"""DNS-over-HTTPS resolver. Cached, multi-endpoint."""
import time, threading, requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ENDPOINTS=["https://cloudflare-dns.com/dns-query",
           "https://dns.google/resolve",
           "https://dns.quad9.net:5053/dns-query"]

class DoHResolver:
    def __init__(self,endpoints=None,timeout=4,cache_ttl=300,proxy=None,
                 on_event=None):
        self.endpoints=endpoints or ENDPOINTS
        self.timeout=timeout; self.cache_ttl=cache_ttl; self.proxy=proxy
        self.on_event=on_event or (lambda *a,**k: None)
        self._cache={}; self._lock=threading.Lock()

    def resolve(self,host,rtype="A"):
        now=time.time(); key=(host,rtype)
        with self._lock:
            h=self._cache.get(key)
            if h and h[0]>now: return h[1]
        last=None
        for ep in self.endpoints:
            try:
                r=requests.get(ep,params={"name":host,"type":rtype},
                               headers={"Accept":"application/dns-json"},
                               timeout=self.timeout,verify=False,
                               proxies=self.proxy)
                if r.status_code!=200: last=f"HTTP {r.status_code}"; continue
                d=r.json()
                want=1 if rtype=="A" else 28 if rtype=="AAAA" else None
                ips=[a["data"] for a in d.get("Answer",[]) if a.get("type")==want]
                if not ips: last="no answer"; continue
                ip=ips[0]
                with self._lock: self._cache[key]=(now+self.cache_ttl,ip)
                return ip
            except Exception as e:
                last=str(e)
        raise OSError(f"DoH {host}/{rtype}: {last}")
