"""Multi-source free proxy scraper + validator."""
import re,threading,time,requests,urllib3
from concurrent.futures import ThreadPoolExecutor,as_completed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SOURCES=[
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
]
PAT=re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")

class Scraper:
    def __init__(self,on_event=None,timeout=15):
        self.on_event=on_event or (lambda *a,**k: None)
        self.timeout=timeout

    def fetch_all(self):
        found=set()
        for url in SOURCES:
            try:
                r=requests.get(url,timeout=self.timeout,
                               headers={"User-Agent":"Mozilla/5.0"})
                if r.status_code!=200:
                    self.on_event("WARN",f"{url.split('/')[-1]} HTTP {r.status_code}"); continue
                hits=set(f"{m[0]}:{m[1]}" for m in PAT.findall(r.text))
                self.on_event("OK",f"{url.split('/')[-1]} +{len(hits)}")
                found|=hits
            except Exception as e:
                self.on_event("ERR",f"{url.split('/')[-1]} — {e}")
        self.on_event("OK",f"scraped {len(found)} unique")
        return list(found)

    def validate(self,proxies,workers=80,timeout=6):
        good=[]; lock=threading.Lock()
        def probe(p):
            cfg={"http":f"http://{p}","https":f"http://{p}"}
            try:
                t0=time.time()
                r=requests.get("http://httpbin.org/ip",proxies=cfg,
                               timeout=timeout,verify=False)
                if r.status_code==200:
                    lat=int((time.time()-t0)*1000)
                    with lock: good.append((p,lat))
            except Exception: pass
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(probe,proxies))
        self.on_event("OK",f"validated {len(good)}/{len(proxies)}")
        return good
