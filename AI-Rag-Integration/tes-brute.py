import os
import requests as req

BASE = os.environ.get("DVWA_URL", "http://192.168.43.100")

url = f"{BASE}/vulnerabilities/brute/?username=admin&password=salah&Login=Login"
cookies = {"PHPSESSID": os.environ["DVWA_PHPSESSID"], "security": "low"}

s = req.Session()
for i in range(10):
  resp = s.get(url, cookies=cookies)
  marker = "password incorrect" in resp.text.lower()
  print(f"req {i+1} -> {resp.status_code}(failed-login marker: {marker}) -> {resp.url} ({resp.request.headers.get('Cookie')})({resp.request.headers.get('Content-Encoding')})")
