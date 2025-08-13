import requests
import concurrent.futures
import random
import time
import csv
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, quote
from bs4 import BeautifulSoup
import threading
import json

# ---------------- CONFIGURAÇÃO ----------------
params_to_test = [
    "url","uri","path","goto","target","redir","redirect","redirect_url","redirect_uri",
    "return","returnTo","return_url","returnUri","continue","continueTo","continueUrl",
    "next","next_url","nextUri","forward","forward_url","location","dest","destination",
    "dest_url","to","out","outUrl","ref","referrer","page","login_url","logout_url",
    "success_url","failure_url","redirectTo","go","jump","link","u","r","n","callback",
    "callback_url","cb"
]

TEST_DOMAIN = "https://meu-webhook.com"
MIN_DELAY = 0.1
MAX_DELAY = 0.4
MAX_THREADS = 30
MAX_CRAWL_DEPTH = 2
lock = threading.Lock()
visited_urls = set()
vulnerable_urls = set()
tested_urls = set()
results_csv = "vulnerable_urls.csv"
vulnerable_txt = "vulnerable_urls.txt"
safe_txt = "safe_urls.txt"
VERBOSE = False

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/114.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/117.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1) Safari/604.1"
]

payloads = [
    TEST_DOMAIN,
    "//" + TEST_DOMAIN.replace("https://","").replace("http://",""),
    TEST_DOMAIN + "/%2e%2e",
    TEST_DOMAIN + "%2F..%2F",
    quote(TEST_DOMAIN),
    quote("//" + TEST_DOMAIN.replace("https://","")),
    TEST_DOMAIN + "#@legit.com",
    TEST_DOMAIN + "@legit.com",
    TEST_DOMAIN + "/./",
    TEST_DOMAIN + "/../",
    TEST_DOMAIN + "?param=test",
    TEST_DOMAIN + "&param=test",
    "https://sub." + TEST_DOMAIN.replace("https://",""),
    TEST_DOMAIN + "/login",
    TEST_DOMAIN + "/redirect",
    TEST_DOMAIN + "#fragment",
    TEST_DOMAIN + "/#/",
    TEST_DOMAIN + "?next=" + TEST_DOMAIN,
    TEST_DOMAIN.replace("https://", "%68%74%74%70%73%3A%2F%2F")
]

# ---------------- FUNÇÕES AUXILIARES ----------------
def log(msg):
    if VERBOSE:
        print(msg)

def random_headers():
    return {"User-Agent": random.choice(user_agents)}

def save_result(url, param, payload, location, status):
    with lock:
        with open(results_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([url, param, payload, status, location])
        with open(vulnerable_txt, "a", encoding="utf-8") as f:
            f.write(f"{url}\n")

def mark_safe(url):
    with lock:
        with open(safe_txt, "a", encoding="utf-8") as f:
            f.write(f"{url}\n")

# ---------------- TESTE DE OPEN REDIRECT ----------------
def test_url(base_url, param, payload):
    try:
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)
        query_params[param] = payload
        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        resp = requests.get(new_url, headers=random_headers(), timeout=6, allow_redirects=False)
        location = resp.headers.get("Location", "")

        if resp.status_code in (301,302,303,307,308) and TEST_DOMAIN in location:
            with lock:
                if base_url not in vulnerable_urls:
                    vulnerable_urls.add(base_url)
            print(f"[VULNERÁVEL] {base_url} -> {location}")
            save_result(base_url, param, payload, location, resp.status_code)
        else:
            print(f"[SEGURO] {base_url}")
            mark_safe(base_url)
    except Exception as e:
        log(f"[ERRO] {base_url}: {e}")
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

# ---------------- CRAWLER ----------------
def crawl(url, depth, executor):
    if depth > MAX_CRAWL_DEPTH:
        return
    with lock:
        if url in visited_urls:
            return
        visited_urls.add(url)
    try:
        resp = requests.get(url, headers=random_headers(), timeout=6)
        if "text/html" not in resp.headers.get("Content-Type",""):
            return
        soup = BeautifulSoup(resp.text, "html.parser")
        links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)]
        for link in links:
            print(f"[COLETADA] {link}")
    except Exception as e:
        log(f"[ERRO] Crawling {url}: {e}")
        links = []
    for link in links:
        if urlparse(link).scheme.startswith("http"):
            with lock:
                if link not in visited_urls:
                    executor.submit(crawl, link, depth+1, executor)
            if "?" in link:
                for param in params_to_test:
                    for payload in payloads:
                        executor.submit(test_url, link, param, payload)

# ---------------- COLETA DE URLs ----------------
def get_wayback_urls(domain):
    urls = set()
    try:
        log(f"[INFO] Wayback Machine: coletando URLs de {domain}")
        resp = requests.get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey", timeout=10)
        data = resp.json()
        for entry in data[1:]:
            if "?" in entry[0]:
                urls.add(entry[0])
                print(f"[COLETADA] {entry[0]}")
        log(f"[INFO] Wayback Machine: {len(urls)} URLs coletadas")
    except:
        log("[!] Falha Wayback Machine")
    return urls

def get_duckduckgo_urls(domain, max_pages=2):
    urls = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    for page in range(max_pages):
        try:
            q = f"site:{domain}"
            r = requests.get(f"https://html.duckduckgo.com/html/?q={q}&s={page*50}", headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a['href']
                if domain in href and "?" in href:
                    urls.add(href)
                    print(f"[COLETADA] {href}")
            time.sleep(1)
        except:
            pass
    log(f"[INFO] DuckDuckGo: {len(urls)} URLs coletadas")
    return urls

def get_bing_urls(domain, max_pages=2):
    urls = set()
    headers = {"User-Agent": "Mozilla/5.0"}
    for page in range(max_pages):
        try:
            q = f"site:{domain}"
            r = requests.get(f"https://www.bing.com/search?q={q}&first={page*10}", headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a['href']
                if domain in href and "?" in href:
                    urls.add(href)
                    print(f"[COLETADA] {href}")
            time.sleep(1)
        except:
            pass
    log(f"[INFO] Bing: {len(urls)} URLs coletadas")
    return urls

# ---------------- SUBDOMÍNIOS C99.nl ----------------
def get_subdomains_c99(domain):
    subdomains = set()
    try:
        print(f"[INFO] Coletando subdomínios via C99.nl para {domain}")
        url = f"https://subdomainfinder.c99.nl/{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        for td in soup.find_all("td"):
            sub = td.get_text().strip()
            if domain in sub:
                subdomains.add(sub)
                print(f"[COLETADA] Subdomínio: {sub}")
        print(f"[INFO] Subdomínios encontrados: {len(subdomains)}")
    except Exception as e:
        print(f"[!] Falha ao buscar subdomínios: {e}")
    return subdomains

# ---------------- MAIN ----------------
def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Open Redirect Scanner completo")
    parser.add_argument("-u", "--url", help="URL única para testar")
    parser.add_argument("-l", "--list", help="Arquivo com lista de URLs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")
    args = parser.parse_args()
    VERBOSE = args.verbose

    # CSV e TXT
    with open(results_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["URL", "Parâmetro", "Payload", "Status Code", "Location"])
    open(vulnerable_txt, "w").close()
    open(safe_txt, "w").close()

    urls_to_scan = set()

    if args.url:
        urls_to_scan.add(args.url)
        domain = urlparse(args.url).netloc
        # Subdomínios via C99.nl
        subdomains = get_subdomains_c99(domain)
        for sub in subdomains:
            urls_to_scan.add(f"http://{sub}")
            urls_to_scan.add(f"https://{sub}")
        # URLs históricas e indexadas
        urls_to_scan.update(get_wayback_urls(domain))
        urls_to_scan.update(get_duckduckgo_urls(domain))
        urls_to_scan.update(get_bing_urls(domain))
    elif args.list:
        try:
            with open(args.list, "r") as f:
                urls_to_scan.update(line.strip() for line in f if "http" in line)
        except:
            print("[!] Arquivo inválido")
            return
    else:
        print("[!] Informe -u <URL> ou -l <arquivo>")
        return

    log(f"[INFO] Total de URLs coletadas para scan: {len(urls_to_scan)}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for url in urls_to_scan:
            # Crawl
            executor.submit(crawl, url, 0, executor)
            # Teste imediato se a URL tiver parâmetros
            if "?" in url:
                for param in params_to_test:
                    for payload in payloads:
                        executor.submit(test_url, url, param, payload)

if __name__ == "__main__":
    main()
