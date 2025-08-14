import os, re, io, json, time, math, glob, pathlib, requests, shutil, zipfile, urllib.parse, hashlib, random, string, base64, csv
from bs4 import BeautifulSoup
from readability import Document
from dateutil import tz
from datetime import datetime
from PyPDF2 import PdfReader
import ast

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.1:8b"

AGENT_NAME = "LocalAgent"
AGENT_GOAL = (
    "You are a helpful *local* AI agent on the user's Mac. "
    "Use tools when they help. Be concise by default."
)

ROOT = pathlib.Path.cwd().resolve()

def _within_root(p: pathlib.Path) -> bool:
    try:
        p.resolve().relative_to(ROOT)
        return True
    except Exception:
        return False

def _sanitize_relpath(path_str: str) -> pathlib.Path:
    p = (ROOT / path_str).resolve()
    if not _within_root(p):
        raise ValueError("Access outside project folder is not allowed.")
    return p

MEM = {
    "todos": [],
    "notes": [],
    "history": [
        {"role":"system","content":AGENT_GOAL},
        {"role":"system","content":f"Your name is {AGENT_NAME}. Keep replies under 150 words unless asked."}
    ],
}

def tool_get_time(args):
    tz_local = tz.tzlocal()
    now = datetime.now(tz_local)
    return {"now": now.strftime("%Y-%m-%d %H:%M:%S %Z")}

def tool_todo_add(args):
    item = (args or {}).get("item","").strip()
    if item:
        MEM["todos"].append(item)
    return {"todos": MEM["todos"]}

def tool_todo_clear(args):
    MEM["todos"].clear()
    return {"todos": MEM["todos"]}

def tool_notes_add(args):
    text = (args or {}).get("text","").strip()
    if text:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        MEM["notes"].append({"ts": ts, "text": text})
    return {"notes": MEM["notes"]}

def tool_notes_list(args):
    return {"notes": MEM["notes"]}

class SafeCalc(ast.NodeVisitor):
    ALLOWED = {
        ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Constant,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow, ast.Mod, ast.FloorDiv,
        ast.USub, ast.UAdd, ast.Load, ast.Call, ast.Name
    }
    ALLOWED_FUNCS = {"sqrt": math.sqrt, "log": math.log, "ln": math.log,
                     "log10": math.log10, "sin": math.sin, "cos": math.cos,
                     "tan": math.tan, "pi": math.pi, "e": math.e}
    def visit(self, node):
        if type(node) not in self.ALLOWED:
            raise ValueError(f"Disallowed expression: {type(node).__name__}")
        return super().visit(node)
    def eval(self, expr: str):
        tree = ast.parse(expr, mode="eval")
        self.visit(tree)
        return eval(compile(tree, "<calc>", "eval"), {"__builtins__": {}}, self.ALLOWED_FUNCS)

def tool_calc(args):
    expr = (args or {}).get("expression","").strip()
    if not expr:
        raise ValueError("Missing 'expression'.")
    res = SafeCalc().eval(expr)
    return {"expression": expr, "result": res}

def tool_convert(args):
    v = float((args or {}).get("value"))
    src = (args or {}).get("from","").lower()
    dst = (args or {}).get("to","").lower()
    if src==dst:
        return {"value": v, "from": src, "to": dst, "result": v}
    if src in {"c","°c","celsius"} and dst in {"f","°f","fahrenheit"}:
        return {"result": v*9/5+32, "from": src, "to": dst}
    if src in {"f","°f","fahrenheit"} and dst in {"c","°c","celsius"}:
        return {"result": (v-32)*5/9, "from": src, "to": dst}
    L = {"mm":0.001,"cm":0.01,"m":1.0,"km":1000,"in":0.0254,"ft":0.3048,"mi":1609.344}
    if src in L and dst in L:
        return {"result": v*L[src]/L[dst], "from": src, "to": dst}
    M = {"g":0.001,"kg":1.0,"lb":0.45359237}
    if src in M and dst in M:
        return {"result": v*M[src]/M[dst], "from": src, "to": dst}
    raise ValueError("Unsupported units. Try length mm/cm/m/km/in/ft/mi, mass g/kg/lb, temp C/F.")

def tool_files_list(args):
    pattern = (args or {}).get("glob","**/*")
    max_items = int((args or {}).get("max_items", 50))
    files = []
    for p in ROOT.glob(pattern):
        if p.is_file() and _within_root(p):
            rel = p.relative_to(ROOT).as_posix()
            files.append(rel)
            if len(files) >= max_items:
                break
    return {"files": files}

def _read_text_file(p: pathlib.Path, max_bytes=300_000):
    data = p.read_bytes()
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")

def tool_file_read(args):
    path = (args or {}).get("path","")
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"{path} not found.")
    ext = p.suffix.lower()
    if ext in {".txt",".md",".py",".json",".csv"}:
        return {"path": path, "text": _read_text_file(p)}
    elif ext == ".pdf":
        text = []
        with open(p, "rb") as f:
            reader = PdfReader(f)
            pages = min(len(reader.pages), int((args or {}).get("max_pages", 10)))
            for i in range(pages):
                try:
                    text.append(reader.pages[i].extract_text() or "")
                except Exception:
                    text.append("")
        return {"path": path, "text": "\n".join(text)}
    else:
        raise ValueError("Unsupported extension. Use txt, md, py, json, csv, pdf.")

def tool_search_local(args):
    query = (args or {}).get("query","").strip()
    pattern = (args or {}).get("glob","**/*")
    max_hits = int((args or {}).get("max_hits", 30))
    if not query:
        raise ValueError("Missing 'query'.")
    hits = []
    for p in ROOT.glob(pattern):
        if p.is_file() and p.suffix.lower() in {".txt",".md",".py",".json",".csv"} and _within_root(p):
            try:
                content = _read_text_file(p, max_bytes=200_000)
                for line_no, line in enumerate(content.splitlines(), 1):
                    if query.lower() in line.lower():
                        hits.append({"file": p.relative_to(ROOT).as_posix(), "line": line_no, "text": line.strip()[:300]})
                        if len(hits) >= max_hits:
                            return {"hits": hits}
            except Exception:
                continue
    return {"hits": hits}

def tool_web_fetch(args):
    url = (args or {}).get("url","").strip()
    if not url.startswith(("http://","https://")):
        raise ValueError("URL must start with http:// or https://")
    r = requests.get(url, timeout=20, headers={"User-Agent":"LocalAgent/1.0"})
    r.raise_for_status()
    html = r.text
    doc = Document(html)
    title = doc.short_title()
    article_html = doc.summary(html_partial=True)
    soup = BeautifulSoup(article_html, "lxml")
    text = soup.get_text(separator="\n")
    text = re.sub(r"\n{3,}", "\n\n", text.strip())[:10000]
    return {"title": title, "url": url, "text": text}

def tool_dir_list(args):
    path = _sanitize_relpath((args or {}).get("path","."))
    max_items = int((args or {}).get("max_items", 200))
    out = []
    for p in sorted(path.iterdir()):
        if not _within_root(p):
            continue
        try:
            size = p.stat().st_size if p.is_file() else sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
        except Exception:
            size = None
        out.append({"name": p.relative_to(ROOT).as_posix(),"is_dir": p.is_dir(), "size": size})
        if len(out) >= max_items:
            break
    return {"items": out}

def tool_file_write(args):
    path = (args or {}).get("path","")
    text = (args or {}).get("text","")
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return {"path": p.relative_to(ROOT).as_posix(), "bytes": len(text.encode("utf-8"))}

def tool_file_append(args):
    path = (args or {}).get("path","")
    text = (args or {}).get("text","")
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(text)
    return {"path": p.relative_to(ROOT).as_posix(), "appended_bytes": len(text.encode("utf-8"))}

def tool_file_delete(args):
    path = (args or {}).get("path","")
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"{path} not found or not a file.")
    p.unlink()
    return {"deleted": path}

def tool_file_move(args):
    src = (args or {}).get("src","")
    dst = (args or {}).get("dst","")
    if not src or not dst:
        raise ValueError("Need 'src' and 'dst'.")
    psrc = _sanitize_relpath(src)
    pdst = _sanitize_relpath(dst)
    pdst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(psrc.as_posix(), pdst.as_posix())
    return {"moved": src, "to": dst}

def tool_zip_create(args):
    src = (args or {}).get("src","")
    zip_path = (args or {}).get("zip_path","")
    if not src or not zip_path:
        raise ValueError("Need 'src' and 'zip_path'.")
    psrc = _sanitize_relpath(src)
    pzip = _sanitize_relpath(zip_path)
    pzip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pzip, "w", zipfile.ZIP_DEFLATED) as z:
        if psrc.is_dir():
            for f in psrc.rglob("*"):
                if f.is_file() and _within_root(f):
                    z.write(f, f.relative_to(ROOT))
        else:
            z.write(psrc, psrc.relative_to(ROOT))
    return {"zip": pzip.relative_to(ROOT).as_posix()}

def tool_unzip(args):
    zip_path = (args or {}).get("zip_path","")
    dest = (args or {}).get("dest","")
    if not zip_path or not dest:
        raise ValueError("Need 'zip_path' and 'dest'.")
    pzip = _sanitize_relpath(zip_path)
    pdest = _sanitize_relpath(dest)
    pdest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(pzip) as z:
        z.extractall(pdest)
        names = z.namelist()
    return {"unzipped_to": pdest.relative_to(ROOT).as_posix(), "files": names}

def tool_download(args):
    url = (args or {}).get("url","").strip()
    dest = (args or {}).get("dest","").strip()
    if not url or not dest:
        raise ValueError("Need 'url' and 'dest'.")
    p = _sanitize_relpath(dest)
    p.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, timeout=60, headers={"User-Agent":"LocalAgent/1.0"})
    r.raise_for_status()
    p.write_bytes(r.content)
    return {"url": url, "saved_as": p.relative_to(ROOT).as_posix(), "bytes": len(r.content)}

def tool_http_head(args):
    url = (args or {}).get("url","").strip()
    if not url.startswith(("http://","https://")):
        raise ValueError("Bad URL.")
    r = requests.head(url, timeout=20, allow_redirects=True)
    return {"url": r.url, "status": r.status_code, "headers": dict(r.headers)}

def tool_web_search(args):
    q = (args or {}).get("query","").strip()
    max_results = int((args or {}).get("max_results", 5))
    if not q:
        raise ValueError("Missing 'query'.")
    params = {"q": q, "t": "localagent", "ia": "web"}
    url = "https://duckduckgo.com/html/?" + urllib.parse.urlencode(params)
    r = requests.get(url, timeout=30, headers={"User-Agent":"Mozilla/5.0"})
    r.raise_for_status()
    s = BeautifulSoup(r.text, "lxml")
    results = []
    for res in s.select(".result")[:max_results]:
        a = res.select_one("a.result__a")
        snip = res.select_one(".result__snippet")
        if a and a.get("href"):
            results.append({"title": a.get_text(strip=True), "href": a["href"], "snippet": snip.get_text(" ", strip=True) if snip else ""})
    return {"results": results}

def tool_hash_file(args):
    path = (args or {}).get("path","")
    algo = (args or {}).get("algo","sha256").lower()
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    h = hashlib.new(algo)
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return {"path": path, algo: h.hexdigest()}

def tool_hash_text(args):
    text = (args or {}).get("text","")
    algo = (args or {}).get("algo","sha256").lower()
    h = hashlib.new(algo)
    h.update(text.encode())
    return {algo: h.hexdigest()}

def tool_random_string(args):
    length = int((args or {}).get("length", 12))
    chars = string.ascii_letters + string.digits
    return {"random": "".join(random.choice(chars) for _ in range(length))}

def tool_random_int(args):
    start = int((args or {}).get("start", 0))
    end = int((args or {}).get("end", 100))
    return {"random": random.randint(start, end)}

def tool_url_encode(args):
    s = (args or {}).get("text","")
    return {"encoded": urllib.parse.quote_plus(s)}

def tool_url_decode(args):
    s = (args or {}).get("text","")
    return {"decoded": urllib.parse.unquote_plus(s)}

def tool_base64_encode(args):
    s = (args or {}).get("text","")
    return {"b64": base64.b64encode(s.encode()).decode()}

def tool_base64_decode(args):
    s = (args or {}).get("b64","")
    return {"text": base64.b64decode(s.encode()).decode(errors="replace")}

def tool_json_read(args):
    path = (args or {}).get("path","")
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    return {"path": path, "data": data}

def tool_json_write(args):
    path = (args or {}).get("path","")
    data = (args or {}).get("data",{})
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": p.relative_to(ROOT).as_posix()}

def tool_csv_head(args):
    path = (args or {}).get("path","")
    n = int((args or {}).get("rows", 5))
    if not path:
        raise ValueError("Missing 'path'.")
    p = _sanitize_relpath(path)
    rows = []
    with p.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            rows.append(row)
            if i+1 >= n:
                break
    return {"rows": rows}

def tool_path_info(args):
    path = (args or {}).get("path",".")
    p = _sanitize_relpath(path)
    return {
        "abs": str(p),
        "exists": p.exists(),
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
        "size": p.stat().st_size if p.exists() and p.is_file() else None,
        "parts": p.relative_to(ROOT).as_posix().split("/") if _within_root(p) else []
    }

TOOLS = {
    "get_time": {"fn": tool_get_time, "schema": {"type":"function","function":{"name":"get_time","description":"Get current local time with timezone.","parameters":{"type":"object","properties":{}}}}},
    "todo_add": {"fn": tool_todo_add, "schema": {"type":"function","function":{"name":"todo_add","description":"Add a todo to short-term memory.","parameters":{"type":"object","properties":{"item":{"type":"string"}},"required":["item"]}}}},
    "todo_clear": {"fn": tool_todo_clear, "schema": {"type":"function","function":{"name":"todo_clear","description":"Clear all todos.","parameters":{"type":"object","properties":{}}}}}, 
    "notes_add": {"fn": tool_notes_add, "schema": {"type":"function","function":{"name":"notes_add","description":"Append a note with timestamp.","parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}}},
    "notes_list": {"fn": tool_notes_list, "schema": {"type":"function","function":{"name":"notes_list","description":"List notes captured in this session.","parameters":{"type":"object","properties":{}}}}}, 
    "calc": {"fn": tool_calc, "schema": {"type":"function","function":{"name":"calc","description":"Safely evaluate a math expression.","parameters":{"type":"object","properties":{"expression":{"type":"string"}},"required":["expression"]}}}},
    "convert": {"fn": tool_convert, "schema": {"type":"function","function":{"name":"convert","description":"Convert units: length(mm,cm,m,km,in,ft,mi), mass(g,kg,lb), temperature(C,F).","parameters":{"type":"object","properties":{"value":{"type":"number"},"from":{"type":"string"},"to":{"type":"string"}},"required":["value","from","to"]}}}},
    "files_list": {"fn": tool_files_list, "schema": {"type":"function","function":{"name":"files_list","description":"List files in the project root by glob (**/*).","parameters":{"type":"object","properties":{"glob":{"type":"string"},"max_items":{"type":"integer","minimum":1}}}}}},
    "file_read": {"fn": tool_file_read, "schema": {"type":"function","function":{"name":"file_read","description":"Read a local file within the project (txt, md, py, json, csv, pdf).","parameters":{"type":"object","properties":{"path":{"type":"string"},"max_pages":{"type":"integer"}},"required":["path"]}}}},
    "search_local": {"fn": tool_search_local, "schema": {"type":"function","function":{"name":"search_local","description":"Search text query across project files (txt, md, py, json, csv).","parameters":{"type":"object","properties":{"query":{"type":"string"},"glob":{"type":"string"},"max_hits":{"type":"integer","minimum":1,"maximum":200}},"required":["query"]}}}},
    "web_fetch": {"fn": tool_web_fetch, "schema": {"type":"function","function":{"name":"web_fetch","description":"Download a webpage and extract readable text.","parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}},
    "dir_list": {"fn": tool_dir_list, "schema": {"type":"function","function":{"name":"dir_list","description":"List directory contents with sizes.","parameters":{"type":"object","properties":{"path":{"type":"string"},"max_items":{"type":"integer"}}}}}},
    "file_write": {"fn": tool_file_write, "schema": {"type":"function","function":{"name":"file_write","description":"Create/overwrite a text file.","parameters":{"type":"object","properties":{"path":{"type":"string"},"text":{"type":"string"}},"required":["path","text"]}}}},
    "file_append": {"fn": tool_file_append, "schema": {"type":"function","function":{"name":"file_append","description":"Append text to a file.","parameters":{"type":"object","properties":{"path":{"type":"string"},"text":{"type":"string"}},"required":["path","text"]}}}},
    "file_delete": {"fn": tool_file_delete, "schema": {"type":"function","function":{"name":"file_delete","description":"Delete a file.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}},
    "file_move": {"fn": tool_file_move, "schema": {"type":"function","function":{"name":"file_move","description":"Move/rename a file or folder.","parameters":{"type":"object","properties":{"src":{"type":"string"},"dst":{"type":"string"}},"required":["src","dst"]}}}},
    "zip_create": {"fn": tool_zip_create, "schema": {"type":"function","function":{"name":"zip_create","description":"Create a zip from a file/folder.","parameters":{"type":"object","properties":{"src":{"type":"string"},"zip_path":{"type":"string"}},"required":["src","zip_path"]}}}},
    "unzip": {"fn": tool_unzip, "schema": {"type":"function","function":{"name":"unzip","description":"Extract a zip archive.","parameters":{"type":"object","properties":{"zip_path":{"type":"string"},"dest":{"type":"string"}},"required":["zip_path","dest"]}}}},
    "download": {"fn": tool_download, "schema": {"type":"function","function":{"name":"download","description":"Download a URL to a file path.","parameters":{"type":"object","properties":{"url":{"type":"string"},"dest":{"type":"string"}},"required":["url","dest"]}}}},
    "http_head": {"fn": tool_http_head, "schema": {"type":"function","function":{"name":"http_head","description":"Fetch HTTP headers.","parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}},
    "web_search": {"fn": tool_web_search, "schema": {"type":"function","function":{"name":"web_search","description":"DuckDuckGo HTML search.","parameters":{"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"integer"}},"required":["query"]}}}},
    "hash_file": {"fn": tool_hash_file, "schema": {"type":"function","function":{"name":"hash_file","description":"Hash a file (e.g., sha256).","parameters":{"type":"object","properties":{"path":{"type":"string"},"algo":{"type":"string"}},"required":["path"]}}}},
    "hash_text": {"fn": tool_hash_text, "schema": {"type":"function","function":{"name":"hash_text","description":"Hash a text string.","parameters":{"type":"object","properties":{"text":{"type":"string"},"algo":{"type":"string"}},"required":["text"]}}}},
    "random_string": {"fn": tool_random_string, "schema": {"type":"function","function":{"name":"random_string","description":"Generate random alphanumeric string.","parameters":{"type":"object","properties":{"length":{"type":"integer"}}}}}},
    "random_int": {"fn": tool_random_int, "schema": {"type":"function","function":{"name":"random_int","description":"Generate random integer in range.","parameters":{"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}}}}}},
    "url_encode": {"fn": tool_url_encode, "schema": {"type":"function","function":{"name":"url_encode","description":"URL-encode text.","parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}}},
    "url_decode": {"fn": tool_url_decode, "schema": {"type":"function","function":{"name":"url_decode","description":"URL-decode text.","parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}}},
    "base64_encode": {"fn": tool_base64_encode, "schema": {"type":"function","function":{"name":"base64_encode","description":"Base64-encode text.","parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}}},
    "base64_decode": {"fn": tool_base64_decode, "schema": {"type":"function","function":{"name":"base64_decode","description":"Base64-decode to text.","parameters":{"type":"object","properties":{"b64":{"type":"string"}},"required":["b64"]}}}},
    "json_read": {"fn": tool_json_read, "schema": {"type":"function","function":{"name":"json_read","description":"Read and parse a JSON file.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}}},
    "json_write": {"fn": tool_json_write, "schema": {"type":"function","function":{"name":"json_write","description":"Write JSON data to file.","parameters":{"type":"object","properties":{"path":{"type":"string"},"data":{"type":"object"}},"required":["path","data"]}}}},
    "csv_head": {"fn": tool_csv_head, "schema": {"type":"function","function":{"name":"csv_head","description":"Read first N rows of a CSV.","parameters":{"type":"object","properties":{"path":{"type":"string"},"rows":{"type":"integer"}},"required":["path"]}}}},
    "path_info": {"fn": tool_path_info, "schema": {"type":"function","function":{"name":"path_info","description":"Get info about a path.","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}}}
}

def chat_ollama(messages, tools=None, stream=False):
    body = {"model": MODEL, "messages": messages, "stream": stream}
    if tools:
        body["tools"] = [t["schema"] for t in tools.values()]
    r = requests.post(OLLAMA_URL, json=body, timeout=300)
    r.raise_for_status()
    return r.json()

def run():
    print(f"{AGENT_NAME} (Ollama) ready. Tools available: {', '.join(sorted(TOOLS.keys()))}. Type 'exit' to quit.")
    while True:
        try:
            user = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye!")
            return
        if user.lower() in {"exit","quit"}:
            print("Bye!")
            return
        MEM["history"].append({"role":"user","content":user})
        resp = chat_ollama(MEM["history"], tools=TOOLS)
        msg = resp.get("message", {})
        tool_calls = msg.get("tool_calls") or []
        for call in tool_calls:
            name = call.get("function", {}).get("name")
            args = call.get("function", {}).get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            result = {"error": f"Unknown tool: {name}"}
            if name in TOOLS:
                try:
                    result = TOOLS[name]["fn"](args)
                except Exception as e:
                    result = {"error": str(e)}
            MEM["history"].append({"role":"tool","name":name,"content":json.dumps(result)})
        if tool_calls:
            resp2 = chat_ollama(MEM["history"], tools=TOOLS)
            msg2 = resp2.get("message", {})
            text = (msg2.get("content") or "").strip()
            MEM["history"].append({"role":"assistant","content":text})
            print(f"\n{AGENT_NAME}: {text}")
        else:
            text = (msg.get("content") or "").strip()
            MEM["history"].append({"role":"assistant","content":text})
            print(f"\n{AGENT_NAME}: {text}")

if __name__ == "__main__":
    run()
