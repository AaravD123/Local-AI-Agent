LocalAgent — a tiny local AI with real tools

A lightweight command-line AI agent that runs fully on your machine with Ollama (default: llama3.1:8b). It can chat, call safe local utilities (read/write files, search, hash, zip, convert units, math, fetch web pages, etc.), and keep short-term memory for notes/todos — all inside your project folder.

✨ Features

Local first. Talks to your locally hosted Ollama model (no cloud by default).

Useful tools, safely sandboxed. File ops are restricted to your project root.

Readable web fetch. Pull readable text from pages with readability + BeautifulSoup.

Quick utilities. Calc, converters, hashing, zipping, randoms, base64, URL encode/decode.

Mini memory. In-session notes & todos.

PDF + text parsing. Read .pdf, .txt, .md, .py, .json, .csv.

🧱 Project Layout (core pieces)

AGENT_NAME, AGENT_GOAL — personality & reply length.

MODEL, OLLAMA_URL — which Ollama model/endpoint to use.

ROOT — sandbox boundary (current working directory).

TOOLS — registry that exposes tool schemas to the model.

_sanitize_relpath() — prevents access outside ROOT.

run() — chat loop with tool call execution.

🔧 Requirements

Python 3.9+ (tested with 3.10/3.11)

Ollama installed and running (ollama serve)

Model pulled locally (default: ollama pull llama3.1:8b)

Python packages:

pip install requests beautifulsoup4 lxml readability-lxml python-dateutil PyPDF2

🚀 Quickstart

Start Ollama and pull a model:

ollama serve
ollama pull llama3.1:8b


Clone / add the script to a folder you’re okay sandboxing as the project root.

Install deps:

pip install requests beautifulsoup4 lxml readability-lxml python-dateutil PyPDF2


Run:

python local_agent.py


You’ll see:

LocalAgent (Ollama) ready. Tools available: base64_decode, base64_encode, ...
Type 'exit' to quit.

⚙️ Configuration

Edit the top of the file or set env vars:

OLLAMA_URL (default http://localhost:11434/api/chat)

MODEL (default llama3.1:8b)

AGENT_NAME (default LocalAgent)

AGENT_GOAL (system prompt)

Sandbox root: ROOT = pathlib.Path.cwd().resolve()

All file and directory tools are locked inside this folder.

🛠️ Built-in Tools (grouped)

Time & Memory

get_time — local time with timezone

todo_add, todo_clear

notes_add, notes_list

Math & Conversion

calc — safe expression evaluator (via ast)

convert — length (mm/cm/m/km/in/ft/mi), mass (g/kg/lb), temp (C/F)

Filesystem (sandboxed to ROOT)

files_list — glob list

dir_list — with sizes

file_read — txt/md/py/json/csv/pdf

file_write, file_append, file_delete, file_move

path_info

Search & Data

search_local — grep-like search across texty files

csv_head — first N rows

json_read, json_write

Compression & Download

zip_create, unzip

download — save URL to a file

http_head — check URL headers

Web & Encoding

web_fetch — fetch + readable article text

web_search — DuckDuckGo HTML results

url_encode, url_decode

base64_encode, base64_decode

Hashing & Random

hash_file, hash_text

random_string, random_int

Tools are exposed to the model via OpenAI-style tool schemas; the agent chooses when to call them.

💬 Usage Examples

Notes

You: add a note: "Call coach at 5pm"
You: list notes


Todos

You: todo "Finish algebra worksheet"
You: clear todos


Files

You: list files matching **/*.py
You: read docs/plan.md
You: write to logs/run.txt with "started at 10:32"


Search

You: search "TODO:" in **/*.py, show up to 20 hits


Web

You: fetch https://example.com and summarize
You: search the web for "python datetime timezone guide"


Utilities

You: convert 72 F to C
You: calc (2^10 - 1) / 3
You: zip src=notebooks zip_path=artifacts/nb.zip

🔒 Safety & Sandboxing

All file paths are sanitized with _sanitize_relpath() to stay inside ROOT.

calc is a restricted ast evaluator; only whitelisted nodes/functions are allowed.

Network fetches are explicit: web_fetch, download, http_head, web_search.

🧠 How It Works (flow)
User input
   ↓
MEM["history"] += user
   ↓
chat_ollama(messages, tools=SCHEMAS)  ──► model may return tool_calls
   ↓                                (name + JSON args)
Execute tool(s) locally and append {"role":"tool","name":..., "content": result}
   ↓
Call model again with tool results
   ↓
Print assistant message, update history

🧪 Tips & Customization

Swap models:

MODEL = "llama3.2:3b-instruct"


Rename/retone the agent:

AGENT_NAME = "MacBuddy"
AGENT_GOAL = "Ultra-concise local helper. Prefer bullet points."


Add a new tool:

Write a tool_*.py-style function

Register it in TOOLS with a JSON schema

The agent can now call it autonomously

🧯 Troubleshooting

requests.exceptions.ConnectionError to Ollama

Ensure ollama serve is running and OLLAMA_URL is correct.

model not found

ollama pull llama3.1:8b (or your chosen model).

PDF returns little text

Many PDFs are images; you’ll need OCR (not included).

Windows path/encoding issues

Use forward slashes in prompts (e.g., data/file.txt) and keep the project inside a simple folder path.

📄 License

MIT — see LICENSE.

🙌 Acknowledgements

Ollama for local LLM serving

readability-lxml, beautifulsoup4, lxml, PyPDF2, python-dateutil

📌 Roadmap (ideas)

Optional OCR for scanned PDFs

Persistent memory across runs

Config file (.localagent.json)

Simple TUI/GUI

Streaming tokens in the CLI

Badges (optional)
![Local](https://img.shields.io/badge/AI-local-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![Sandboxed](https://img.shields.io/badge/fs-sandboxed-important)
