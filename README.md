<div align="center">

```
  __/\\\______________________________________________________/\\\\\\\\\\\\\\\___________
  _\/\\\______________________________________________________\/\\\///////////____________
  _\/\\\__________________________________________/\\\__/\\\__\/\\\______________________
  _\/\\\______________/\\\\\\\\\_____/\\\\\\\\\\\__\//\\\/\\\__\/\\\\\\\\\\\______/\\\____
  _\/\\\______________\////////\\\___\///////\\\/_____\//\\\\\___\/\\\///////______\/\\\___
  _\/\\\_______________/\\\\\\\\\\_______/\\\/________\//\\\____\/\\\______________\/\\\__
  _\/\\\______________/\\\/////\\\_____/\\\/_______/\\_/\\\_____\/\\\______________\/\\\__
  _\/\\\\\\\\\\\\\\\_\//\\\\\\\\/\\__/\\\\\\\\\\\_\//\\\\/______\/\\\______________\//\\\_
  _\///////////////___\////////\//__\///////////__\////________\///________________\//__
```

# lazyFuzz

**Fast, flexible, and full-featured web fuzzer — built for security professionals.**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-4.4.0-orange?style=flat-square)]()

</div>

---

## 📖 What is lazyFuzz?

**lazyFuzz** is a high-performance, multi-purpose web fuzzer written in Go. Designed to be as flexible as possible, it supports everything from simple directory enumeration to complex multi-wordlist attacks with header injection, response filtering, recursive scanning, and structured output — all from a single binary.

It is inspired by tools like `ffuf` and `dirsearch`, but built to be a single-file, easy-to-extend, fully customizable fuzzing engine.

> ⚠️ **Legal Disclaimer:** lazyFuzz is intended for **authorized security testing only**. Use this tool only on systems you own or have explicit written permission to test. Unauthorized use against systems is illegal and unethical.

---

## ✨ Features

| Category | Features |
|---|---|
| 🌐 **HTTP** | Custom methods, headers, cookies, POST data, HTTP/2, TLS client certs, proxy, SOCKS5, replay proxy, follow redirects, raw request files |
| 🎯 **Input** | Multiple wordlists with custom keywords, DirSearch mode, extension expansion, encoders (urlencode/b64/html), shell command input, clusterbomb/pitchfork/sniper modes |
| 🔍 **Matching** | Match by status code range, response size, line count, word count, regexp, TTFB — with AND/OR logic |
| 🚫 **Filtering** | Filter by status code, size, lines, words, regexp, TTFB — with AND/OR logic |
| ⚙️ **General** | Auto-calibration, per-host calibration, rate limiting, delay, random delay, concurrent threads, max time, silent/verbose mode, colorized output |
| 📤 **Output** | JSON, extended JSON, CSV, extended CSV, Markdown, HTML report — single file or directory, debug log |
| 🔁 **Recursion** | Recursive scanning with depth control, default and greedy strategies |
| 🎲 **Evasion** | Random User-Agent rotation (15 real browser UAs), dynamic header substitution per URL (`Referer`, `X-Original-URL`, etc.) |
| 📊 **Progress** | Real-time URL checkpoint logging when using `-l` |

---

## 📦 Installation

### Build from source

```bash
git clone https://github.com/Fantasymind/lazyFuzz.git
cd lazyFuzz
go mod tidy
go build -o lazyfuzz fuzz.go
chmod +x lazyfuzz
sudo mv lazyfuzz /usr/local/bin/
```

### Requirements

- Go 1.21+
- `golang.org/x/net` (auto-installed via `go mod tidy`)

---

## 🚀 Quick Start

```bash
# Basic directory fuzzing
lazyfuzz -u https://example.com -w wordlist.txt

# With color, follow redirects, filter 404
lazyfuzz -u https://example.com -w wordlist.txt -c -r -fc 404

# Fuzz multiple targets from file
lazyfuzz -l urls.txt -w wordlist.txt -t 50 -c -o results.json
```

---

## 💡 Best Usage Example

The following command demonstrates a full-featured scan across multiple targets with header bypass techniques, extension expansion, recursive fuzzing, and structured output:

```bash
lazyfuzz -l urls.txt:FUZZ -w wordlist.txt \
  -e .html,.php,.txt,.pdf,.js,.zip,.bak,.env \
  -X POST \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Original-URL: /FUZZ" \
  -H "X-Rewrite-URL: /FUZZ" \
  -H "Referer: URL" \
  -t 100 -r -ac -c \
  -recursion -recursion-depth 2 \
  -fc 400,401,402,403,404,429,500,501,502,503 \
  -o results.json \
  -rua
```

### What each flag does

| Flag | Purpose |
|---|---|
| `-l urls.txt:FUZZ` | Load target URLs from file. The `:FUZZ` suffix declares the keyword used as a template variable in headers |
| `-w wordlist.txt` | Path wordlist to fuzz against each target |
| `-e .html,.php,.txt,...` | Expand each wordlist entry with these extensions (e.g. `admin` → `admin.php`, `admin.bak`, etc.) |
| `-X POST` | Use HTTP POST method |
| `-H "X-Forwarded-For: 127.0.0.1"` | Spoof source IP header — common WAF bypass technique |
| `-H "X-Real-IP: 127.0.0.1"` | Additional IP spoofing header |
| `-H "X-Original-URL: /FUZZ"` | Dynamically substituted with the current fuzz path — tests URL override bypasses |
| `-H "X-Rewrite-URL: /FUZZ"` | Same as above — tests rewrite-based access control bypasses |
| `-H "Referer: URL"` | `URL` is auto-replaced with the current base target URL per request |
| `-t 100` | 100 concurrent threads |
| `-r` | Follow HTTP redirects |
| `-ac` | Auto-calibrate filters — probe a nonexistent path first to establish baseline response, then filter noise automatically |
| `-c` | Colorize output by status code |
| `-recursion -recursion-depth 2` | Recursively fuzz discovered directories up to depth 2 |
| `-fc 400,401,...,503` | Filter out these status codes from results (noise reduction) |
| `-o results.json` | Save all matched results to a JSON file |
| `-rua` | Rotate random real browser User-Agent per request |

### Dynamic header substitution

When using `-l`, headers support two automatic substitutions per request:

| Placeholder | Replaced with |
|---|---|
| `URL` | The current base URL from the `-l` file (e.g. `https://target.com`) |
| `/FUZZ` or `FUZZ` | The path component of the current fuzzed URL (e.g. `/admin.php`) |

This means `Referer: URL` becomes `Referer: https://target.com` for each target automatically — no manual scripting needed.

---

## 📋 All Options

```
━━━ HTTP OPTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -H <header>            Header "Name: Value". Can be used multiple times.
  -X <method>            HTTP method (default: GET)
  -b <cookies>           Cookie data "NAME1=VALUE1; NAME2=VALUE2"
  -cc <cert>             Client certificate (PEM)
  -ck <key>              Client key (PEM)
  -d <data>              POST data / request body
  -http2                 Use HTTP/2 protocol
  -ignore-body           Do not fetch response body
  -r                     Follow redirects
  -raw                   Do not encode URI
  -recursion             Recursive scanning (FUZZ keyword only)
  -recursion-depth <n>   Maximum recursion depth (default: 0)
  -recursion-strategy    "default" (redirect) or "greedy" (all matches)
  -replay-proxy <url>    Replay matched requests to this proxy
  -sni <host>            Target TLS SNI
  -timeout <n>           Request timeout in seconds (default: 10)
  -u <url>               Single target URL
  -x <url>               Proxy (http:// or socks5://)

━━━ GENERAL OPTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -V                     Show version
  -ac                    Auto-calibrate filters
  -acc <str>             Custom calibration string (repeatable, implies -ac)
  -ach                   Per-host autocalibration
  -ack <kw>              Calibration keyword (default: FUZZ)
  -acs <strategy>        Custom calibration strategy (repeatable, implies -ac)
  -c                     Colorize output
  -config <file>         Load config from file
  -json                  JSON output (newline-delimited)
  -maxtime <n>           Max total run time in seconds
  -maxtime-job <n>       Max time per job in seconds
  -noninteractive        Disable interactive console
  -p <delay>             Delay between requests ("0.1" or "0.1-2.0")
  -rate <n>              Requests per second limit
  -rua                   Random browser User-Agent per request
  -s                     Silent mode
  -sa                    Stop on all errors (implies -sf -se)
  -se                    Stop on spurious errors
  -sf                    Stop if >95% responses are 403
  -t <n>                 Concurrent threads (default: 40)
  -v                     Verbose output

━━━ MATCHER OPTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -mc <codes>            Match status codes (default: 200-299,301,302,307,401,403,405,500)
  -ml <n>                Match line count
  -mmode <op>            Matcher operator: and / or (default: or)
  -mr <regexp>           Match response body regexp
  -ms <n>                Match response size in bytes
  -mt <ms>               Match TTFB: ">100" or "<100"
  -mw <n>                Match word count

━━━ FILTER OPTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -fc <codes>            Filter status codes (ranges supported: 400-404)
  -fl <n>                Filter by line count
  -fmode <op>            Filter operator: and / or (default: or)
  -fr <regexp>           Filter response body regexp
  -fs <n>                Filter by response size
  -ft <ms>               Filter by TTFB: ">100" or "<100"
  -fw <n>                Filter by word count

━━━ INPUT OPTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -D                     DirSearch compatibility mode (use with -e)
  -e <exts>              Extension list: php,html,bak
  -enc <enc>             Keyword encoder: 'FUZZ:urlencode b64encode'
  -ic                    Ignore wordlist comments
  -input-cmd <cmd>       Shell command as input source
  -input-num <n>         Number of inputs from -input-cmd (default: 100)
  -input-shell <shell>   Shell for -input-cmd
  -mode <mode>           Multi-wordlist mode: clusterbomb / pitchfork / sniper
  -request <file>        Raw HTTP request file
  -request-proto <p>     Protocol for raw request (default: https)
  -w <file[:KEYWORD]>    Wordlist file, optional keyword (repeatable)

━━━ OUTPUT OPTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  -debug-log <file>      Write internal logs to file
  -o <file>              Output file
  -od <dir>              Output directory (one file per format)
  -of <format>           Format: json, ejson, html, md, csv, ecsv, all
  -or                    Skip output file if no results
```

---

## 🔧 More Usage Examples

### Fuzz with extension expansion (DirSearch style)

```bash
lazyfuzz -u https://example.com -w common.txt \
  -D -e php,html,txt,bak,old -c -r -fc 404
```

### Multi-wordlist clusterbomb

```bash
lazyfuzz -u "https://example.com/api/PARAM/VAL" \
  -w params.txt:PARAM \
  -w values.txt:VAL \
  -mode clusterbomb -mc 200 -c
```

### Fuzz from raw Burp Suite request

```bash
lazyfuzz -request burp_req.txt -w paths.txt \
  -request-proto https -c -o results.html -of html
```

### Rate-limited scan with delay

```bash
lazyfuzz -u https://example.com -w paths.txt \
  -t 10 -p "0.5-1.5" -rate 5 -c -fc 404,429
```

### Match only responses containing keyword

```bash
lazyfuzz -u https://example.com -w paths.txt \
  -mc all -mr "admin|dashboard|config" -c
```

### Save results in all formats

```bash
lazyfuzz -u https://example.com -w paths.txt \
  -od ./scan_output -of all -c
```

### Silent scan — output JSON only

```bash
lazyfuzz -u https://example.com -w paths.txt \
  -s -json -fc 404 > results.ndjson
```

---

## 📁 Output Formats

| Format | Description |
|---|---|
| `json` | Newline-delimited JSON — pipe-friendly, works with `jq` |
| `ejson` | Pretty-printed JSON array |
| `csv` | Compact CSV (url, status, size) |
| `ecsv` | Extended CSV (all fields including lines, words, TTFB) |
| `md` | Markdown table — ready for reports |
| `html` | Dark-themed HTML report with color-coded status codes |
| `all` | Generate all of the above simultaneously |

---

## 🏗️ Architecture

```
lazyFuzz
├── Input Engine      → -w (multi-wordlist), -l (URL list), -input-cmd
├── Combination Layer → clusterbomb / pitchfork / sniper
├── Extension Engine  → -e / -D expansion per entry
├── Encoder Layer     → urlencode / b64encode / htmlencode per keyword
├── HTTP Engine       → concurrent workers, TLS, HTTP/2, proxy
├── Matcher Engine    → status, size, lines, words, regexp, TTFB (AND/OR)
├── Filter Engine     → inverse of matcher — drops unwanted responses
└── Output Engine     → terminal (colorized) + file (6 formats)
```

---


## 🔗 Links

- **Repository:** https://github.com/Fantasymind/lazyFuzz
- **Issues:** https://github.com/Fantasymind/lazyFuzz/issues

---

<div align="center">
<sub>Built with ❤️ for the security research community. Use responsibly.</sub>
</div>
