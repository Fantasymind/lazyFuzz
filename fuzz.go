package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

const Version = "lazyFuzz v4.4.0"

// randomUserAgents is a pool of real browser User-Agent strings.
var randomUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
}

func randomUA() string {
	return randomUserAgents[rand.Intn(len(randomUserAgents))]
}

// ============================================================
// Custom flag types
// ============================================================

type headersFlag []string

func (h *headersFlag) String() string { return strings.Join(*h, ", ") }
func (h *headersFlag) Set(v string) error {
	*h = append(*h, v)
	return nil
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ", ") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// intRange represents a single integer value or an inclusive lo-hi range.
// Used by filter flags (-fc, -fl, -fw, -fs).
type intRange struct {
	lo, hi int
}

func (r intRange) contains(v int) bool { return v >= r.lo && v <= r.hi }

// parseIntRanges parses a comma-separated list of values/ranges like "200,300-399,404".
func parseIntRanges(s string) ([]intRange, error) {
	var out []intRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			// Could be a range like "300-399" – but also a negative number; keep it simple
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("range tidak valid: %q", part)
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			out = append(out, intRange{lo, hi})
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("nilai tidak valid: %q", part)
			}
			out = append(out, intRange{n, n})
		}
	}
	return out, nil
}

// matchesAnyRange returns true if v falls within any of the provided ranges.
func matchesAnyRange(v int, ranges []intRange) bool {
	for _, r := range ranges {
		if r.contains(v) {
			return true
		}
	}
	return false
}

// ============================================================
// Config structs
// ============================================================

type FuzzConfig struct {
	// HTTP options
	Method          string
	Headers         []string
	Cookie          string
	PostData        string
	IgnoreBody      bool
	RawURI          bool
	AllowedCodes    map[int]bool
	Recursion       bool
	RecursionDepth  int
	RecursionStrat  string
	ReplayTransport *http.Transport
	ReplayProxy     string
	Timeout         int

	// General options
	Colorize       bool
	JSONOutput     bool
	Silent         bool
	Verbose        bool
	AutoCalib      bool
	AutoCalibStr   []string
	AutoCalibKw    string
	PerHostCalib   bool
	AutoCalibStrat []string
	Delay          string
	Rate           int
	MaxTime        int
	MaxTimeJob     int
	NonInteractive bool
	ScraperFile    string
	Scrapers       string
	StopOnError    bool
	StopOnSpurious bool
	StopOn403      bool

	// Matcher options
	MatchCodes   map[int]bool   // -mc
	MatchAll     bool           // -mc all
	MatchLines   int            // -ml  (0 = disabled)
	MatchWords   int            // -mw  (0 = disabled)
	MatchSize    int            // -ms  (0 = disabled)
	MatchRegexp  *regexp.Regexp // -mr
	MatchTimeOp  string         // -mt operator: ">" or "<"
	MatchTimeMs  int64          // -mt milliseconds threshold
	MatchMode    string         // -mmode: "and" | "or" (default: or)

	// Filter options  (-f* = exclude/drop matching responses)
	FilterCodes  []intRange     // -fc
	FilterLines  []intRange     // -fl
	FilterWords  []intRange     // -fw
	FilterSizes  []intRange     // -fs
	FilterRegexp *regexp.Regexp // -fr
	FilterTimeOp string         // -ft operator: ">" or "<"
	FilterTimeMs int64          // -ft milliseconds threshold
	FilterMode   string         // -fmode: "and" | "or" (default: or)

	// Input options
	Extensions   []string       // -e
	DirSearch    bool           // -D
	Encoders     map[string][]string // -enc: keyword -> []encoderName
	IgnoreComments bool         // -ic
	InputCmd     string         // -input-cmd
	InputNum     int            // -input-num
	InputShell   string         // -input-shell
	WordlistMode string         // -mode: clusterbomb|pitchfork|sniper
	RequestFile  string         // -request
	RequestProto string         // -request-proto
	// Wordlists: list of {keyword, entries}
	Wordlists    []WordlistEntry

	// Output options
	OutputFile    string   // -o
	OutputDir     string   // -od
	OutputFormats []string // -of (json|ejson|html|md|csv|ecsv|all)
	OutputOnlyResults bool // -or: skip creating file if no results
	DebugLogFile  string   // -debug-log

	// Runtime state (atomic)
	startTime  time.Time
	totalReqs  int64
	total403   int64
	stopFlag   int32
	urlIndex   int64      // current URL index for checkpoint log
	resultsMu  sync.Mutex
	results    []JSONRecord
	debugLog   *os.File
	RandomUA   bool       // -rua
}

// JSONRecord is emitted per result when -json is active
type JSONRecord struct {
	URL          string `json:"url"`
	StatusCode   int    `json:"status"`
	Lines        int    `json:"lines"`
	Words        int    `json:"words"`
	Size         int    `json:"size"`
	DurationMs   int64  `json:"duration_ms"`
	Timestamp    string `json:"timestamp"`
}

// WordlistEntry holds one wordlist with its associated keyword.
type WordlistEntry struct {
	Keyword string
	Entries []string
}

// applyEncoder applies a named encoder to a string value.
// Supported encoders: urlencode, b64encode, htmlencode, none.
func applyEncoder(value, encoderName string) string {
	switch strings.ToLower(strings.TrimSpace(encoderName)) {
	case "urlencode":
		return url.QueryEscape(value)
	case "b64encode":
		return base64.StdEncoding.EncodeToString([]byte(value))
	case "htmlencode":
		value = strings.ReplaceAll(value, "&", "&amp;")
		value = strings.ReplaceAll(value, "<", "&lt;")
		value = strings.ReplaceAll(value, ">", "&gt;")
		value = strings.ReplaceAll(value, `"`, "&quot;")
		value = strings.ReplaceAll(value, "'", "&#39;")
		return value
	default: // "none" or unknown
		return value
	}
}

// applyEncoders applies zero or more encoders in sequence.
func applyEncoders(value string, encoders []string) string {
	for _, enc := range encoders {
		value = applyEncoder(value, enc)
	}
	return value
}

// parseEncoders parses "-enc" value like "FUZZ:urlencode b64encode".
// Returns map[keyword][]encoderName.
func parseEncoders(raw string) map[string][]string {
	out := make(map[string][]string)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, ":")
		if idx < 0 {
			continue
		}
		kw := strings.TrimSpace(part[:idx])
		encoderNames := strings.Fields(part[idx+1:])
		out[kw] = encoderNames
	}
	return out
}

// ============================================================
// Input generation helpers
// ============================================================

// generateInputsClusterbomb returns the cartesian product of all wordlists.
// Each item in the result is a map[keyword]value for substitution.
func generateInputsClusterbomb(wlists []WordlistEntry) []map[string]string {
	result := []map[string]string{{}}
	for _, wl := range wlists {
		var next []map[string]string
		for _, existing := range result {
			for _, entry := range wl.Entries {
				clone := make(map[string]string, len(existing)+1)
				for k, v := range existing {
					clone[k] = v
				}
				clone[wl.Keyword] = entry
				next = append(next, clone)
			}
		}
		result = next
	}
	return result
}

// generateInputsPitchfork zips wordlists together (stops at shortest).
func generateInputsPitchfork(wlists []WordlistEntry) []map[string]string {
	if len(wlists) == 0 {
		return nil
	}
	minLen := len(wlists[0].Entries)
	for _, wl := range wlists {
		if len(wl.Entries) < minLen {
			minLen = len(wl.Entries)
		}
	}
	result := make([]map[string]string, minLen)
	for i := range result {
		m := make(map[string]string, len(wlists))
		for _, wl := range wlists {
			m[wl.Keyword] = wl.Entries[i]
		}
		result[i] = m
	}
	return result
}

// generateInputsSniper uses one wordlist at a time, substituting only that
// keyword and leaving others as their literal keyword name.
func generateInputsSniper(wlists []WordlistEntry) []map[string]string {
	var result []map[string]string
	for _, target := range wlists {
		for _, entry := range target.Entries {
			m := make(map[string]string, len(wlists))
			for _, wl := range wlists {
				if wl.Keyword == target.Keyword {
					m[wl.Keyword] = entry
				} else {
					m[wl.Keyword] = wl.Keyword // leave keyword literal
				}
			}
			result = append(result, m)
		}
	}
	return result
}

// substituteKeywords replaces all keywords in template with their values,
// applying any configured encoders.
func substituteKeywords(template string, kv map[string]string, cfg *FuzzConfig) string {
	result := template
	for kw, val := range kv {
		if encs, ok := cfg.Encoders[kw]; ok {
			val = applyEncoders(val, encs)
		}
		result = strings.ReplaceAll(result, kw, val)
	}
	return result
}

// loadRawRequest reads a raw HTTP request file and builds a *http.Request.
func loadRawRequest(path, proto string) (method, rawURL string, headers map[string]string, body string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		err = fmt.Errorf("request file kosong")
		return
	}
	// First line: METHOD /path HTTP/version
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		err = fmt.Errorf("request line tidak valid: %s", lines[0])
		return
	}
	method = parts[0]
	path2 := parts[1]

	headers = make(map[string]string)
	i := 1
	var host string
	for i < len(lines) && lines[i] != "" {
		if idx := strings.Index(lines[i], ":"); idx >= 0 {
			k := strings.TrimSpace(lines[i][:idx])
			v := strings.TrimSpace(lines[i][idx+1:])
			headers[k] = v
			if strings.EqualFold(k, "host") {
				host = v
			}
		}
		i++
	}
	i++ // skip blank line
	if i < len(lines) {
		body = strings.Join(lines[i:], "\n")
	}

	rawURL = proto + "://" + host + path2
	return
}

// inputsFromCmd runs a shell command repeatedly (inputNum times) and
// collects each line of stdout as an input entry for keyword FUZZ.
func inputsFromCmd(cmdStr, shell string, inputNum int) []string {
	var entries []string
	if shell == "" {
		shell = "/bin/sh"
	}
	for i := 0; i < inputNum; i++ {
		out, err := exec.Command(shell, "-c", cmdStr).Output()
		if err != nil {
			continue
		}
		line := strings.TrimSpace(string(out))
		if line != "" {
			entries = append(entries, line)
		}
	}
	return entries
}

// ============================================================
// Banner & Help
// ============================================================

const banner = `
  __/\\\______________________________________________________/\\\\\\\\\\\\\\\___________
  _\/\\\______________________________________________________\/\\\///////////____________
  _\/\\\__________________________________________/\\\__/\\\__\/\\\______________________
  _\/\\\______________/\\\\\\\\\_____/\\\\\\\\\\\__\//\\\/\\\__\/\\\\\\\\\\\______/\\\____
  _\/\\\______________\////////\\\___\///////\\\/_____\//\\\\\___\/\\\///////______\/\\\___
  _\/\\\_______________/\\\\\\\\\\_______/\\\/________\//\\\____\/\\\______________\/\\\__
  _\/\\\______________/\\\/////\\\_____/\\\/_______/\\_/\\\_____\/\\\______________\/\\\__
  _\/\\\\\\\\\\\\\\\_\//\\\\\\\\/\\__/\\\\\\\\\\\_\//\\\\/______\/\\\______________\//\\\_
  _\///////////////___\////////\//__\///////////__\////________\///________________\//__`

func printBanner() {
	cyan   := "\033[36m"
	yellow := "\033[33m"
	reset  := "\033[0m"

	fmt.Println(cyan + banner + reset)
	fmt.Printf("\n  %s%s%s\n\n", yellow, Version, reset)
}

func printHelp() {
	// Color codes
	bold   := "\033[1m"
	cyan   := "\033[36m"
	yellow := "\033[33m"
	green  := "\033[32m"
	dim    := "\033[2m"
	reset  := "\033[0m"

	printBanner()

	section := func(title string) {
		fmt.Printf("%s%s━━━ %s %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n",
			bold, cyan, title, dim, reset)
	}

	opt := func(flag, desc string) {
		fmt.Printf("  %s%-22s%s %s\n", yellow, flag, reset, desc)
	}

	fmt.Printf("  %sUsage:%s lazyfuzz [OPTIONS]\n\n", bold, reset)

	section("HTTP OPTIONS")
	opt("-H <header>",          `Header "Name: Value". Can be used multiple times.`)
	opt("-X <method>",          "HTTP method to use (default: GET)")
	opt("-b <cookies>",         `Cookie data "NAME1=VALUE1; NAME2=VALUE2"`)
	opt("-cc <cert>",           "Client cert for authentication (PEM)")
	opt("-ck <key>",            "Client key for authentication (PEM)")
	opt("-d <data>",            "POST data / request body")
	opt("-http2",               "Use HTTP/2 protocol (default: false)")
	opt("-ignore-body",         "Do not fetch response content (default: false)")
	opt("-r",                   "Follow redirects (default: false)")
	opt("-raw",                 "Do not encode URI (default: false)")
	opt("-recursion",           "Scan recursively. Only FUZZ keyword supported (default: false)")
	opt("-recursion-depth <n>", "Maximum recursion depth (default: 0)")
	opt("-recursion-strategy",  `"default" (redirect-based) or "greedy" (all matches)`)
	opt("-replay-proxy <url>",  "Replay matched requests using this proxy")
	opt("-sni <host>",          "Target TLS SNI (does not support FUZZ keyword)")
	opt("-timeout <n>",         "HTTP request timeout in seconds (default: 10)")
	opt("-u <url>",             "Target URL")
	opt("-x <url>",             "Proxy URL. eg: http://127.0.0.1:8080 or socks5://...")
	fmt.Println()

	section("GENERAL OPTIONS")
	opt("-V",                   "Show version information (default: false)")
	opt("-ac",                  "Automatically calibrate filtering options (default: false)")
	opt("-acc <string>",        "Custom auto-calibration string. Implies -ac (repeatable)")
	opt("-ach",                 "Per-host autocalibration (default: false)")
	opt("-ack <keyword>",       "Autocalibration keyword (default: FUZZ)")
	opt("-acs <strategy>",      "Custom auto-calibration strategy. Implies -ac (repeatable)")
	opt("-c",                   "Colorize output (default: false)")
	opt("-config <file>",       "Load configuration from a file")
	opt("-json",                "JSON output, newline-delimited records (default: false)")
	opt("-maxtime <n>",         "Maximum running time in seconds for entire process (default: 0)")
	opt("-maxtime-job <n>",     "Maximum running time in seconds per job (default: 0)")
	opt("-noninteractive",      "Disable interactive console (default: false)")
	opt("-p <delay>",           `Delay between requests. eg: "0.1" or "0.1-2.0"`)
	opt("-rate <n>",            "Rate of requests per second (default: 0 = unlimited)")
	opt("-s",                   "Silent mode — do not print additional info (default: false)")
	opt("-sa",                  "Stop on all error cases. Implies -sf and -se (default: false)")
	opt("-scraperfile <file>",  "Custom scraper file path")
	opt("-scrapers <groups>",   "Active scraper groups (default: all)")
	opt("-se",                  "Stop on spurious errors (default: false)")
	opt("-search <hash>",       "Search for a FFUFHASH payload from ffuf history")
	opt("-sf",                  "Stop when >95% of responses return 403 (default: false)")
	opt("-t <n>",               "Number of concurrent threads (default: 40)")
	opt("-v",                   "Verbose output — print full URL and redirect location (default: false)")
	opt("-rua",                 "Random User-Agent browser tiap request (default: false)")
	fmt.Println()

	section("MATCHER OPTIONS")
	opt("-mc <codes>",          `Match HTTP status codes, or "all". (default: 200-299,301,302,307,401,403,405,500)`)
	opt("-ml <lines>",          "Match amount of lines in response")
	opt("-mmode <op>",          `Matcher set operator: "and" or "or" (default: or)`)
	opt("-mr <regexp>",         "Match regexp on response body")
	opt("-ms <size>",           "Match HTTP response size in bytes")
	opt("-mt <ms>",             `Match time to first byte. eg: ">100" or "<100"`)
	opt("-mw <words>",          "Match amount of words in response")
	fmt.Println()

	section("FILTER OPTIONS")
	opt("-fc <codes>",          "Filter HTTP status codes. Comma-separated values and ranges")
	opt("-fl <lines>",          "Filter by amount of lines. Comma-separated values and ranges")
	opt("-fmode <op>",          `Filter set operator: "and" or "or" (default: or)`)
	opt("-fr <regexp>",         "Filter regexp on response body")
	opt("-fs <sizes>",          "Filter HTTP response size. Comma-separated values and ranges")
	opt("-ft <ms>",             `Filter by time to first byte. eg: ">100" or "<100"`)
	opt("-fw <words>",          "Filter by amount of words. Comma-separated values and ranges")
	fmt.Println()

	section("INPUT OPTIONS")
	opt("-D",                   "DirSearch wordlist compatibility mode. Use with -e (default: false)")
	opt("-e <exts>",            "Comma-separated extensions. Extends FUZZ keyword. eg: php,html")
	opt("-enc <enc>",           `Encoders for keywords. eg: 'FUZZ:urlencode b64encode'`)
	opt("-ic",                  "Ignore wordlist comments (default: false)")
	opt("-input-cmd <cmd>",     "Command producing the input. Requires -input-num. Overrides -w.")
	opt("-input-num <n>",       "Number of inputs from -input-cmd (default: 100)")
	opt("-input-shell <shell>", "Shell to use for -input-cmd (default: /bin/sh)")
	opt("-mode <mode>",         "Multi-wordlist mode: clusterbomb, pitchfork, sniper (default: clusterbomb)")
	opt("-request <file>",      "File containing the raw HTTP request")
	opt("-request-proto <p>",   "Protocol to use with raw request (default: https)")
	opt("-w <wordlist>",        `Wordlist file. Optional keyword via colon: '/path/list:KEYWORD' (repeatable)`)
	fmt.Println()

	section("OUTPUT OPTIONS")
	opt("-debug-log <file>",    "Write all internal logging to the specified file")
	opt("-o <file>",            "Write output to file")
	opt("-od <dir>",            "Directory path to store matched results")
	opt("-of <format>",         "Output format: json, ejson, html, md, csv, ecsv, or 'all' (default: json)")
	opt("-or",                  "Don't create output file if there are no results (default: false)")
	fmt.Println()

	section("EXAMPLE USAGE")
	fmt.Printf("  %sFuzz file paths, filter size 42, colorized verbose output:%s\n", dim, reset)
	fmt.Printf("    %slazyfuzz -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v%s\n\n", green, reset)

	fmt.Printf("  %sFuzz Host-header, match HTTP 200:%s\n", dim, reset)
	fmt.Printf("    %slazyfuzz -w hosts.txt -u https://example.org/ -H \"Host: FUZZ\" -mc 200%s\n\n", green, reset)

	fmt.Printf("  %sFuzz POST JSON data, filter body containing \"error\":%s\n", dim, reset)
	fmt.Printf("    %slazyfuzz -w entries.txt -u https://example.org/ -X POST \\\n", green)
	fmt.Printf("      -H \"Content-Type: application/json\" \\\n")
	fmt.Printf("      -d '{\"name\": \"FUZZ\"}' -fr \"error\"%s\n\n", reset)

	fmt.Printf("  %sMulti-wordlist clusterbomb, match value reflection:%s\n", dim, reset)
	fmt.Printf("    %slazyfuzz -w params.txt:PARAM -w values.txt:VAL \\\n", green)
	fmt.Printf("      -u https://example.org/?PARAM=VAL -mr \"VAL\" -c%s\n\n", reset)

	fmt.Printf("  %sSave results as HTML report:%s\n", dim, reset)
	fmt.Printf("    %slazyfuzz -w wordlist.txt -u https://example.org/FUZZ -o report.html -of html%s\n\n", green, reset)

	fmt.Printf("  %s─────────────────────────────────────────────────────────────────%s\n", dim, reset)
	fmt.Printf("  %sMore info: https://github.com/Fantasymind/lazyFuzz%s\n\n", dim, reset)
}

// ============================================================
// main
// ============================================================

func main() {
	listPtr := flag.String("l", "", "File berisi daftar URL/Domain")
	scPtr   := flag.String("sc", "200", "Status code filter (pisahkan koma: 200,403,302)")

	// --- INPUT OPTIONS ---
	// -w now supports multiple invocations and keyword syntax: /path:KEYWORD
	var wFlags stringSliceFlag
	flag.Var(&wFlags, "w", "Wordlist file path dan (opsional) keyword dipisah titik dua. Contoh: '/path/wordlist:KEYWORD'. Bisa diulang.")
	dirSearch    := flag.Bool("D", false, "DirSearch compatibility mode, gunakan bersama -e (default: false)")
	extensionsPtr := flag.String("e", "", "Comma-separated ekstensi. Memperluas keyword FUZZ. Contoh: php,html,txt")
	encPtr       := flag.String("enc", "", "Encoder untuk keyword. Contoh: 'FUZZ:urlencode b64encode'")
	ignoreComments := flag.Bool("ic", false, "Abaikan komentar dalam wordlist (default: false)")
	inputCmd     := flag.String("input-cmd", "", "Command yang menghasilkan input. --input-num wajib diisi. Override -w.")
	inputNum     := flag.Int("input-num", 100, "Jumlah input dari --input-cmd (default: 100)")
	inputShell   := flag.String("input-shell", "", "Shell untuk menjalankan --input-cmd. Default: /bin/sh")
	modePtr      := flag.String("mode", "clusterbomb", "Mode multi-wordlist: clusterbomb, pitchfork, sniper (default: clusterbomb)")
	requestFile  := flag.String("request", "", "File berisi raw HTTP request")
	requestProto := flag.String("request-proto", "https", "Protokol untuk raw request (default: https)")

	// --- HTTP OPTIONS ---
	var customHeaders headersFlag
	flag.Var(&customHeaders, "H", `Header "Name: Value", bisa diulang. Contoh: -H "X-Token: abc"`)

	methodPtr      := flag.String("X", "GET", "HTTP method (GET, POST, PUT, DELETE, dll)")
	cookiePtr      := flag.String("b", "", `Cookie data "NAME1=VALUE1; NAME2=VALUE2"`)
	clientCertPtr  := flag.String("cc", "", "Path ke client certificate (PEM)")
	clientKeyPtr   := flag.String("ck", "", "Path ke client key (PEM)")
	postDataPtr    := flag.String("d", "", "POST data / request body")
	http2Flag      := flag.Bool("http2", false, "Gunakan HTTP/2 protocol (default: false)")
	ignoreBodyPtr  := flag.Bool("ignore-body", false, "Jangan fetch response body (default: false)")
	followRedir    := flag.Bool("r", false, "Follow redirects (default: false)")
	rawURI         := flag.Bool("raw", false, "Jangan encode URI (default: false)")
	recursionPtr   := flag.Bool("recursion", false, "Scan rekursif (default: false)")
	recursionDepth := flag.Int("recursion-depth", 0, "Maksimum kedalaman rekursi (default: 0)")
	recursionStrat := flag.String("recursion-strategy", "default", `Strategi rekursi: "default" atau "greedy"`)
	replayProxy    := flag.String("replay-proxy", "", "Replay matched requests ke proxy ini")
	sniPtr         := flag.String("sni", "", "Target TLS SNI")
	timeoutPtr     := flag.Int("timeout", 10, "HTTP timeout dalam detik (default: 10)")
	targetURL      := flag.String("u", "", "Target URL tunggal (alternatif -l)")
	proxyPtr       := flag.String("x", "", "Proxy URL: http://127.0.0.1:8080 atau socks5://127.0.0.1:8080")

	// --- GENERAL OPTIONS ---
	showVersion    := flag.Bool("V", false, "Tampilkan versi (default: false)")
	autoCalib      := flag.Bool("ac", false, "Auto-calibrate filtering options (default: false)")
	var accFlags stringSliceFlag
	flag.Var(&accFlags, "acc", "Custom auto-calibration string, bisa diulang. Implies -ac")
	perHostCalib   := flag.Bool("ach", false, "Per-host autocalibration (default: false)")
	autoCalibKw    := flag.String("ack", "FUZZ", "Autocalibration keyword (default: FUZZ)")
	var acsFlags stringSliceFlag
	flag.Var(&acsFlags, "acs", "Custom auto-calibration strategy, bisa diulang. Implies -ac")
	colorize       := flag.Bool("c", false, "Colorize output (default: false)")
	configFile     := flag.String("config", "", "Load konfigurasi dari file")
	jsonOut        := flag.Bool("json", false, "JSON output newline-delimited (default: false)")
	maxTime        := flag.Int("maxtime", 0, "Maks waktu total detik untuk seluruh proses (default: 0)")
	maxTimeJob     := flag.Int("maxtime-job", 0, "Maks waktu detik per job (default: 0)")
	nonInteractive := flag.Bool("noninteractive", false, "Nonaktifkan interactive console (default: false)")
	delayPtr       := flag.String("p", "", `Delay antar request dalam detik, atau range. Contoh: "0.1" atau "0.1-2.0"`)
	ratePtr        := flag.Int("rate", 0, "Request per detik (default: 0 = unlimited)")
	silent         := flag.Bool("s", false, "Silent mode, tidak print info tambahan (default: false)")
	stopAll        := flag.Bool("sa", false, "Stop on all error cases. Implies -sf dan -se (default: false)")
	scraperFile    := flag.String("scraperfile", "", "Custom scraper file path")
	scrapers       := flag.String("scrapers", "all", "Active scraper groups (default: all)")
	stopSpurious   := flag.Bool("se", false, "Stop on spurious errors (default: false)")
	searchHash     := flag.String("search", "", "Search FFUFHASH payload dari ffuf history")
	stop403        := flag.Bool("sf", false, "Stop bila >95% response 403 Forbidden (default: false)")
	threadPtr      := flag.Int("t", 40, "Jumlah concurrent threads (default: 40)")
	verbose        := flag.Bool("v", false, "Verbose output, print full URL dan redirect location (default: false)")
	ruaPtr         := flag.Bool("rua", false, "Gunakan random User-Agent browser tiap request (default: false)")

	// --- MATCHER OPTIONS ---
	mcPtr    := flag.String("mc", "200-299,301,302,307,401,403,405,500",
		`Match HTTP status codes, atau "all". (default: 200-299,301,302,307,401,403,405,500)`)
	mlPtr    := flag.Int("ml", 0, "Match jumlah baris dalam response (0 = disabled)")
	mmodePtr := flag.String("mmode", "or", `Operator matcher: "and" atau "or" (default: or)`)
	mrPtr    := flag.String("mr", "", "Match regexp pada response body")
	msPtr    := flag.Int("ms", 0, "Match ukuran HTTP response dalam bytes (0 = disabled)")
	mtPtr    := flag.String("mt", "", `Match waktu ke byte pertama (ms). Contoh: ">100" atau "<500"`)
	mwPtr    := flag.Int("mw", 0, "Match jumlah kata dalam response (0 = disabled)")

	// --- FILTER OPTIONS ---
	fcPtr    := flag.String("fc", "", "Filter HTTP status codes. Comma-separated nilai dan range. Contoh: 404,500-599")
	flPtr    := flag.String("fl", "", "Filter berdasarkan jumlah baris. Comma-separated nilai dan range. Contoh: 0,10-20")
	fmodePtr := flag.String("fmode", "or", `Operator filter: "and" atau "or" (default: or)`)
	frPtr    := flag.String("fr", "", "Filter regexp pada response body")
	fsPtr    := flag.String("fs", "", "Filter HTTP response size dalam bytes. Comma-separated nilai dan range")
	ftPtr    := flag.String("ft", "", `Filter waktu ke byte pertama (ms). Contoh: ">100" atau "<100"`)
	fwPtr    := flag.String("fw", "", "Filter berdasarkan jumlah kata. Comma-separated nilai dan range")

	// --- OUTPUT OPTIONS ---
	debugLogPtr  := flag.String("debug-log", "", "Tulis semua internal log ke file yang ditentukan")
	outputPtr    := flag.String("o", "", "Tulis output ke file")
	outputDirPtr := flag.String("od", "", "Path direktori untuk menyimpan hasil yang cocok")
	outputFmtPtr := flag.String("of", "json", "Format output: json, ejson, html, md, csv, ecsv, atau 'all' (default: json)")
	outputOnlyR  := flag.Bool("or", false, "Jangan buat file output jika tidak ada hasil (default: false)")

	flag.Usage = printHelp
	flag.Parse()

	// Show banner on every run (unless -s silent)
	// We peek at -s before full parse — check os.Args manually
	silentMode := false
	for _, a := range os.Args[1:] {
		if a == "-s" {
			silentMode = true
			break
		}
	}
	if !silentMode {
		printBanner()
	}

	// --- Version ---
	if *showVersion {
		fmt.Printf("  %s\n\n", Version)
		return
	}

	// -h / --help already handled by flag.Usage above

	// --- Config file ---
	if *configFile != "" {
		loadConfig(*configFile)
	}

	// --- Search mode ---
	if *searchHash != "" {
		fmt.Printf("[*] Searching history untuk FFUFHASH: %s\n", *searchHash)
		fmt.Println("[-] Fitur history search belum diimplementasikan.")
		return
	}

	// --- Validasi input ---
	if *listPtr == "" && *targetURL == "" && *requestFile == "" {
		fmt.Println("Usage: lazyfuzz -u https://target.com/FUZZ -w paths.txt [OPTIONS]")
		fmt.Println("       lazyfuzz -l domains.txt -w paths.txt [OPTIONS]")
		fmt.Println("       lazyfuzz -request req.txt -w paths.txt [OPTIONS]")
		flag.PrintDefaults()
		return
	}
	if len(wFlags) == 0 && *inputCmd == "" {
		fmt.Println("[-] Harap berikan wordlist dengan -w atau command dengan -input-cmd")
		return
	}

	// acc/acs implies -ac
	if len(accFlags) > 0 || len(acsFlags) > 0 {
		*autoCalib = true
	}
	// -sa implies -sf dan -se
	if *stopAll {
		*stop403 = true
		*stopSpurious = true
	}

	// --- Parsing status code filter (-sc legacy) ---
	allowedCodes := make(map[int]bool)
	for _, codeStr := range strings.Split(*scPtr, ",") {
		var code int
		fmt.Sscanf(strings.TrimSpace(codeStr), "%d", &code)
		if code != 0 {
			allowedCodes[code] = true
		}
	}

	// --- Parsing MATCHER OPTIONS ---
	// -mc: match codes (overrides -sc when provided explicitly)
	matchCodes := make(map[int]bool)
	matchAll := false
	if *mcPtr == "all" {
		matchAll = true
	} else {
		for _, part := range strings.Split(*mcPtr, ",") {
			part = strings.TrimSpace(part)
			// Support range like "200-299"
			if strings.Contains(part, "-") {
				bounds := strings.SplitN(part, "-", 2)
				lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
				hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if err1 == nil && err2 == nil {
					for c := lo; c <= hi; c++ {
						matchCodes[c] = true
					}
				}
			} else {
				var code int
				fmt.Sscanf(part, "%d", &code)
				if code != 0 {
					matchCodes[code] = true
				}
			}
		}
	}

	// -mr: compile regexp
	var matchRegexp *regexp.Regexp
	if *mrPtr != "" {
		var err error
		matchRegexp, err = regexp.Compile(*mrPtr)
		if err != nil {
			fmt.Printf("[-] Regexp tidak valid (-mr): %v\n", err)
			return
		}
	}

	// -mt: parse ">100" or "<500"
	var matchTimeOp string
	var matchTimeMs int64
	if *mtPtr != "" {
		s := strings.TrimSpace(*mtPtr)
		if strings.HasPrefix(s, ">") {
			matchTimeOp = ">"
			matchTimeMs, _ = strconv.ParseInt(strings.TrimSpace(s[1:]), 10, 64)
		} else if strings.HasPrefix(s, "<") {
			matchTimeOp = "<"
			matchTimeMs, _ = strconv.ParseInt(strings.TrimSpace(s[1:]), 10, 64)
		} else {
			fmt.Println("[-] Format -mt tidak valid. Gunakan \">100\" atau \"<500\"")
			return
		}
	}

	// --- Parsing FILTER OPTIONS ---
	filterCodes, err := parseIntRanges(*fcPtr)
	if err != nil {
		fmt.Printf("[-] Filter code tidak valid (-fc): %v\n", err)
		return
	}
	filterLines, err := parseIntRanges(*flPtr)
	if err != nil {
		fmt.Printf("[-] Filter lines tidak valid (-fl): %v\n", err)
		return
	}
	filterWords, err := parseIntRanges(*fwPtr)
	if err != nil {
		fmt.Printf("[-] Filter words tidak valid (-fw): %v\n", err)
		return
	}
	filterSizes, err := parseIntRanges(*fsPtr)
	if err != nil {
		fmt.Printf("[-] Filter size tidak valid (-fs): %v\n", err)
		return
	}

	var filterRegexp *regexp.Regexp
	if *frPtr != "" {
		filterRegexp, err = regexp.Compile(*frPtr)
		if err != nil {
			fmt.Printf("[-] Regexp tidak valid (-fr): %v\n", err)
			return
		}
	}

	var filterTimeOp string
	var filterTimeMs int64
	if *ftPtr != "" {
		s := strings.TrimSpace(*ftPtr)
		if strings.HasPrefix(s, ">") {
			filterTimeOp = ">"
			filterTimeMs, _ = strconv.ParseInt(strings.TrimSpace(s[1:]), 10, 64)
		} else if strings.HasPrefix(s, "<") {
			filterTimeOp = "<"
			filterTimeMs, _ = strconv.ParseInt(strings.TrimSpace(s[1:]), 10, 64)
		} else {
			fmt.Println("[-] Format -ft tidak valid. Gunakan \">100\" atau \"<500\"")
			return
		}
	}

	// --- Build HTTP transport ---
	tlsCfg := &tls.Config{InsecureSkipVerify: true}

	if *clientCertPtr != "" && *clientKeyPtr != "" {
		cert, err := tls.LoadX509KeyPair(*clientCertPtr, *clientKeyPtr)
		if err != nil {
			fmt.Printf("[-] Gagal load client cert/key: %v\n", err)
			return
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if *sniPtr != "" {
		tlsCfg.ServerName = *sniPtr
	}

	transport := &http.Transport{
		MaxIdleConns:        *threadPtr,
		MaxIdleConnsPerHost: *threadPtr,
		DisableKeepAlives:   false,
		TLSClientConfig:     tlsCfg,
	}

	if *http2Flag {
		if err := http2.ConfigureTransport(transport); err != nil {
			fmt.Printf("[-] Gagal aktifkan HTTP/2: %v\n", err)
		}
	}

	if *proxyPtr != "" {
		proxyURL, err := url.Parse(*proxyPtr)
		if err != nil {
			fmt.Printf("[-] Proxy URL tidak valid: %v\n", err)
			return
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	var replayTransport *http.Transport
	if *replayProxy != "" {
		rProxyURL, err := url.Parse(*replayProxy)
		if err != nil {
			fmt.Printf("[-] Replay proxy URL tidak valid: %v\n", err)
		} else {
			replayTransport = &http.Transport{
				Proxy:           http.ProxyURL(rProxyURL),
				TLSClientConfig: tlsCfg,
			}
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(*timeoutPtr) * time.Second,
	}
	if !*followRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// --- Load targets ---
	var urls []string
	var rawReqMethod, rawReqURL string
	var rawReqHeaders map[string]string
	var rawReqBody string

	if *requestFile != "" {
		// -request mode: parse raw HTTP request file
		var err error
		rawReqMethod, rawReqURL, rawReqHeaders, rawReqBody, err = loadRawRequest(*requestFile, *requestProto)
		if err != nil {
			fmt.Printf("[-] Gagal baca request file: %v\n", err)
			return
		}
		urls = []string{rawReqURL}
		if rawReqMethod != "" && *methodPtr == "GET" {
			*methodPtr = rawReqMethod // honour method from raw request
		}
		// Copy headers from raw request into customHeaders
		for k, v := range rawReqHeaders {
			customHeaders = append(customHeaders, k+": "+v)
		}
		if rawReqBody != "" && *postDataPtr == "" {
			*postDataPtr = rawReqBody
		}
	} else if *targetURL != "" {
		urls = []string{*targetURL}
	} else {
		// -l supports "file.txt" or "file.txt:KEYWORD" (keyword used as template var in -H etc)
		listFile := *listPtr
		if idx := strings.LastIndex(listFile, ":"); idx > 1 {
			listFile = (*listPtr)[:idx]
		}
		var err error
		urls, err = readLinesFiltered(listFile, false)
		if err != nil {
			fmt.Printf("[-] Gagal baca file list: %v\n", err)
			return
		}
	}

	// --- Build wordlists (INPUT OPTIONS) ---
	// Parse encoders
	encoders := parseEncoders(*encPtr)

	// Parse extensions
	var extensions []string
	if *extensionsPtr != "" {
		for _, e := range strings.Split(*extensionsPtr, ",") {
			e = strings.TrimSpace(e)
			if e != "" {
				if !strings.HasPrefix(e, ".") {
					e = "." + e
				}
				extensions = append(extensions, e)
			}
		}
	}

	var wordlists []WordlistEntry

	if *inputCmd != "" {
		// -input-cmd mode
		entries := inputsFromCmd(*inputCmd, *inputShell, *inputNum)
		wordlists = []WordlistEntry{{Keyword: "FUZZ", Entries: entries}}
	} else {
		// -w flags: parse each "path:KEYWORD" or just "path" (default keyword = FUZZ)
		for _, w := range wFlags {
			keyword := "FUZZ"
			filePath := w
			if idx := strings.LastIndex(w, ":"); idx > 0 && idx < len(w)-1 {
				// Windows paths like C:\... have colon at pos 1
				if idx > 1 {
					filePath = w[:idx]
					keyword = w[idx+1:]
				}
			}
			entries, err := readLinesFiltered(filePath, *ignoreComments)
			if err != nil {
				fmt.Printf("[-] Gagal baca wordlist %s: %v\n", filePath, err)
				return
			}

			// -D (DirSearch mode): append extensions to each entry
			if *dirSearch && len(extensions) > 0 {
				var expanded []string
				for _, entry := range entries {
					expanded = append(expanded, entry) // original
					for _, ext := range extensions {
						expanded = append(expanded, entry+ext)
					}
				}
				entries = expanded
			} else if !*dirSearch && len(extensions) > 0 && keyword == "FUZZ" {
				// -e without -D: duplicate entries with extensions appended
				var expanded []string
				for _, entry := range entries {
					expanded = append(expanded, entry)
					for _, ext := range extensions {
						expanded = append(expanded, entry+ext)
					}
				}
				entries = expanded
			}

			wordlists = append(wordlists, WordlistEntry{Keyword: keyword, Entries: entries})
		}
	}

	if len(wordlists) == 0 {
		fmt.Println("[-] Tidak ada wordlist yang berhasil dimuat")
		return
	}

	// Generate input combinations based on -mode
	var inputCombos []map[string]string
	switch strings.ToLower(*modePtr) {
	case "pitchfork":
		inputCombos = generateInputsPitchfork(wordlists)
	case "sniper":
		inputCombos = generateInputsSniper(wordlists)
	default: // clusterbomb
		inputCombos = generateInputsClusterbomb(wordlists)
	}

	// Total entry count for banner
	totalEntries := len(inputCombos)

	// --- Parsing OUTPUT OPTIONS ---
	// Resolve output formats
	var outputFormats []string
	if *outputFmtPtr == "all" {
		outputFormats = []string{"json", "ejson", "html", "md", "csv", "ecsv"}
	} else {
		for _, f := range strings.Split(*outputFmtPtr, ",") {
			f = strings.TrimSpace(strings.ToLower(f))
			if f != "" {
				outputFormats = append(outputFormats, f)
			}
		}
	}

	// Open debug log file
	var debugLogFile *os.File
	if *debugLogPtr != "" {
		var err error
		debugLogFile, err = os.OpenFile(*debugLogPtr, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Printf("[-] Tidak bisa buka debug log: %v\n", err)
			return
		}
		defer debugLogFile.Close()
	}

	// --- Build config ---
	cfg := &FuzzConfig{
		Method:          strings.ToUpper(*methodPtr),
		Headers:         customHeaders,
		Cookie:          *cookiePtr,
		PostData:        *postDataPtr,
		IgnoreBody:      *ignoreBodyPtr,
		RawURI:          *rawURI,
		AllowedCodes:    allowedCodes,
		Recursion:       *recursionPtr,
		RecursionDepth:  *recursionDepth,
		RecursionStrat:  *recursionStrat,
		ReplayTransport: replayTransport,
		ReplayProxy:     *replayProxy,
		Timeout:         *timeoutPtr,
		Colorize:        *colorize,
		JSONOutput:      *jsonOut,
		Silent:          *silent,
		Verbose:         *verbose,
		AutoCalib:       *autoCalib,
		AutoCalibStr:    accFlags,
		AutoCalibKw:     *autoCalibKw,
		PerHostCalib:    *perHostCalib,
		AutoCalibStrat:  acsFlags,
		Delay:           *delayPtr,
		Rate:            *ratePtr,
		MaxTime:         *maxTime,
		MaxTimeJob:      *maxTimeJob,
		NonInteractive:  *nonInteractive,
		ScraperFile:     *scraperFile,
		Scrapers:        *scrapers,
		StopOnError:     *stopAll,
		StopOnSpurious:  *stopSpurious,
		StopOn403:       *stop403,
		// Matcher
		MatchCodes:      matchCodes,
		MatchAll:        matchAll,
		MatchLines:      *mlPtr,
		MatchWords:      *mwPtr,
		MatchSize:       *msPtr,
		MatchRegexp:     matchRegexp,
		MatchTimeOp:     matchTimeOp,
		MatchTimeMs:     matchTimeMs,
		MatchMode:       *mmodePtr,
		// Filter
		FilterCodes:     filterCodes,
		FilterLines:     filterLines,
		FilterWords:     filterWords,
		FilterSizes:     filterSizes,
		FilterRegexp:    filterRegexp,
		FilterTimeOp:    filterTimeOp,
		FilterTimeMs:    filterTimeMs,
		FilterMode:      *fmodePtr,
		// Input
		Extensions:      extensions,
		DirSearch:       *dirSearch,
		Encoders:        encoders,
		IgnoreComments:  *ignoreComments,
		InputCmd:        *inputCmd,
		InputNum:        *inputNum,
		InputShell:      *inputShell,
		WordlistMode:    *modePtr,
		RequestFile:     *requestFile,
		RequestProto:    *requestProto,
		Wordlists:       wordlists,
		// Output
		OutputFile:        *outputPtr,
		OutputDir:         *outputDirPtr,
		OutputFormats:     outputFormats,
		OutputOnlyResults: *outputOnlyR,
		DebugLogFile:      *debugLogPtr,
		debugLog:          debugLogFile,
		RandomUA:          *ruaPtr,
		startTime:         time.Now(),
	}
	_ = rawReqMethod  // used above
	_ = rawReqURL

	// --- Banner ---
	if !cfg.Silent {
		fmt.Printf("[*] %s\n", Version)
		fmt.Printf("[*] Targets: %d | Inputs: %d | Method: %s | Filter SC: %s | Threads: %d | Mode: %s\n",
			len(urls), totalEntries, cfg.Method, *scPtr, *threadPtr, *modePtr)
		if *http2Flag        { fmt.Println("[*] HTTP/2 aktif") }
		if *proxyPtr != ""   { fmt.Printf("[*] Proxy: %s\n", *proxyPtr) }
		if *replayProxy != "" { fmt.Printf("[*] Replay Proxy: %s\n", *replayProxy) }
		if cfg.AutoCalib     { fmt.Printf("[*] Auto-calibration aktif (keyword: %s)\n", cfg.AutoCalibKw) }
		if cfg.Delay != ""   { fmt.Printf("[*] Delay: %s detik\n", cfg.Delay) }
		if cfg.Rate > 0      { fmt.Printf("[*] Rate limit: %d req/s\n", cfg.Rate) }
		if cfg.MaxTime > 0   { fmt.Printf("[*] Max waktu total: %ds\n", cfg.MaxTime) }
		if cfg.MaxTimeJob > 0 { fmt.Printf("[*] Max waktu per job: %ds\n", cfg.MaxTimeJob) }
		if cfg.ScraperFile != "" { fmt.Printf("[*] Scraper file: %s\n", cfg.ScraperFile) }
		if len(extensions) > 0 { fmt.Printf("[*] Extensions: %s\n", strings.Join(extensions, ",")) }
		if *dirSearch        { fmt.Println("[*] DirSearch mode aktif") }
		if *encPtr != ""     { fmt.Printf("[*] Encoders: %s\n", *encPtr) }
		if *requestFile != "" { fmt.Printf("[*] Request file: %s (%s)\n", *requestFile, *requestProto) }
		if *inputCmd != ""   { fmt.Printf("[*] Input command: %s (n=%d)\n", *inputCmd, *inputNum) }
		if len(wordlists) > 1 {
			for _, wl := range wordlists {
				fmt.Printf("[*] Wordlist [%s]: %d entries\n", wl.Keyword, len(wl.Entries))
			}
		}
		if *mrPtr != ""          { fmt.Printf("[*] Match regexp: %s\n", *mrPtr) }
		if *mlPtr > 0            { fmt.Printf("[*] Match lines: %d\n", *mlPtr) }
		if *mwPtr > 0            { fmt.Printf("[*] Match words: %d\n", *mwPtr) }
		if *msPtr > 0            { fmt.Printf("[*] Match size: %d bytes\n", *msPtr) }
		if *mtPtr != ""          { fmt.Printf("[*] Match time: %s ms\n", *mtPtr) }
		if len(matchCodes) > 0 || matchAll {
			fmt.Printf("[*] Match codes: %s | mode: %s\n", *mcPtr, *mmodePtr)
		}
		if *fcPtr != "" { fmt.Printf("[*] Filter codes: %s\n", *fcPtr) }
		if *flPtr != "" { fmt.Printf("[*] Filter lines: %s\n", *flPtr) }
		if *fwPtr != "" { fmt.Printf("[*] Filter words: %s\n", *fwPtr) }
		if *fsPtr != "" { fmt.Printf("[*] Filter size: %s bytes\n", *fsPtr) }
		if *ftPtr != "" { fmt.Printf("[*] Filter time: %s ms\n", *ftPtr) }
		if *frPtr != "" { fmt.Printf("[*] Filter regexp: %s\n", *frPtr) }
		if *fcPtr != "" || *flPtr != "" || *fwPtr != "" || *fsPtr != "" || *ftPtr != "" || *frPtr != "" {
			fmt.Printf("[*] Filter mode: %s\n", *fmodePtr)
		}
		if *outputPtr != ""    { fmt.Printf("[*] Output file: %s (format: %s)\n", *outputPtr, *outputFmtPtr) }
		if *outputDirPtr != "" { fmt.Printf("[*] Output dir: %s\n", *outputDirPtr) }
		if *debugLogPtr != ""  { fmt.Printf("[*] Debug log: %s\n", *debugLogPtr) }
		fmt.Println()
	}

	// Suppress unused warning for nonInteractive
	_ = *nonInteractive

	// --- Rate limiter ---
	var rateTicker <-chan time.Time
	if cfg.Rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(cfg.Rate))
		defer ticker.Stop()
		rateTicker = ticker.C
	}

	// --- Global timer ---
	var globalTimer <-chan time.Time
	if cfg.MaxTime > 0 {
		globalTimer = time.After(time.Duration(cfg.MaxTime) * time.Second)
	}

	// --- Auto-calibration ---
	if cfg.AutoCalib {
		runAutoCalib(client, urls, cfg)
	}

	// --- Worker pool ---
	jobs := make(chan string, *threadPtr*2)
	var wg sync.WaitGroup

	jobStart := time.Now()

	for i := 0; i < *threadPtr; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if atomic.LoadInt32(&cfg.stopFlag) == 1 {
					continue
				}
				// Per-job max time
				if cfg.MaxTimeJob > 0 && time.Since(jobStart).Seconds() > float64(cfg.MaxTimeJob) {
					if !cfg.Silent {
						fmt.Println("\n[!] Waktu per job tercapai (-maxtime-job), menghentikan...")
					}
					atomic.StoreInt32(&cfg.stopFlag, 1)
					continue
				}
				// Rate limit
				if rateTicker != nil {
					<-rateTicker
				}
				// Delay
				if cfg.Delay != "" {
					sleepDelay(cfg.Delay)
				}
				// Unpack target and baseURL
				parts := strings.SplitN(job, "\x00", 2)
				target := parts[0]
				baseURL := target
				if len(parts) == 2 {
					baseURL = parts[1]
				}
				fuzz(client, target, baseURL, cfg, 0)
			}
		}()
	}

	// --- URL generator goroutine ---
	done := make(chan struct{})
	totalURLs := len(urls)
	go func() {
		defer close(done)
		for urlIdx, u := range urls {
			if atomic.LoadInt32(&cfg.stopFlag) == 1 {
				break
			}

			// Checkpoint log: progress per URL
			if !cfg.Silent {
				pct := float64(urlIdx+1) / float64(totalURLs) * 100
				fmt.Printf("\r\033[36m[checkpoint]\033[0m URL %d/%d (%.1f%%) → %s\033[K",
					urlIdx+1, totalURLs, pct, u)
			}
			atomic.StoreInt64(&cfg.urlIndex, int64(urlIdx+1))

			for _, combo := range inputCombos {
				if atomic.LoadInt32(&cfg.stopFlag) == 1 {
					break
				}
				// Substitute FUZZ keyword in URL
				target := substituteKeywords(u, combo, cfg)
				// If no keyword in URL, append first wordlist value as path
				if target == u && len(combo) > 0 {
					for _, val := range combo {
						target = strings.TrimRight(u, "/") + "/" + strings.TrimLeft(val, "/")
						break
					}
				}
				// Pass current base URL for dynamic header substitution (Referer etc.)
				jobs <- target + "\x00" + u
			}
		}
		close(jobs)
		if !cfg.Silent {
			fmt.Println() // newline after checkpoint
		}
	}()

	// --- Watch global timer ---
	if globalTimer != nil {
		go func() {
			select {
			case <-globalTimer:
				if !cfg.Silent {
					fmt.Println("\n[!] Waktu maksimum tercapai (-maxtime), menghentikan scan...")
				}
				atomic.StoreInt32(&cfg.stopFlag, 1)
			case <-done:
			}
		}()
	}

	wg.Wait()

	// --- Write output files ---
	if cfg.OutputFile != "" || cfg.OutputDir != "" {
		writeOutputFiles(cfg)
	}

	if !cfg.Silent {
		elapsed := time.Since(cfg.startTime).Round(time.Millisecond)
		fmt.Printf("\n[!] Scanning Selesai. Total request: %d | Durasi: %s\n",
			atomic.LoadInt64(&cfg.totalReqs), elapsed)
	}
}

// ============================================================
// fuzz - core request function
// ============================================================

func fuzz(client *http.Client, fullURL string, baseURL string, cfg *FuzzConfig, depth int) {
	if !strings.HasPrefix(fullURL, "http") {
		fullURL = "http://" + fullURL
	}
	if baseURL == "" {
		baseURL = fullURL
	}

	var bodyReader io.Reader
	if cfg.PostData != "" {
		bodyReader = strings.NewReader(cfg.PostData)
	}

	req, err := http.NewRequest(cfg.Method, fullURL, bodyReader)
	if err != nil {
		handleError(cfg, err)
		return
	}

	// User-Agent: random or default
	if cfg.RandomUA {
		req.Header.Set("User-Agent", randomUA())
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) lazyFuzz/4.4")
	}

	// Parse the fuzz path for header substitution (e.g. /FUZZ value)
	parsedTarget, _ := url.Parse(fullURL)
	fuzzPath := ""
	if parsedTarget != nil {
		fuzzPath = parsedTarget.Path
	}

	// Custom headers — support dynamic substitutions:
	//   URL      → current base URL from -l list
	//   /FUZZ    → path component of current fuzzed URL
	for _, h := range cfg.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			// Substitute dynamic placeholders in header values
			v = strings.ReplaceAll(v, "URL", baseURL)
			v = strings.ReplaceAll(v, "/FUZZ", fuzzPath)
			v = strings.ReplaceAll(v, "FUZZ", fuzzPath)
			req.Header.Set(k, v)
		}
	}

	if cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}

	if cfg.PostData != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Measure TTFB (time to first byte)
	reqStart := time.Now()
	debugLogWrite(cfg, fmt.Sprintf("REQ %s %s", cfg.Method, fullURL))
	resp, err := client.Do(req)
	if err != nil {
		handleError(cfg, err)
		return
	}
	ttfbMs := time.Since(reqStart).Milliseconds()

	// Read body — needed for size/lines/words/regexp matchers
	var bodyBuf bytes.Buffer
	if !cfg.IgnoreBody {
		io.Copy(&bodyBuf, resp.Body)
	} else {
		io.Copy(io.Discard, resp.Body)
	}
	resp.Body.Close()

	atomic.AddInt64(&cfg.totalReqs, 1)

	// Track 403 for -sf
	if resp.StatusCode == 403 {
		atomic.AddInt64(&cfg.total403, 1)
	}
	if cfg.StopOn403 {
		total := atomic.LoadInt64(&cfg.totalReqs)
		f403  := atomic.LoadInt64(&cfg.total403)
		if total > 20 && float64(f403)/float64(total) > 0.95 {
			if !cfg.Silent {
				fmt.Println("\n[!] >95% response 403 Forbidden, menghentikan scan (-sf)...")
			}
			atomic.StoreInt32(&cfg.stopFlag, 1)
			return
		}
	}

	// --- Legacy -sc filter (kept for backward compat) ---
	if len(cfg.AllowedCodes) > 0 && !cfg.AllowedCodes[resp.StatusCode] {
		// Only apply legacy filter when no -mc matchers configured
		if len(cfg.MatchCodes) == 0 && !cfg.MatchAll {
			return
		}
	}

	// --- Compute response metrics ---
	bodyStr  := bodyBuf.String()
	bodySize := bodyBuf.Len()
	lineCount := strings.Count(bodyStr, "\n")
	if bodyStr != "" && !strings.HasSuffix(bodyStr, "\n") {
		lineCount++
	}
	wordCount := len(strings.Fields(bodyStr))

	// --- Run MATCHER OPTIONS ---
	matched := matchResponse(resp.StatusCode, bodySize, lineCount, wordCount, ttfbMs, bodyStr, cfg)
	if !matched {
		return
	}

	// --- Run FILTER OPTIONS (drop if filter fires) ---
	if filterResponse(resp.StatusCode, bodySize, lineCount, wordCount, ttfbMs, bodyStr, cfg) {
		return
	}

	// --- Output ---
	rec := JSONRecord{
		URL:        fullURL,
		StatusCode: resp.StatusCode,
		Lines:      lineCount,
		Words:      wordCount,
		Size:       bodySize,
		DurationMs: ttfbMs,
		Timestamp:  time.Now().Format(time.RFC3339),
	}

	// Collect result for file output
	cfg.resultsMu.Lock()
	cfg.results = append(cfg.results, rec)
	cfg.resultsMu.Unlock()

	// Debug log
	if cfg.debugLog != nil {
		b, _ := json.Marshal(rec)
		fmt.Fprintf(cfg.debugLog, "[DEBUG] %s\n", string(b))
	}

	if cfg.JSONOutput {
		b, _ := json.Marshal(rec)
		fmt.Println(string(b))
	} else {
		redirectLoc := ""
		if cfg.Verbose {
			redirectLoc = resp.Header.Get("Location")
		}
		fmt.Println(formatResult(fullURL, resp.StatusCode, bodySize, lineCount, wordCount, ttfbMs, redirectLoc, cfg))
	}

	// --- Replay proxy ---
	if cfg.ReplayProxy != "" && cfg.ReplayTransport != nil {
		replayClient := &http.Client{
			Transport: cfg.ReplayTransport,
			Timeout:   time.Duration(cfg.Timeout) * time.Second,
		}
		replayReq, err := http.NewRequest(cfg.Method, fullURL, strings.NewReader(cfg.PostData))
		if err == nil {
			for _, h := range cfg.Headers {
				parts := strings.SplitN(h, ":", 2)
				if len(parts) == 2 {
					replayReq.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
			if cfg.Cookie != "" {
				replayReq.Header.Set("Cookie", cfg.Cookie)
			}
			if rResp, err := replayClient.Do(replayReq); err == nil {
				io.Copy(io.Discard, rResp.Body)
				rResp.Body.Close()
			}
		}
	}

	// --- Recursion ---
	if cfg.Recursion && depth < cfg.RecursionDepth {
		subURL := strings.TrimRight(fullURL, "/")
		if cfg.RecursionStrat == "greedy" || resp.StatusCode == 301 || resp.StatusCode == 302 {
			if !cfg.Silent {
				fmt.Printf("  \033[36m[>] Rekursi: %s (depth %d)\033[0m\n", subURL, depth+1)
			}
			fuzz(client, subURL, baseURL, cfg, depth+1)
		}
	}
}

// ============================================================
// Output writers
// ============================================================

// writeOutputFiles writes result data to -o file and/or -od directory
// in all specified -of formats.
func writeOutputFiles(cfg *FuzzConfig) {
	cfg.resultsMu.Lock()
	results := make([]JSONRecord, len(cfg.results))
	copy(results, cfg.results)
	cfg.resultsMu.Unlock()

	if cfg.OutputOnlyResults && len(results) == 0 {
		return
	}

	formats := cfg.OutputFormats
	if len(formats) == 0 {
		formats = []string{"json"}
	}

	// -o: single file, first format only (or derive ext from -of)
	if cfg.OutputFile != "" {
		ext := filepath.Ext(cfg.OutputFile)
		fmt_ := formats[0]
		if ext != "" {
			ext = strings.ToLower(strings.TrimPrefix(ext, "."))
			fmt_ = ext
		}
		if err := writeFormat(cfg.OutputFile, fmt_, results); err != nil {
			fmt.Printf("[-] Gagal tulis output file: %v\n", err)
		} else {
			fmt.Printf("[+] Output disimpan ke: %s\n", cfg.OutputFile)
		}
	}

	// -od: directory, one file per format
	if cfg.OutputDir != "" {
		if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
			fmt.Printf("[-] Gagal buat output dir: %v\n", err)
			return
		}
		ts := time.Now().Format("20060102_150405")
		for _, fmt_ := range formats {
			ext := formatExtension(fmt_)
			path := filepath.Join(cfg.OutputDir, "lazyfuzz_"+ts+"."+ext)
			if err := writeFormat(path, fmt_, results); err != nil {
				fmt.Printf("[-] Gagal tulis %s: %v\n", path, err)
			} else {
				fmt.Printf("[+] Output [%s] disimpan ke: %s\n", fmt_, path)
			}
		}
	}
}

func formatExtension(fmt_ string) string {
	switch fmt_ {
	case "ejson":
		return "json"
	case "ecsv":
		return "csv"
	case "md":
		return "md"
	case "html":
		return "html"
	case "csv":
		return "csv"
	default:
		return "json"
	}
}

// writeFormat writes results to path in the given format.
func writeFormat(path, format string, results []JSONRecord) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	switch format {
	case "json":
		return writeJSON(f, results, false)
	case "ejson":
		return writeJSON(f, results, true) // ejson = JSON array (extended)
	case "csv":
		return writeCSV(f, results, false)
	case "ecsv":
		return writeCSV(f, results, true)
	case "md":
		return writeMarkdown(f, results)
	case "html":
		return writeHTML(f, results)
	default:
		return writeJSON(f, results, false)
	}
}

// writeJSON writes newline-delimited JSON (false) or a JSON array (true).
func writeJSON(w io.Writer, results []JSONRecord, asArray bool) error {
	if asArray {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	for _, r := range results {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(b))
	}
	return nil
}

// writeCSV writes a CSV file. ecsv=true adds all fields; false is compact.
func writeCSV(w io.Writer, results []JSONRecord, extended bool) error {
	cw := csv.NewWriter(w)
	if extended {
		cw.Write([]string{"url", "status", "lines", "words", "size", "duration_ms", "timestamp"})
		for _, r := range results {
			cw.Write([]string{
				r.URL,
				strconv.Itoa(r.StatusCode),
				strconv.Itoa(r.Lines),
				strconv.Itoa(r.Words),
				strconv.Itoa(r.Size),
				strconv.FormatInt(r.DurationMs, 10),
				r.Timestamp,
			})
		}
	} else {
		cw.Write([]string{"url", "status", "size"})
		for _, r := range results {
			cw.Write([]string{r.URL, strconv.Itoa(r.StatusCode), strconv.Itoa(r.Size)})
		}
	}
	cw.Flush()
	return cw.Error()
}

// writeMarkdown writes a Markdown table.
func writeMarkdown(w io.Writer, results []JSONRecord) error {
	fmt.Fprintln(w, "# lazyFuzz Results")
	fmt.Fprintf(w, "\nGenerated: %s\n\n", time.Now().Format(time.RFC3339))
	fmt.Fprintln(w, "| Status | URL | Lines | Words | Size | Time (ms) |")
	fmt.Fprintln(w, "|--------|-----|-------|-------|------|-----------|")
	for _, r := range results {
		fmt.Fprintf(w, "| %d | %s | %d | %d | %d | %d |\n",
			r.StatusCode, r.URL, r.Lines, r.Words, r.Size, r.DurationMs)
	}
	return nil
}

const htmlTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>lazyFuzz Results</title>
<style>
body{font-family:monospace;background:#1a1a2e;color:#eee;padding:20px}
h1{color:#e94560}
table{border-collapse:collapse;width:100%}
th{background:#16213e;color:#0f3460;padding:8px;text-align:left;color:#e94560}
td{padding:6px 8px;border-bottom:1px solid #333}
tr:hover{background:#16213e}
.s200{color:#00b894}.s301{color:#74b9ff}.s302{color:#74b9ff}
.s403{color:#fdcb6e}.s404{color:#636e72}.s500{color:#d63031}
</style>
</head>
<body>
<h1>lazyFuzz Results</h1>
<p>Generated: {{.Generated}} | Total: {{.Total}}</p>
<table>
<tr><th>Status</th><th>URL</th><th>Lines</th><th>Words</th><th>Size</th><th>Time (ms)</th></tr>
{{range .Results}}
<tr>
<td class="s{{.StatusCode}}">{{.StatusCode}}</td>
<td>{{.URL}}</td>
<td>{{.Lines}}</td>
<td>{{.Words}}</td>
<td>{{.Size}}</td>
<td>{{.DurationMs}}</td>
</tr>
{{end}}
</table>
</body>
</html>`

func writeHTML(w io.Writer, results []JSONRecord) error {
	tmpl, err := template.New("report").Parse(htmlTmpl)
	if err != nil {
		return err
	}
	data := struct {
		Generated string
		Total     int
		Results   []JSONRecord
	}{
		Generated: time.Now().Format(time.RFC3339),
		Total:     len(results),
		Results:   results,
	}
	return tmpl.Execute(w, data)
}

// debugLogWrite writes a message to the debug log file if open.
func debugLogWrite(cfg *FuzzConfig, msg string) {
	if cfg.debugLog == nil {
		return
	}
	fmt.Fprintf(cfg.debugLog, "[%s] %s\n", time.Now().Format("15:04:05.000"), msg)
}

// ============================================================
// matchResponse evaluates all active matchers against the response.
// In "or" mode: at least one matcher must pass.
// In "and" mode: ALL active matchers must pass.
func matchResponse(statusCode, size, lines, words int, ttfbMs int64, body string, cfg *FuzzConfig) bool {
	type result struct {
		active bool
		pass   bool
	}

	checks := []result{
		// -mc / -mc all
		{
			active: len(cfg.MatchCodes) > 0 || cfg.MatchAll,
			pass:   cfg.MatchAll || cfg.MatchCodes[statusCode],
		},
		// -ml
		{active: cfg.MatchLines > 0, pass: lines == cfg.MatchLines},
		// -mw
		{active: cfg.MatchWords > 0, pass: words == cfg.MatchWords},
		// -ms
		{active: cfg.MatchSize > 0, pass: size == cfg.MatchSize},
		// -mr
		{
			active: cfg.MatchRegexp != nil,
			pass:   cfg.MatchRegexp != nil && cfg.MatchRegexp.MatchString(body),
		},
		// -mt
		{
			active: cfg.MatchTimeOp != "",
			pass: func() bool {
				if cfg.MatchTimeOp == ">" {
					return ttfbMs > cfg.MatchTimeMs
				}
				if cfg.MatchTimeOp == "<" {
					return ttfbMs < cfg.MatchTimeMs
				}
				return false
			}(),
		},
	}

	// Collect only active checks
	activeChecks := []result{}
	for _, c := range checks {
		if c.active {
			activeChecks = append(activeChecks, c)
		}
	}

	// If no matchers configured at all, fall back to legacy AllowedCodes behaviour
	if len(activeChecks) == 0 {
		if len(cfg.AllowedCodes) > 0 {
			return cfg.AllowedCodes[statusCode]
		}
		return true
	}

	mode := strings.ToLower(cfg.MatchMode)
	if mode == "and" {
		for _, c := range activeChecks {
			if !c.pass {
				return false
			}
		}
		return true
	}
	// default: "or"
	for _, c := range activeChecks {
		if c.pass {
			return true
		}
	}
	return false
}

// filterResponse returns true when the response should be DROPPED (filtered out).
// In "or" mode: drop if ANY active filter matches.
// In "and" mode: drop only if ALL active filters match.
func filterResponse(statusCode, size, lines, words int, ttfbMs int64, body string, cfg *FuzzConfig) bool {
	type result struct {
		active bool
		pass   bool // true = "this filter fires / matches"
	}

	checks := []result{
		// -fc: filter by status code
		{
			active: len(cfg.FilterCodes) > 0,
			pass:   matchesAnyRange(statusCode, cfg.FilterCodes),
		},
		// -fl: filter by line count
		{
			active: len(cfg.FilterLines) > 0,
			pass:   matchesAnyRange(lines, cfg.FilterLines),
		},
		// -fw: filter by word count
		{
			active: len(cfg.FilterWords) > 0,
			pass:   matchesAnyRange(words, cfg.FilterWords),
		},
		// -fs: filter by response size
		{
			active: len(cfg.FilterSizes) > 0,
			pass:   matchesAnyRange(size, cfg.FilterSizes),
		},
		// -fr: filter by regexp
		{
			active: cfg.FilterRegexp != nil,
			pass:   cfg.FilterRegexp != nil && cfg.FilterRegexp.MatchString(body),
		},
		// -ft: filter by TTFB
		{
			active: cfg.FilterTimeOp != "",
			pass: func() bool {
				if cfg.FilterTimeOp == ">" {
					return ttfbMs > cfg.FilterTimeMs
				}
				if cfg.FilterTimeOp == "<" {
					return ttfbMs < cfg.FilterTimeMs
				}
				return false
			}(),
		},
	}

	activeChecks := []result{}
	for _, c := range checks {
		if c.active {
			activeChecks = append(activeChecks, c)
		}
	}

	if len(activeChecks) == 0 {
		return false // no filters configured → don't drop anything
	}

	mode := strings.ToLower(cfg.FilterMode)
	if mode == "and" {
		// Drop only if ALL filters fire
		for _, c := range activeChecks {
			if !c.pass {
				return false // at least one filter didn't fire → keep
			}
		}
		return true // all fired → drop
	}
	// default: "or" — drop if ANY filter fires
	for _, c := range activeChecks {
		if c.pass {
			return true
		}
	}
	return false
}

// ============================================================
// Helpers
// ============================================================

func formatResult(fullURL string, statusCode, size, lines, words int, ttfbMs int64, redirectLoc string, cfg *FuzzConfig) string {
	scStr := fmt.Sprintf("[%d]", statusCode)

	if cfg.Colorize {
		color := "\033[37m"
		switch statusCode {
		case 200, 201, 204:
			color = "\033[32m" // Hijau
		case 301, 302, 307, 308:
			color = "\033[34m" // Biru
		case 401, 403:
			color = "\033[33m" // Kuning
		case 500, 502, 503:
			color = "\033[31m" // Merah
		}
		scStr = fmt.Sprintf("%s[%d]\033[0m", color, statusCode)
	}

	meta := fmt.Sprintf("Lines: %-4d Words: %-6d Size: %-8d Time: %dms", lines, words, size, ttfbMs)

	if cfg.Verbose && redirectLoc != "" {
		return fmt.Sprintf("%s  %-70s  [%s]  -> %s", scStr, fullURL, meta, redirectLoc)
	}
	return fmt.Sprintf("%s  %-70s  [%s]", scStr, fullURL, meta)
}

func handleError(cfg *FuzzConfig, err error) {
	debugLogWrite(cfg, fmt.Sprintf("ERROR: %v", err))
	if cfg.StopOnSpurious || cfg.StopOnError {
		if !cfg.Silent {
			fmt.Printf("[-] Error: %v\n", err)
		}
		atomic.StoreInt32(&cfg.stopFlag, 1)
	}
}

// sleepDelay handles "0.1" or "0.1-2.0" format
func sleepDelay(d string) {
	parts := strings.SplitN(d, "-", 2)
	if len(parts) == 2 {
		min, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		max, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if err1 == nil && err2 == nil && max > min {
			dur := min + rand.Float64()*(max-min)
			time.Sleep(time.Duration(dur * float64(time.Second)))
			return
		}
	}
	if f, err := strconv.ParseFloat(strings.TrimSpace(d), 64); err == nil {
		time.Sleep(time.Duration(f * float64(time.Second)))
	}
}

// runAutoCalib probes a random path per host to establish baseline filter
func runAutoCalib(client *http.Client, urls []string, cfg *FuzzConfig) {
	if !cfg.Silent {
		fmt.Println("[*] Menjalankan auto-calibration...")
	}
	calibPaths := cfg.AutoCalibStr
	if len(calibPaths) == 0 {
		calibPaths = []string{fmt.Sprintf("lazyfuzz_calib_%d", time.Now().UnixNano())}
	}

	seen := make(map[string]bool)
	for _, u := range urls {
		base := extractBase(u)
		if seen[base] && !cfg.PerHostCalib {
			continue
		}
		seen[base] = true
		for _, cp := range calibPaths {
			probeURL := strings.TrimRight(base, "/") + "/" + cp
			req, err := http.NewRequest("GET", probeURL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 lazyFuzz-calib")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if !cfg.Silent {
				fmt.Printf("  [calib] %s -> %d\n", probeURL, resp.StatusCode)
			}
		}
	}
	if !cfg.Silent {
		fmt.Println()
	}
}

func extractBase(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host)
}

// loadConfig reads simple key=value config file
func loadConfig(path string) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("[-] Tidak bisa buka config file: %v\n", err)
		return
	}
	defer file.Close()
	fmt.Printf("[*] Memuat config dari: %s\n", path)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			os.Args = append(os.Args, "-"+key, val)
		}
	}
}

func readLines(path string) ([]string, error) {
	return readLinesFiltered(path, false)
}

func readLinesFiltered(path string, ignoreComments bool) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		if ignoreComments && (strings.HasPrefix(text, "#") || strings.HasPrefix(text, "//")) {
			continue
		}
		lines = append(lines, text)
	}
	return lines, scanner.Err()
}
