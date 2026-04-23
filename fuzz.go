package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	// Flag definitions
	listPtr := flag.String("l", "", "File berisi daftar URL/Domain")
	wordPtr := flag.String("w", "", "File berisi wordlist path")
	threadPtr := flag.Int("t", 50, "Jumlah worker/threads")
	timeoutPtr := flag.Int("timeout", 5, "Timeout per request (detik)")
	scPtr := flag.String("sc", "200", "Status code yang ingin ditampilkan (pisahkan dengan koma, contoh: 200,403,302)")
	flag.Parse()

	if *listPtr == "" || *wordPtr == "" {
		fmt.Println("Usage: go run main.go -l domains.txt -w paths.txt -t 100 -sc 200,403")
		return
	}

	// Parsing desired status codes
	allowedCodes := make(map[int]bool)
	for _, codeStr := range strings.Split(*scPtr, ",") {
		var code int
		fmt.Sscanf(strings.TrimSpace(codeStr), "%d", &code)
		if code != 0 {
			allowedCodes[code] = true
		}
	}

	urls, _ := readLines(*listPtr)
	paths, _ := readLines(*wordPtr)

	fmt.Printf("[*] Mass Fuzzing | Targets: %d | Wordlist: %d | Filter SC: %s\n\n", len(urls), len(paths), *scPtr)

	jobs := make(chan string, *threadPtr)
	var wg sync.WaitGroup

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        *threadPtr,
			MaxIdleConnsPerHost: *threadPtr,
			DisableKeepAlives:   false,
		},
		Timeout: time.Duration(*timeoutPtr) * time.Second,
	}

	// Worker Pool
	for i := 0; i < *threadPtr; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				fuzz(client, target, allowedCodes)
			}
		}()
	}

	// Generator kombinasi
	go func() {
		for _, u := range urls {
			u = strings.TrimRight(u, "/")
			for _, p := range paths {
				p = strings.TrimLeft(p, "/")
				jobs <- u + "/" + p
			}
		}
		close(jobs)
	}()

	wg.Wait()
	fmt.Println("\n[!] Scanning Selesai.")
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if text := strings.TrimSpace(scanner.Text()); text != "" {
			lines = append(lines, text)
		}
	}
	return lines, scanner.Err()
}

func fuzz(client *http.Client, fullURL string, allowedCodes map[int]bool) {
	if !strings.HasPrefix(fullURL, "http") {
		fullURL = "http://" + fullURL
	}

	req, _ := http.NewRequest("GET", fullURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) lazyFuzz/3.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Hanya cetak jika status code ada di dalam list filter
	if allowedCodes[resp.StatusCode] {
		color := "\033[37m" // Putih (default)
		switch resp.StatusCode {
		case 200:
			color = "\033[32m" // Hijau
		case 301, 302:
			color = "\033[34m" // Biru
		case 403:
			color = "\033[33m" // Kuning
		case 500:
			color = "\033[31m" // Merah
		}
		fmt.Printf("%s[%d]\033[0m %s\n", color, resp.StatusCode, fullURL)
	}
}
