package main

import (
   "bufio"
   "context"
   "encoding/json"
   "flag"
   "fmt"
   "io"
   "math/rand"
   "net/http"
   "os"
   "strings"
   "sync"
   "time"

   "github.com/schollz/progressbar/v3"
)

type Result struct {
   URL    string `json:"url"`
   Status int    `json:"status"`
   Size   int    `json:"size"`
}

type SmartFuzzer struct {
   Targets        []string
   WordlistPath   string
   Output         string
   Concurrency    int
   RPS            float64
   CheckpointFile string
   Results        []Result
   Baselines      map[string]Baseline
   SizeCounters   map[string]map[int]int
   SkippedTargets map[string]bool
   CurrentIdx     int
   HardFilter     map[int]bool
   mu             sync.Mutex
   bar            *progressbar.ProgressBar
}

type Baseline struct {
   Status int
   Sizes  []int
}

// List User-Agents untuk rotasi
var userAgents = []string{
   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/115.0",
   "Mozilla/5.0 (X11; Linux x86_64) Safari/605.1.15",
   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
}

// Random header injection
func randomHeaders(req *http.Request) {
   ua := userAgents[rand.Intn(len(userAgents))]
   req.Header.Set("User-Agent", ua)
   req.Header.Set("X-Request-ID", randomString(12))
   req.Header.Set("X-Custom-Token", randomString(8))
}

func NewSmartFuzzer(targets []string, wordlistPath, output string, concurrency int, rps float64, startLine int) *SmartFuzzer {
   sf := &SmartFuzzer{
       Targets:        targets,
       WordlistPath:   wordlistPath,
       Output:         output,
       Concurrency:    concurrency,
       RPS:            rps,
       CheckpointFile: "checkpoint.txt",
       Baselines:      make(map[string]Baseline),
       SizeCounters:   make(map[string]map[int]int),
       SkippedTargets: make(map[string]bool),
       HardFilter:     map[int]bool{2634: true, 1091: true},
   }
   if startLine > 0 {
       sf.CurrentIdx = startLine
       fmt.Printf("[*] Manual Start: Line %d\n", sf.CurrentIdx)
   } else {
       sf.CurrentIdx = sf.loadCheckpoint()
   }
   return sf
}

func (sf *SmartFuzzer) loadCheckpoint() int {
   data, err := os.ReadFile(sf.CheckpointFile)
   if err != nil {
       return 0
   }
   var idx int
   fmt.Sscanf(string(data), "%d", &idx)
   return idx
}

func (sf *SmartFuzzer) saveCheckpoint(idx int) {
   os.WriteFile(sf.CheckpointFile, []byte(fmt.Sprintf("%d", idx)), 0644)
}

func (sf *SmartFuzzer) saveResults() {
   sf.mu.Lock()
   defer sf.mu.Unlock()
   if len(sf.Results) > 0 {
       data, _ := json.MarshalIndent(sf.Results, "", "  ")
       os.WriteFile(sf.Output, data, 0644)
   }
}

func getResponseSize(resp *http.Response) int {
   if cl := resp.Header.Get("Content-Length"); cl != "" {
       var size int
       fmt.Sscanf(cl, "%d", &size)
       return size
   }
   body, _ := io.ReadAll(resp.Body)
   return len(body)
}

func (sf *SmartFuzzer) calibrate(target string) *Baseline {
   fake := randomString(15)
   url := strings.TrimRight(target, "/") + "/" + fake
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()
   req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
   randomHeaders(req)
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
       return nil
   }
   defer resp.Body.Close()
   size := getResponseSize(resp)
   return &Baseline{Status: resp.StatusCode, Sizes: []int{size}}
}

func (sf *SmartFuzzer) worker(ctx context.Context, jobs <-chan [2]string, wg *sync.WaitGroup) {
   defer wg.Done()
   for {
       select {
       case <-ctx.Done():
           return
       case item, ok := <-jobs:
           if !ok {
               return
           }
           target, word := item[0], item[1]
           if sf.SkippedTargets[target] {
               sf.bar.Add(1)
               continue
           }
           baseline := sf.Baselines[target]
           url := strings.TrimRight(target, "/") + "/" + strings.TrimLeft(word, "/")
           req, _ := http.NewRequest("GET", url, nil)
           randomHeaders(req)
           resp, err := http.DefaultClient.Do(req)
           if err != nil {
               sf.bar.Add(1)
               continue
           }
           defer resp.Body.Close()
           if resp.StatusCode == 200 || (resp.StatusCode >= 300 && resp.StatusCode < 400) {
               size := getResponseSize(resp)
               if sf.HardFilter[size] {
                   sf.bar.Add(1)
                   continue
               }
               isNoise := false
               if resp.StatusCode == baseline.Status {
                   for _, bsize := range baseline.Sizes {
                       if abs(size-bsize) < 50 {
                           isNoise = true
                           break
                       }
                   }
               }
               if !isNoise {
                   sf.mu.Lock()
                   if sf.SizeCounters[target] == nil {
                       sf.SizeCounters[target] = make(map[int]int)
                   }
                   sf.SizeCounters[target][size]++
                   if sf.SizeCounters[target][size] > 10 {
                       sf.SkippedTargets[target] = true
                       fmt.Printf("[!] SKIPPING %s - Wildcard (Size %d)\n", target, size)
                   } else {
                       res := Result{URL: url, Status: resp.StatusCode, Size: size}
                       sf.Results = append(sf.Results, res)
                       sf.saveResults()
                       fmt.Printf("[%d] %8d bytes | %s\n", resp.StatusCode, size, url)
                   }
                   sf.mu.Unlock()
               }
           }
           sf.bar.Add(1)
       }
   }
}

func (sf *SmartFuzzer) Run() {
   for _, t := range sf.Targets {
       if b := sf.calibrate(t); b != nil {
           sf.Baselines[t] = *b
       }
   }
   file, err := os.Open(sf.WordlistPath)
   if err != nil {
       return
   }
   defer file.Close()
   var words []string
   scanner := bufio.NewScanner(file)
   for scanner.Scan() {
       word := strings.TrimSpace(scanner.Text())
       if word != "" {
           words = append(words, word)
       }
   }
   shuffle(words)
   shuffle(sf.Targets)

   totalWords := len(words) * len(sf.Baselines)
   sf.bar = progressbar.NewOptions(totalWords,
       progressbar.OptionSetDescription("Fuzzing"),
       progressbar.OptionShowCount(),
       progressbar.OptionSetWidth(15),
       progressbar.OptionThrottle(65*time.Millisecond),
       progressbar.OptionShowIts(),
       progressbar.OptionOnCompletion(func() {
           fmt.Println("\nDone!")
       }),
   )

   jobs := make(chan [2]string, 2000)
   ctx, cancel := context.WithCancel(context.Background())
   defer cancel()
   var wg sync.WaitGroup
   for i := 0; i < sf.Concurrency; i++ {
       wg.Add(1)
       go sf.worker(ctx, jobs, &wg)
   }
   idx := 0
   for _, word := range words {
       if idx < sf.CurrentIdx {
           idx++
           continue
       }
       for _, t := range sf.Targets {
           if !sf.SkippedTargets[t] {
               jobs <- [2]string{t, word}
           }
       }
       if idx%100 == 0 {
           sf.saveCheckpoint(idx)
       }
       idx++
   }
   close(jobs)
   wg.Wait()
   sf.saveCheckpoint(idx)
   sf.saveResults()
}

func randomString(n int) string {
   letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
   b := make([]rune, n)
   for i := range b {
       b[i] = letters[rand.Intn(len(letters))]
   }
   return string(b)
}

func abs(x int) int {
   if x < 0 {
       return -x
   }
   return x
}

func shuffle(slice []string) {
   rand.Seed(time.Now().UnixNano())
   rand.Shuffle(len(slice), func(i, j int) {
       slice[i], slice[j] = slice[j], slice[i]
   })
}

func main() {
   listFile := flag.String("list", "", "Target list file")
   wordlist := flag.String("wordlist", "", "Wordlist file")
   concurrency := flag.Int("c", 5, "Concurrency")
   rps := flag.Float64("rps", 5, "Requests per second")
   output := flag.String("o", "results.json", "Output file")
   start := flag.Int("s", 0, "Start line")
   flag.Parse()

   data, _ := os.ReadFile(*listFile)
   lines := strings.Split(string(data), "\n")
   var targets []string
   for _, l := range lines {
       if strings.TrimSpace(l) != "" {
           targets = append(targets, strings.TrimSpace(l))
       }
   }
   fuzzer := NewSmartFuzzer(targets, *wordlist, *output, *concurrency, *rps, *start)
   fuzzer.Run()
}