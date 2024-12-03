package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Predefined valid Swagger favicon hashes
var validSwaggerHashes = map[uint32]string{
	2809258714: "swagger-favicon1",
	1109606820: "swagger-favicon2",
	1906814157: "swagger-favicon3",
	932778223:  "swagger-favicon4",
	667846612:  "swagger-favicon5",
	1574961625: "swagger-favicon6",
	4087864177: "swagger-favicon7",
}

var (
	verbose        bool
	silent         bool
	outputFile     string
	outputFormat   string
	inputFile      string
	getFaviconHash bool
	timeout        int
	concurrent     int
	retries        int
	validOnly      bool

	wg     sync.WaitGroup
	logger *log.Logger
)

type Result struct {
	URL       string    `json:"url"`
	Valid     bool      `json:"valid"`
	Hash      uint32    `json:"hash,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

type HashOnlyResult struct {
	URL       string    `json:"url"`
	Hash      uint32    `json:"hash"`
	Timestamp time.Time `json:"timestamp"`
	Error     string    `json:"error,omitempty"`
}

func init() {
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.BoolVar(&silent, "silent", false, "Silent mode, only show results")
	flag.StringVar(&outputFile, "o", "", "Output file path (optional)")
	flag.StringVar(&inputFile, "i", "", "Input file containing potential Swagger URLs")
	flag.StringVar(&outputFormat, "format", "txt", "Output format (txt, json, csv)")
	flag.BoolVar(&getFaviconHash, "get-hash", false, "Fetch and display favicon hashes")
	flag.IntVar(&timeout, "timeout", 10, "Request timeout in seconds")
	flag.IntVar(&concurrent, "concurrent", 10, "Number of concurrent workers")
	flag.IntVar(&retries, "retries", 3, "Number of retry attempts for failed requests")
	flag.BoolVar(&validOnly, "valid", false, "Output only valid results")
}

func main() {
	flag.Parse()

	setupLogging()
	defer closeLogging()

	if !silent {
		printBanner()
	}

	if inputFile == "" {
		logger.Fatal("No input file provided. Use -i to specify a file containing URLs.")
	}

	urls, err := readURLsFromFile(inputFile)
	if err != nil {
		logger.Fatalf("Error reading input file: %v", err)
	}

	results := processURLsConcurrent(urls)

	if err := outputResults(results); err != nil {
		logger.Fatalf("Error outputting results: %v", err)
	}
}

func setupLogging() {
	var logWriter io.Writer
	if outputFile != "" {
		logFile, err := os.OpenFile("swagger_verifier.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			log.Fatalf("Failed to open log file: %v", err)
		}
		if silent {
			logWriter = logFile
		} else {
			logWriter = io.MultiWriter(logFile, os.Stdout)
		}
	} else {
		logWriter = os.Stdout
	}

	logger = log.New(logWriter, "SWAGGER_VERIFIER: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func closeLogging() {
	// Placeholder for future logging cleanup needs
}

func printBanner() {
	banner := `
    ╔═══════════════════════════════════════════════════════════════╗
    ║                   Swagger URL Verifier v2.0.2                  ║
    ║              Enhanced Favicon Detection & Analysis             ║
    ╚═══════════════════════════════════════════════════════════════╝
    `
	fmt.Println(banner)
}

func processURLsConcurrent(urls []string) []Result {
	resultsChan := make(chan Result, len(urls))
	semaphore := make(chan struct{}, concurrent)
	var results []Result

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			result := processURL(url)
			resultsChan <- result
		}(url)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
		// Only show valid URLs if -get-hash is not set and not in silent mode
		if !getFaviconHash && !silent && result.Valid {
			fmt.Printf("[+] Found valid Swagger URL: %s\n", result.URL)
		}
	}

	return results
}

func processURL(targetURL string) Result {
	result := Result{
		URL:       targetURL,
		Timestamp: time.Now(),
	}

	client := getHTTPClient()

	var err error
	for i := 0; i < retries; i++ {
		faviconURL, err := getFaviconURL(targetURL)
		if err != nil {
			continue
		}

		hash, err := fetchAndHashFavicon(client, faviconURL)
		if err != nil {
			continue
		}

		result.Hash = hash
		if getFaviconHash {
			result.Valid = true
			return result
		}
		result.Valid = isValidSwaggerHash(hash)
		return result
	}

	result.Error = err.Error()
	return result
}

func getHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(timeout) * time.Second,
	}
}

func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" && !strings.HasPrefix(url, "#") {
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid URLs found in file")
	}

	return urls, nil
}

func getFaviconURL(websiteURL string) (string, error) {
	resp, err := http.Get(websiteURL)
	if err != nil {
		return "", fmt.Errorf("error fetching website: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received status code: %d", resp.StatusCode)
	}

	return parseHTMLForFavicon(resp.Body, websiteURL)
}

func parseHTMLForFavicon(body io.Reader, websiteURL string) (string, error) {
	doc, err := html.Parse(body)
	if err != nil {
		return "", err
	}

	baseURL, err := url.Parse(websiteURL)
	if err != nil {
		return "", err
	}

	var faviconLink string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "link" {
			var rel, href string
			for _, attr := range n.Attr {
				switch attr.Key {
				case "rel":
					if strings.Contains(strings.ToLower(attr.Val), "icon") {
						rel = attr.Val
					}
				case "href":
					href = attr.Val
				}
			}
			if rel != "" && href != "" {
				faviconLink = href
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}
	traverse(doc)

	if faviconLink == "" {
		return baseURL.String() + "/favicon.ico", nil
	}

	faviconURL, err := url.Parse(faviconLink)
	if err != nil {
		return "", err
	}

	return baseURL.ResolveReference(faviconURL).String(), nil
}

func fetchAndHashFavicon(client *http.Client, faviconURL string) (uint32, error) {
	resp, err := client.Get(faviconURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("received status code: %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	hasher := fnv.New32a()
	hasher.Write(data)
	return hasher.Sum32(), nil
}

func isValidSwaggerHash(hash uint32) bool {
	_, exists := validSwaggerHashes[hash]
	return exists
}

func outputResults(results []Result) error {
	if outputFile == "" {
		return writeToStdout(results)
	}
	return writeResultsToFile(results, outputFile, outputFormat)
}

func writeToStdout(results []Result) error {
	var filteredResults []Result
	if validOnly && !getFaviconHash {
		for _, result := range results {
			if result.Valid {
				filteredResults = append(filteredResults, result)
			}
		}
	} else {
		filteredResults = results
	}

	switch strings.ToLower(outputFormat) {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if getFaviconHash {
			// Convert to HashOnlyResult to exclude the Valid field
			hashResults := make([]HashOnlyResult, len(filteredResults))
			for i, result := range filteredResults {
				hashResults[i] = HashOnlyResult{
					URL:       result.URL,
					Hash:      result.Hash,
					Timestamp: result.Timestamp,
					Error:     result.Error,
				}
			}
			return encoder.Encode(hashResults)
		}
		return encoder.Encode(filteredResults)
	case "csv":
		writer := csv.NewWriter(os.Stdout)
		defer writer.Flush()
		return writeCSVContent(writer, filteredResults)
	default: // txt format
		for _, result := range filteredResults {
			if getFaviconHash {
				fmt.Printf("[*] %s (Hash: %d)\n", result.URL, result.Hash)
			} else {
				status := "[-]"
				if result.Valid {
					status = "[+]"
				}
				fmt.Printf("%s %s (Hash: %d)\n", status, result.URL, result.Hash)
			}
		}
		return nil
	}
}

func writeResultsToFile(results []Result, outputFile string, format string) error {
	var filteredResults []Result
	if validOnly && !getFaviconHash {
		for _, result := range results {
			if result.Valid {
				filteredResults = append(filteredResults, result)
			}
		}
	} else {
		filteredResults = results
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer file.Close()

	switch strings.ToLower(format) {
	case "json":
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if getFaviconHash {
			// Convert to HashOnlyResult to exclude the Valid field
			hashResults := make([]HashOnlyResult, len(filteredResults))
			for i, result := range filteredResults {
				hashResults[i] = HashOnlyResult{
					URL:       result.URL,
					Hash:      result.Hash,
					Timestamp: result.Timestamp,
					Error:     result.Error,
				}
			}
			return encoder.Encode(hashResults)
		}
		return encoder.Encode(filteredResults)

	case "csv":
		writer := csv.NewWriter(file)
		defer writer.Flush()
		return writeCSVContent(writer, filteredResults)

	default: // txt format
		for _, result := range filteredResults {
			if getFaviconHash {
				line := fmt.Sprintf("[*] %s (Hash: %d)\n", result.URL, result.Hash)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("error writing to file: %v", err)
				}
			} else {
				status := "[-]"
				if result.Valid {
					status = "[+]"
				}
				line := fmt.Sprintf("%s %s (Hash: %d)\n", status, result.URL, result.Hash)
				if _, err := file.WriteString(line); err != nil {
					return fmt.Errorf("error writing to file: %v", err)
				}
			}
		}
	}

	return nil
}

func writeCSVContent(writer *csv.Writer, results []Result) error {
	headers := []string{"URL", "Valid", "Hash", "Timestamp", "Error"}
	if getFaviconHash {
		headers = []string{"URL", "Hash", "Timestamp", "Error"}
	}

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing CSV header: %v", err)
	}

	for _, result := range results {
		var record []string
		if getFaviconHash {
			record = []string{
				result.URL,
				fmt.Sprintf("%d", result.Hash),
				result.Timestamp.Format(time.RFC3339),
				result.Error,
			}
		} else {
			record = []string{
				result.URL,
				fmt.Sprintf("%t", result.Valid),
				fmt.Sprintf("%d", result.Hash),
				result.Timestamp.Format(time.RFC3339),
				result.Error,
			}
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("error writing CSV record: %v", err)
		}
	}
	return nil
}
