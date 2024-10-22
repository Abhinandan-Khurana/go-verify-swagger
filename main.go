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

	"golang.org/x/net/html"
)

// Predefined valid Swagger favicon hashes (Replace with actual hashes)
var validSwaggerHashes = map[uint32]string{
	2809258714: "swagger-favicon1",
	1109606820: "swagger-favicon2",
	1906814157: "swagger-favicon3",
	932778223:  "swagger-favicon4",
}

var (
	verbose        bool
	silent         bool
	outputFile     string
	outputFormat   string
	inputFile      string
	getFaviconHash bool
	ultraVerbose   bool
	wg             sync.WaitGroup
	logger         *log.Logger
)

// Result struct to hold each URL result
type Result struct {
	URL   string `json:"url"`
	Valid bool   `json:"valid"`
}

// Banner to display whenthe program starts
func printBanner() {
	fmt.Println(`
  
____ _ _ _ ____ ____ ____ ____ ____    _  _ ____ ____ _ ____ _ ____ ____    
[__  | | | |__| | __ | __ |___ |__/    |  | |___ |__/ | |___ | |___ |__/    
___] |_|_| |  | |__] |__] |___ |  \     \/  |___ |  \ | |    | |___ |  \    

                                               ~ by L0u51f3r007
`)
}

// Initialize command-line flags and logger
func init() {
	// Command-line flags
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.BoolVar(&silent, "silent", false, "Silent mode, only show results")
	flag.StringVar(&outputFile, "o", "", "Output file (choose format with .txt, .json, .csv)")
	flag.StringVar(&inputFile, "i", "", "Input file containing potential Swagger URLs")
	flag.StringVar(&outputFormat, "format", "txt", "Output format (txt, json, csv)")
	flag.BoolVar(&getFaviconHash, "get-hash", false, "Fetch and display favicon hashes for the input URLs")
	flag.BoolVar(&ultraVerbose, "vv", false, "Enable ultra verbose logging for debugging")
}

func main() {
	// Parse command-line flags
	flag.Parse()

	// Setup logging
	setupLogging()
	defer closeLogging()

	if verbose && !silent {
		logger.Println("Verbose mode activated")
	}

	if !silent {
		printBanner()
	}

	// Validate input file
	if inputFile == "" {
		logger.Println("No input file provided. Use -i to specify a file containing potential Swagger URLs.")
		os.Exit(1)
	}

	// Read input URLs from file
	urls, err := readURLsFromFile(inputFile)
	if err != nil {
		logger.Fatalf("Error reading input file: %v", err)
	}

	// Handle -get-hash flag
	if getFaviconHash {
		fetchFaviconHashes(urls)
		os.Exit(0)
	}

	// Process URLs concurrently
	foundSwagger := processURLs(urls)

	// Output results if required
	if outputFile != "" {
		if err := writeResultsToFile(foundSwagger, outputFile, outputFormat); err != nil {
			logger.Fatalf("Error writing output: %v", err)
		}
		if !silent {
			fmt.Printf("[+] Results saved to %s\n", outputFile)
		}
	}
}

// setupLogging initializes the logger
func setupLogging() {
	logFile, err := os.OpenFile("swagger_verifier.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	logger = log.New(io.MultiWriter(logFile, os.Stdout), "SWAGGER_VERIFIER: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// closeLogging ensures the log file is properly closed
func closeLogging() {
	// Currently, nothing to close as logFile is handled by os.Exit or main defer
}

// processURLs handles the concurrent processing of URLs
func processURLs(urls []string) []Result {
	results := make(chan Result)
	var foundSwagger []Result

	// Start workers
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			isValid := checkSwaggerURL(url)
			results <- Result{URL: url, Valid: isValid}
		}(url)
	}

	// Close the results channel once all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for res := range results {
		if res.Valid {
			if !silent {
				fmt.Printf("[+] Found valid Swagger URL: %s\n", res.URL)
			}
			foundSwagger = append(foundSwagger, res)
		} else if verbose {
			logger.Printf("[-] Invalid Swagger URL: %s\n", res.URL)
		}
	}

	return foundSwagger
}

// checkSwaggerURL verifies if the given URL has a valid Swagger favicon
func checkSwaggerURL(url string) bool {
	faviconURL, err := getFaviconURL(url)
	if err != nil {
		if verbose {
			logger.Printf("Error finding favicon for %s: %v", url, err)
		}
		return false
	}

	resp, err := http.Get(faviconURL)
	if err != nil {
		if verbose {
			logger.Printf("Error fetching %s: %v", faviconURL, err)
		}
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if verbose {
			logger.Printf("Non-200 status for %s: %d", faviconURL, resp.StatusCode)
		}
		return false
	}

	// Read the favicon content
	faviconBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		if verbose {
			logger.Printf("Error reading favicon content from %s: %v", faviconURL, err)
		}
		return false
	}

	// Compute the hash
	faviconHash := hashFavicon(faviconBytes)

	// Check if the hash matches a valid Swagger favicon
	if _, exists := validSwaggerHashes[faviconHash]; exists {
		return true
	}

	return false
}

// hashFavicon computes the FNV hash of the favicon data
func hashFavicon(data []byte) uint32 {
	hasher := fnv.New32a()
	hasher.Write(data)
	return hasher.Sum32()
}

// readURLsFromFile reads potential Swagger URLs from a file
func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return urls, nil
}

// writeResultsToFile writes the results to the specified output file in the selected format
func writeResultsToFile(results []Result, outputFile, format string) error {
	switch strings.ToLower(format) {
	case "txt":
		return writeTXT(results, outputFile)
	case "json":
		return writeJSON(results, outputFile)
	case "csv":
		return writeCSV(results, outputFile)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// writeTXT writes the results in plain text format
func writeTXT(results []Result, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range results {
		if _, err := file.WriteString(result.URL + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// writeJSON writes the results in JSON format
func writeJSON(results []Result, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// writeCSV writes the results in CSV format
func writeCSV(results []Result, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{"URL", "Valid"}); err != nil {
		return err
	}

	for _, result := range results {
		if err := writer.Write([]string{result.URL, fmt.Sprintf("%t", result.Valid)}); err != nil {
			return err
		}
	}
	return nil
}

// fetchFaviconHashes retrieves and prints the favicon hash for each URL in the list
func fetchFaviconHashes(urls []string) {
	var wg sync.WaitGroup
	client := getHTTPClient() // Create the custom HTTP client

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			faviconURL, err := getFaviconURL(url)
			if err != nil {
				if verbose {
					logger.Printf("Error finding favicon for %s: %v", url, err)
				}
				return
			}

			// Fetch the favicon using the custom client
			resp, err := client.Get(faviconURL)
			if err != nil {
				if verbose {
					logger.Printf("Error fetching favicon for %s: %v", faviconURL, err)
				}
				return
			}
			defer resp.Body.Close()

			// Handle non-200 status codes
			if resp.StatusCode != http.StatusOK {
				if verbose {
					logger.Printf("Non-200 status for %s: %d", faviconURL, resp.StatusCode)
				}
				return
			}

			faviconBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				if verbose {
					logger.Printf("Error reading favicon from %s: %v", faviconURL, err)
				}
				return
			}

			hash := hashFavicon(faviconBytes)
			fmt.Printf("[Favicon Hash] URL: %s, Favicon URL: %s, Hash: %d\n", url, faviconURL, hash)
		}(url)
	}
	wg.Wait()
}

// getHTTPClient creates an HTTP client with TLS verification disabled
func getHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Disables certificate verification
	}
	return &http.Client{Transport: tr}
}

// getFaviconURL retrieves the favicon URL from the given website URL by parsing its HTML
func getFaviconURL(websiteURL string) (string, error) {
	// Fetch the website's HTML
	resp, err := http.Get(websiteURL)
	if err != nil {
		return "", fmt.Errorf("error fetching website HTML: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	// Parse the HTML and look for <link rel="icon">
	faviconURL, err := parseHTMLForFavicon(resp.Body, websiteURL)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML for favicon: %v", err)
	}

	if faviconURL == "" {
		return "", fmt.Errorf("favicon not found for %s", websiteURL)
	}

	return faviconURL, nil
}

// parseHTMLForFavicon parses the HTML and finds the <link rel="icon"> or similar tag
func parseHTMLForFavicon(body io.Reader, websiteURL string) (string, error) {
	doc, err := html.Parse(body)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML: %v", err)
	}

	var faviconLink string
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if faviconLink != "" {
			return
		}
		if n.Type == html.ElementNode && n.Data == "link" {
			var rel, href string
			for _, attr := range n.Attr {
				if attr.Key == "rel" && strings.Contains(strings.ToLower(attr.Val), "icon") {
					rel = attr.Val
				}
				if attr.Key == "href" {
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

	if faviconLink != "" {
		base, err := url.Parse(websiteURL)
		if err != nil {
			return "", fmt.Errorf("error parsing base URL: %v", err)
		}
		faviconURL, err := url.Parse(faviconLink)
		if err != nil {
			return "", fmt.Errorf("error parsing favicon URL: %v", err)
		}

		fullURL := base.ResolveReference(faviconURL).String()
		return fullURL, nil
	}

	// Fallback to /favicon.ico if no link tag is found
	fallbackURL := strings.TrimRight(websiteURL, "/") + "/favicon.ico"
	return fallbackURL, nil
}
