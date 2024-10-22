package get_favicon_url

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// getFaviconURL retrieves the favicon URL from the given website URL by parsing its HTML.
func getFaviconURL(websiteURL string) (string, error) {
	// Fetch the website's HTML
	resp, err := http.Get(websiteURL)
	if err != nil {
		return "", fmt.Errorf("error fetching website HTML: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
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

// parseHTMLForFavicon parses the HTML and finds the <link rel="icon"> or similar tag.
func parseHTMLForFavicon(body io.Reader, websiteURL string) (string, error) {
	doc, err := html.Parse(body)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML: %v", err)
	}

	// Traverse the HTML nodes to find the <link> tag with rel="icon"
	var faviconLink string
	var f func(*html.Node)
	f = func(n *html.Node) {
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
			f(c)
		}
	}
	f(doc)

	// If a favicon link was found, resolve its URL (handle relative URLs)
	if faviconLink != "" {
		base, err := url.Parse(websiteURL)
		if err != nil {
			return "", fmt.Errorf("error parsing base URL: %v", err)
		}
		faviconURL, err := url.Parse(faviconLink)
		if err != nil {
			return "", fmt.Errorf("error parsing favicon URL: %v", err)
		}

		// Resolve the full URL
		fullURL := base.ResolveReference(faviconURL).String()
		return fullURL, nil
	}

	return "", nil
}

func main() {
	websiteURL := "https://swagger.io" // Example
	faviconURL, err := getFaviconURL(websiteURL)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Printf("Favicon URL for %s: %s\n", websiteURL, faviconURL)
}
