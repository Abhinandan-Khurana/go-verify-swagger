# Swagger Verifier

A robust and efficient tool to verify Swagger URLs by fetching and validating their favicons. Built with concurrency and enhanced logging for seamless performance.

## Features

- **Favicon Verification**: Retrieves and validates favicons using reliable HTML parsing.
- **Hash Matching**: Compares favicon hashes against predefined valid Swagger hashes.
- **Concurrent Processing**: Optimized with goroutines for faster URL verification.
- **Flexible Output**: Supports TXT, JSON, and CSV formats for result storage.
- **Verbose Logging**: Offers multiple logging levels for detailed insights.
- **Favicon Hash Retrieval**: Option to fetch and display favicon hashes for given URLs.

## Installation

Ensure you have [Go](https://golang.org/dl/) installed.

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/Abhinandan-Khurana/swagger-verifier.git
   cd swagger-verifier
   ```

2. **Build the Executable**:
   ```bash
   go build -o swagger_verifier swagger_verifier.go
   ```

## Usage

### Basic Verification

Verify URLs from an input file:

```bash
./swagger_verifier -i urls.txt
```

### Enable Verbose Logging

```bash
./swagger_verifier -i urls.txt -v
```

### Fetch and Display Favicon Hashes

```bash
./swagger_verifier -i urls.txt -get-hash
```

### Output Results to a JSON File

```bash
./swagger_verifier -i urls.txt -o results.json -format json
```

### Enable Ultra Verbose Logging

```bash
./swagger_verifier -i urls.txt -vv
```

### Command-Line Flags

- `-i, --input`: **(Required)** Path to the input file containing URLs.
- `-o, --output`: Path to the output file. Choose format with extension (`.txt`, `.json`, `.csv`).
- `-format`: Output format (`txt`, `json`, `csv`). Default is `txt`.
- `-v`: Enable verbose logging.
- `-vv`: Enable ultra verbose logging for debugging.
- `-silent`: Silent mode; only show results.
- `-get-hash`: Fetch and display favicon hashes for the input URLs.

## Example

Given a `urls.txt`:

```
https://example.com
https://swagger.io
https://api.github.com
```

Run the verifier:

```bash
./swagger_verifier -i urls.txt -o verified.json -format json -v
```

## Logs

Logs are written to both the console and `swagger_verifier.log`. Use verbose modes (`-v` or `-vv`) for detailed logs.

## Notes

- **Valid Swagger Hashes**: Update the `validSwaggerHashes` map with actual FNV hash values corresponding to valid Swagger favicons for accurate verification.
- **TLS Verification**: Currently, TLS certificate verification is disabled (`InsecureSkipVerify: true`). For enhanced security, consider enabling it in production environments.
- **Error Handling**: The tool exits on critical errors like missing input files. Ensure input files are correctly formatted and accessible.
- **Fallback Mechanism**: If no `<link rel="icon">` tag is found, the tool attempts to fetch `/favicon.ico` as a fallback.

## License

MIT License. See [LICENSE](LICENSE) for details.

---

_Created with ❤️ by Abhinandan-Khurana_
