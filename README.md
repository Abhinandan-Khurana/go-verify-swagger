# go-verify-swagger

A robust and efficient tool to verify Swagger URLs by fetching and validating their favicons. Built with advanced concurrency, comprehensive logging, and enhanced output options.

## Features

- **Advanced Favicon Verification**: Robust HTML parsing with fallback mechanisms
- **Intelligent Hash Matching**: FNV32-based favicon hash verification
- **High Performance Processing**: Configurable concurrent execution with worker pools
- **Flexible Output Options**:
  - Multiple formats (TXT, JSON, CSV)
  - Filtered output for valid results only
  - Console or file output support
- **Enhanced Logging System**:
  - Configurable verbosity levels
  - Detailed execution insights
  - Error tracking and reporting
- **Robust Error Handling**: Retry mechanisms and graceful failure recovery
- **Resource Management**: Proper cleanup and resource allocation

## Installation

### Direct Installation

```bash
go install -v github.com/Abhinandan-Khurana/go-verify-swagger@vlatest
```

### Manual Installation

```bash
git clone https://github.com/Abhinandan-Khurana/go-verify-swagger.git
cd swagger-verifier
go build -o dist/go-verify-swagger main.go
```

## Usage

### Basic Usage

```bash
go-verify-swagger -i urls.txt
```

### Advanced Usage Examples

```bash
# Output only valid results in JSON format
go-verify-swagger -i urls.txt -format json -valid

# Custom concurrency and timeout settings
go-verify-swagger -i urls.txt -concurrent 20 -timeout 15

# Verbose mode with CSV output
go-verify-swagger -i urls.txt -v -format csv -o results.csv

# Silent mode with custom retry attempts
go-verify-swagger -i urls.txt -silent -retries 5
```

### Command-Line Flags

| Flag          | Description                    | Default |
| ------------- | ------------------------------ | ------- |
| `-i`          | Input file path (required)     | -       |
| `-o`          | Output file path               | stdout  |
| `-format`     | Output format (txt, json, csv) | txt     |
| `-v`          | Enable verbose logging         | false   |
| `-silent`     | Silent mode                    | false   |
| `-get-hash`   | Display favicon hashes         | false   |
| `-valid`      | Output only valid results      | false   |
| `-concurrent` | Number of concurrent workers   | 10      |
| `-timeout`    | Request timeout in seconds     | 10      |
| `-retries`    | Number of retry attempts       | 3       |

## Output Formats

### JSON Format

```json
{
  "url": "https://example.com",
  "valid": true,
  "hash": 1234567890,
  "timestamp": "2024-01-01T12:00:00Z",
  "error": ""
}
```

### CSV Format

```csv
URL,Valid,Hash,Timestamp,Error
https://example.com,true,1234567890,2024-01-01T12:00:00Z,
```

### Text Format

```
[+] https://example.com (Hash: 1234567890)
```

## Advanced Features

### Concurrent Processing

- Configurable worker pool size
- Controlled resource utilization
- Non-blocking result collection

### Error Handling

- Automatic retry mechanism
- Detailed error reporting
- Graceful failure recovery

### Resource Management

- Proper cleanup of connections
- Managed goroutine lifecycle
- Efficient memory utilization

## Notes

- **Hash Verification**: The tool uses FNV32 hashing for favicon comparison. Update `validSwaggerHashes` map for custom hash validation.
- **TLS Security**: TLS verification is disabled by default. Enable it for production use by modifying the `getHTTPClient()` function.
- **Performance Tuning**: Adjust `-concurrent` and `-timeout` flags based on your network conditions and requirements.
- **Error Recovery**: The tool implements retry mechanisms for transient failures. Adjust `-retries` for different scenarios.

## Example Configuration

`urls.txt`:

```
https://example.com
https://swagger.io
https://api.github.com
```

Run with full features:

```bash
go-verify-swagger -i urls.txt -o results.json -format json -v -concurrent 15 -timeout 20 -retries 5 -valid
```

## Logging

- Logs are written to both console and `swagger_verifier.log`
- Use `-v` for detailed execution logs
- Silent mode (`-silent`) suppresses console output
- Error logs are always preserved

This tool is designed for both simplicity and power, suitable for both basic verification tasks and advanced integration scenarios.
