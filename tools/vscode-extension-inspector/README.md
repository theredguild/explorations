# VSCode Extension Marketplace Inspector

A Python tool for monitoring and analyzing VSCode extensions from the marketplace. Designed to help identify potentially malicious or suspicious extensions by analyzing their metadata, download patterns, and publisher information.

## Features

- **Search & Filter**: Search extensions by keywords, tags, and date ranges
- **Suspicious Pattern Detection**: Analyze extensions for red flags like unverified publishers, low download counts, or recent creation dates
- **Download & Analysis**: Download VSIX files for deeper inspection
- **Monitoring Mode**: Continuously monitor for new or updated extensions
- **Discord Integration**: Send alerts to Discord webhooks
- **Publisher Verification**: Check publisher verification status and domain ownership

## Quick Start

```bash
# Basic search
python VSExInspector.py --keywords "solidity,ethereum,blockchain" --info --analyze

# Download specific extension
python VSExInspector.py --download-only volcanic.crypto-price-viewer

# Monitor mode with Discord alerts
python VSExInspector.py --range-days 10 --monitor --every 30 --discord
```

## Usage

### Command Line Options

```bash
python VSExInspector.py [OPTIONS]

Options:
  --keywords KEYWORDS       Comma-separated keywords to search
  --tags TAGS              Semicolon-separated tags to filter (tag1;tag2)
  --date-type DATE_TYPE    Filter by: releaseDate, publishedDate, lastUpdated
  --range-days RANGE_DAYS  Number of days to look back
  --download               Download and unzip matched extensions
  --download-only ID       Download specific extension by publisher.name
  --analyze                Analyze extensions for suspicious patterns
  --info                   Show detailed extension information
  --info-only ID           Get full info for specific extension
  --monitor                Run in daemon mode
  --every EVERY            Monitor interval in minutes (default: 5)
  --discord                Send alerts to Discord
  --discord-hook URL       Custom Discord webhook URL
```

### Examples

#### Search and Analyze Recent Extensions
```bash
python VSExInspector.py --range-days 30 \
  --keywords "solidity,ethereum,blockchain" \
  --date-type releaseDate \
  --info --analyze
```

#### Download Extension for Analysis
```bash
python VSExInspector.py --download-only volcanic.crypto-price-viewer
tree ext_downloads/volcanic.crypto-price-viewer_2.0.0/
```

#### Monitor with Discord Alerts
```bash
# Set webhook via environment variable
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."

# Or pass directly
python VSExInspector.py --monitor --every 30 \
  --tags "solidity;blockchain;ethereum" \
  --discord --discord-hook "https://discord.com/api/webhooks/..."
```

## Suspicious Pattern Detection

The analyzer flags extensions based on:

- **Unverified Publisher**: Domain not verified with Microsoft
- **New Extension**: Less than 30 days old
- **Low Downloads**: Fewer than 100 downloads
- **Few Reviews**: Less than 5 reviews
- **Suspicious Naming**: Typosquatting patterns
- **Rapid Updates**: Unusual update frequency

## Output Structure

### Extension Information
- Display name and publisher
- Verification status and domain
- Publication, update, and release dates
- Description and marketplace link
- Statistics (downloads, ratings, trends)

### Downloaded Extensions
Extensions are saved to `ext_downloads/publisher.extension_version/`:
```
ext_downloads/volcanic.crypto-price-viewer_2.0.0/
├── [Content_Types].xml
├── extension/
│   ├── package.json
│   ├── README.md
│   └── ...
└── extension.vsixmanifest
```

## Web Interface

A basic web interface is available in the `web/` directory for viewing results:
- `index.html`: Main interface
- `inspector.js`: JavaScript functionality  
- `style.css`: Styling

## Requirements

- Python 3.7+
- `requests` library
- Internet connection for marketplace API access

## Security Note

This tool is designed for defensive security research. Use responsibly and respect the VSCode Marketplace terms of service. Downloaded extensions should be analyzed in isolated environments.