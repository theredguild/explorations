# Tool & scripts public exploration repository
A misc repository for tool explorations and useful scripts that we use.

## VSExInspector.py: VSCode Extension Marketplace Inspector
Current examples are just examples; it does not mean they are malicious extensions.

```
❯ python VSExInspector.py --help
usage: VSExInspector.py [-h] [--keywords KEYWORDS] [--date-type DATE_TYPE] [--range-days RANGE_DAYS] [--download] [--download-only DOWNLOAD_ONLY] [--analyze] [--info]
                                        [--info-only INFO_ONLY]

Fetch and display VSCode extensions from the Marketplace.

options:
  -h, --help            show this help message and exit
  --keywords KEYWORDS   Comma-separated keywords to search for extensions.
  --date-type DATE_TYPE
                        releaseDate, publishedDate or lastUpdated
  --range-days RANGE_DAYS
                        Number of days to filter extensions by date.
  --download            Download and unzip VSIX files for all matched extensions.
  --download-only DOWNLOAD_ONLY
                        Download a specific VSIX file by publisher.extensionname.
  --analyze             Analyze extensions for suspicious characteristics.
  --info                Display additional informational fields for extensions.
  --info-only INFO_ONLY
                        Fetch and display full information for a specific publisher.extension.
```

### Example: Info & analyze, 30 days, few keywords.
- From the past 30 days: `--range-days 30` 
- Keywords: `--keywords "solidity, ethereum, blockchain`
- Date type by release date: `--date-type releaseDate```
- Print information: `--info`
- Analyze: `--analyze`

```
~/guild via 🐍 v3.12.7 took 3s
❯ python VSExInspector.py --range-days 30 --keywords "solidity, ethereum, blockchain" --date-type releaseDate --info --analyze
Fetching extensions for keyword: solidity
Fetching extensions for keyword: ethereum
Fetching extensions for keyword: blockchain

[volcanic.crypto-price-viewer]
  Display Name: Crypto Price Viewer
  Publisher: volcanic (volcanic)
  Domain: N/A (Verified: False)
  Published Date: 17/12/2024 at 03:19:25
  Last Updated: 11/01/2025 at 09:26:48
  Release Date: 17/12/2024 at 03:19:25
  Description: Real-time cryptocurrency price viewer with market data, supply info, and lock-up details. Support multiple data sources and automatic failover.

  Additional Information:
    PublisherId: 47ce81f1-0e97-41a4-83aa-b568b7c537ac
    Publisher Flags: verified
    ExtensionId: 85e23536-c456-458d-928e-971fd3dae5b4
    Extension Flags: validated, public
    Short Description: Real-time cryptocurrency price viewer with market data, supply info, and lock-up details. Support multiple data sources and automatic failover.
    Getstarted: https://github.com/volcanicll/crypto-price-viewer.git
    Support: https://github.com/volcanicll/crypto-price-viewer/issues
    Learn: https://github.com/volcanicll/crypto-price-viewer#readme
    Source: https://github.com/volcanicll/crypto-price-viewer.git
    GitHub: https://github.com/volcanicll/crypto-price-viewer.git
    Changelog: https://volcanic.gallerycdn.vsassets.io/extensions/volcanic/crypto-price-viewer/2.0.0/1736587399060/Microsoft.VisualStudio.Services.Content.Changelog
    Details: https://volcanic.gallerycdn.vsassets.io/extensions/volcanic/crypto-price-viewer/2.0.0/1736587399060/Microsoft.VisualStudio.Services.Content.Details

    More statistics:
      trendingdaily: 0
      trendingmonthly: 0
      trendingweekly: 0
      updateCount: 1
      weightedRating: 4.403204729309272

  Suspiciousness: 4/6
    Warning: Domain is not verified.
    Warning: Extension is newly created (less than 30 days).
    Warning: Low download count (less than 100).
    Warning: Few reviews (less than 5).
```

### Download only: 
```
~/guild via 🐍 v3.12.7
❯ python VSExInspector.py --download-only volcanic.crypto-price-viewer
Fetching volcanic.crypto-price-viewer...
  VSIX downloaded and unzipped to ext_downloads/volcanic.crypto-price-viewer_2.0.0
~/guild via 🐍 v3.12.7
❯ tree -L 2 ext_downloads/volcanic.crypto-price-viewer_2.0.0/
ext_downloads/volcanic.crypto-price-viewer_2.0.0/
├── [Content_Types].xml
├── extension
│   ├── CHANGELOG.md
│   ├── LICENSE.txt
│   ├── node_modules
│   ├── out
│   ├── package.json
│   ├── README.md
│   └── resources
└── extension.vsixmanifest

5 directories, 6 files
```
