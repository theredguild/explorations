# Public explorations repository
This repository is a place to share smaller discoveries, experiments, and code snippets that might otherwise remain hidden. While nothing here is fully tested or explored, we’d rather present these glimpses than keep them tucked away. Perhaps someone else will find them useful or build upon them.


## VSExInspector.py: VSCode Extension Marketplace Inspector
Updating our devcontainer, I found a few suspicious VSCode extensions. We have already talked about this in the past, how easy it is to publish one and trick rating/downloads, and other details. So as a direct consequence of malicious extensions being deployed, tricking users into downloading them only to get rekt, we created a tool to start exploring how to monitor and filter extensions to request additional information and download to further analysis.

Current examples may be incomplete and are just examples; it does not mean they are malicious extensions.

TODO:
- [ ] Evaluate publisher information 
- [ ] Use GitHub Fake Analyzer or something of the sort to dig some info from repository
- [ ] Improve search filters

```
❯ python vscode/VSExInspector.py --help
usage: VSExInspector.py [-h] [--keywords KEYWORDS] [--tags TAGS]
                        [--date-type DATE_TYPE] [--range-days RANGE_DAYS] [--download]
                        [--download-only DOWNLOAD_ONLY] [--analyze] [--info]
                        [--info-only INFO_ONLY] [--monitor] [--every EVERY]
                        [--discord] [--discord-hook DISCORD_HOOK]

Fetch and display VSCode extensions from the Marketplace.

options:
  -h, --help            show this help message and exit
  --keywords KEYWORDS   Comma-separated keywords to search for extensions.
  --tags TAGS           Semicolon-separated tags to filter for extensions, e.g.
                        'tag1;tag2'
  --date-type DATE_TYPE
                        releaseDate, publishedDate or lastUpdated
  --range-days RANGE_DAYS
                        Number of days to filter extensions by date.
  --download            Download and unzip VSIX files for matched extensions.
  --download-only DOWNLOAD_ONLY
                        Download a specific VSIX file by publisher.extensionname.
  --analyze             Analyze extensions for suspicious characteristics.
  --info                Display additional informational fields for extensions.
  --info-only INFO_ONLY
                        Fetch and display full information for a specific
                        publisher.extension.
  --monitor             Run in daemon mode, checking updates every X minutes.
  --every EVERY         Interval in minutes for the monitor (default: 5).
  --discord             Send monitor messages to Discord (default off).
  --discord-hook DISCORD_HOOK
                        Set a custom Discord webhook. Otherwise uses DISCORD_WEBHOOK
                        from environment variable or code default.
```

### Example: Info & analyze, 30 days, few keywords.
Let's say we want to gather information and do an analysis on the past 30 days with a few keywords like solidity, ethereum and blockchain.

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
  Link: https://marketplace.visualstudio.com/items?itemName=volcanic.crypto-price-viewer

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

### Example: Download only
Let's download a specific extension, no analysis.

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

### Example: Monitor & push to discord
Now, attackers may push a seemly legit repository, to be updated later with malicious content. So let's filter by lastUpdated and monitor it every 30' filtering by solidity, blockchain and ethereum tags.

There are several ways to include your webhook, you can add it exporting `DISCORD_WEBHOOK` as an env variable, or by using `--discord-hook [INSERT_YOUR_WEBHOOK_HERE]`

```
❯ DISCORD_WEBHOOK=[INSERT_YOUR_WEBHOOK_HERE] python vscode/VSExInspector.py --range-days 10 --date-type lastUpdated --monitor --every 30 --tags "solidity;blockchain;ethereum" --discord

[Monitor] Fetching extensions in monitor mode...
Filtering only by tags...
  Using tag: solidity
  Using tag: blockchain
  Using tag: ethereum

[JuanBlanco.solidity]
  Display Name: solidity
  Publisher: Juan Blanco (JuanBlanco)
  Domain: N/A (Verified: False)
  Published Date: 19/11/2015 at 07:35:23
  Last Updated: 07/01/2025 at 10:54:21
  Release Date: 19/11/2015 at 07:35:23
  Description: Ethereum Solidity Language for Visual Studio Code
  Link: https://marketplace.visualstudio.com/items?itemName=JuanBlanco.solidity

[NomicFoundation.hardhat-solidity]
  Display Name: Solidity
  Publisher: Nomic Foundation (NomicFoundation)
  Domain: https://nomic.foundation (Verified: True)
  Published Date: 10/03/2022 at 16:28:30
  Last Updated: 14/01/2025 at 23:37:01
  Release Date: 10/03/2022 at 16:28:30
  Description: Solidity and Hardhat support by the Hardhat team
  Link: https://marketplace.visualstudio.com/items?itemName=NomicFoundation.hardhat-solidity

[KonVik.tact-lang-vscode]
  Display Name: Tact Language Support for TON blockchain
  Publisher: Kon Vik (KonVik)
  Domain: N/A (Verified: False)
  Published Date: 26/04/2023 at 04:51:53
  Last Updated: 13/01/2025 at 19:02:18
  Release Date: 26/04/2023 at 04:51:53
  Description: Tact language (for .tact file) extension to use together with Tact compiler for Visual Studio Code to develop smart contract for TON blockchain
  Link: https://marketplace.visualstudio.com/items?itemName=KonVik.tact-lang-vscode

[RuntimeVerification.simbolik]
  Display Name: Simbolik: Solidity Debugger
  Publisher: RuntimeVerification (RuntimeVerification)
  Domain: https://runtimeverification.com/ (Verified: False)
  Published Date: 27/05/2024 at 10:06:56
  Last Updated: 13/01/2025 at 18:17:01
  Release Date: 27/05/2024 at 10:06:56
  Description: Advanced Solidity and EVM Debugger
  Link: https://marketplace.visualstudio.com/items?itemName=RuntimeVerification.simbolik
[Monitor] Sleeping for 30 minute(s)...

```