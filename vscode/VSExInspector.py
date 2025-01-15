import os
import json
import time
import requests
import argparse
import zipfile
from io import BytesIO
from datetime import datetime, timedelta, timezone

API_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
HEADERS = {
    "accept": "application/json;api-version=3.0-preview.1",
    "content-type": "application/json",
}
PREVIOUS_FETCH_FILE = "previously_fetched.json"


def send_to_discord(message: str):
    """
    Sends the given message to the configured Discord webhook.
    Monitor-related results only.
    """
    original_message = message
    message = ""
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": original_message})
    except requests.RequestException as ex:
        print(f"Failed to send to Discord: {ex}")


def load_previously_fetched() -> dict:
    """
    Loads the previously fetched extensions from JSON on disk.
    Returns a dict with { 'publisher.extensionName': {...}, ... } or empty if not found.
    """
    if os.path.exists(PREVIOUS_FETCH_FILE):
        with open(PREVIOUS_FETCH_FILE, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
            except json.JSONDecodeError:
                pass
    return {}


def save_previously_fetched(data: dict):
    """
    Saves the fetched extensions data to disk as JSON.
    """
    with open(PREVIOUS_FETCH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def format_date(date_str):
    """Format ISO date to DD/MM/YYYY at HH:MM:SS."""
    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    return dt.strftime("%d/%m/%Y at %H:%M:%S")


def query_extensions(body):
    """
    Perform the Marketplace API POST request with the given body
    and return the 'extensions' list in the first results batch.
    """
    response = requests.post(API_URL, headers=HEADERS, json=body)
    response.raise_for_status()
    return response.json()["results"][0]["extensions"]


def fetch_extensions(keywords=None, tags=None, page_size=100):
    """
    Fetch extensions based on optional keywords and tags.
    - keywords: list of strings (e.g. ["python", "java"])
    - tags: list of strings (e.g. ["blockchain", "compiler"])
    """
    if not keywords and not tags:
        print("No keywords or tags provided. Returning empty list.")
        return []

    if keywords is None:
        keywords = []
    if tags is None:
        tags = []

    all_extensions = []

    # Case 1: If we have no keywords but DO have tags => single query using only the tags.
    if not keywords and tags:
        print("Filtering only by tags...")
        criteria_list = [
            {"filterType": 8, "value": "Microsoft.VisualStudio.Code"}
        ]
        # Add each tag to the criteria
        for tag in tags:
            print(f"  Using tag: {tag}")
            criteria_list.append({"filterType": 1, "value": tag})

        body = {
            "filters": [
                {
                    "criteria": criteria_list,
                    "pageNumber": 1,
                    "pageSize": page_size,
                    "sortBy": 4,
                    "sortOrder": 0
                }
            ],
            "assetTypes": [],
            "flags": 914
        }
        extensions = query_extensions(body)
        all_extensions.extend(extensions)
        return all_extensions

    # Case 2: If we have keywords (and optionally tags), run multiple queries: 
    # one per keyword, but each query also includes the tags if present.
    for keyword in keywords:
        print(f"Fetching extensions for keyword: {keyword}")
        criteria_list = [
            {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
            {"filterType": 10, "value": keyword}
        ]
        # If user also passed tags, add them
        for tag in tags:
            print(f"  Also filtering by tag: {tag}")
            criteria_list.append({"filterType": 1, "value": tag})

        body = {
            "filters": [
                {
                    "criteria": criteria_list,
                    "pageNumber": 1,
                    "pageSize": page_size,
                    "sortBy": 4,
                    "sortOrder": 0
                }
            ],
            "assetTypes": [],
            "flags": 914
        }
        extensions = query_extensions(body)
        all_extensions.extend(extensions)

    return all_extensions


def fetch_extension_by_name(publisher_extension):
    """
    Fetch details of a specific extension by `publisher.extensionName`.
    Returns a list with that single extension if found, otherwise empty list.
    """
    publisher, extension_name = publisher_extension.split(".")
    print(f"Fetching information for {publisher_extension}...")
    body = {
        "filters": [
            {
                "criteria": [
                    {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                    {"filterType": 10, "value": extension_name}
                ],
                "pageNumber": 1,
                "pageSize": 1,
                "sortBy": 4,
                "sortOrder": 0
            }
        ],
        "assetTypes": [],
        "flags": 914
    }

    extensions = query_extensions(body)
    if extensions:
        ext = extensions[0]
        if ext["publisher"]["publisherName"] == publisher:
            return [ext]
    print(f"Error: {publisher_extension} not found.")
    return []


def filter_extensions_by_date(extensions, days, date_type):
    """Filter extensions by whether `date_type` is within the last `days` days."""
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    filtered_extensions = []

    for ext in extensions:
        dates = {
            "publishedDate": datetime.fromisoformat(ext.get("publishedDate", "1970-01-01T00:00:00.000+00:00").replace("Z", "+00:00")),
            "lastUpdated": datetime.fromisoformat(ext.get("lastUpdated", "1970-01-01T00:00:00.000+00:00").replace("Z", "+00:00")),
            "releaseDate": datetime.fromisoformat(ext.get("releaseDate", "1970-01-01T00:00:00.000+00:00").replace("Z", "+00:00")),
        }
        if dates[date_type] >= cutoff_date:
            filtered_extensions.append(ext)

    return filtered_extensions


def unique_extensions(extensions):
    """Remove duplicate extensions based on publisher and extension name."""
    seen = set()
    unique = []
    for ext in extensions:
        key = f"{ext['publisher']['publisherName']}.{ext['extensionName']}"
        if key not in seen:
            seen.add(key)
            unique.append(ext)
    return unique


def download_vsix(extension):
    """Download the VSIX file for the given extension and unzip it."""
    version = extension["versions"][0]["version"]
    publisher = extension["publisher"]["publisherName"]
    name = extension["extensionName"]
    vsix_url = next(file["source"] for file in extension["versions"][0]["files"]
                    if file["assetType"] == "Microsoft.VisualStudio.Services.VSIXPackage")

    response = requests.get(vsix_url)
    response.raise_for_status()

    downloads_dir = "ext_downloads"
    os.makedirs(downloads_dir, exist_ok=True)

    output_dir = os.path.join(downloads_dir, f"{publisher}.{name}_{version}")
    os.makedirs(output_dir, exist_ok=True)

    with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
        zip_file.extractall(output_dir)
    print(f"  VSIX downloaded and unzipped to {output_dir}")


def analyze_extension(extension):
    """Analyze an extension for suspicious characteristics."""
    total_checks = 6
    suspicious_checks = 0
    warnings = []

    # Check if domain is verified
    if not extension["publisher"]["isDomainVerified"]:
        suspicious_checks += 1
        warnings.append("Domain is not verified.")

    # Check if publisher is verified
    if "verified" not in extension["publisher"]["flags"]:
        suspicious_checks += 1
        warnings.append("Publisher not verified")

    # Check if publisher was recently created
    published_date = datetime.fromisoformat(extension["publishedDate"].replace("Z", "+00:00"))
    if (datetime.now(timezone.utc) - published_date).days < 30:
        suspicious_checks += 1
        warnings.append("Extension is newly created (less than 30 days).")

    # Check for low downloads
    downloads = next((stat["value"] for stat in extension["statistics"] if stat["statisticName"] == "install"), 0)
    if downloads < 100:
        suspicious_checks += 1
        warnings.append("Low download count (less than 100).")

    # Check for low reviews
    reviews = next((stat["value"] for stat in extension["statistics"] if stat["statisticName"] == "ratingcount"), 0)
    if reviews < 5:
        suspicious_checks += 1
        warnings.append("Few reviews (less than 5).")

    # Check for broken or private repository
    repo_url = next(
        (prop["value"] for prop in extension["versions"][0]["properties"]
         if prop["key"] == "Microsoft.VisualStudio.Services.Links.Source"),
        None
    )
    if repo_url:
        try:
            response = requests.head(repo_url)
            if response.status_code == 404:
                suspicious_checks += 1
                warnings.append("Repository link is broken (404).")
        except requests.RequestException:
            suspicious_checks += 1
            warnings.append("Repository link could not be verified.")
    else:
        suspicious_checks += 1
        warnings.append("No repository link provided.")

    return suspicious_checks, total_checks, warnings


def display_extension_details(extension, analyze=False, info=False):
    """Print all the information about an extension in a human-readable format."""
    full_name = f"{extension['publisher']['publisherName']}.{extension['extensionName']}"
    print("")
    print(f"[{full_name}]")
    print(f"  Display Name: {extension['displayName']}")
    print(f"  Publisher: {extension['publisher']['displayName']} ({extension['publisher']['publisherName']})")
    print(f"  Domain: {extension['publisher']['domain'] or 'N/A'} (Verified: {extension['publisher']['isDomainVerified']})")
    print(f"  Published Date: {format_date(extension.get('publishedDate'))}")
    print(f"  Last Updated: {format_date(extension.get('lastUpdated'))}")
    print(f"  Release Date: {format_date(extension.get('releaseDate'))}")
    print(f"  Description: {extension.get('shortDescription')}")
    print(f"  Link: https://marketplace.visualstudio.com/items?itemName={full_name}")

    if info:
        print("\n  Additional Information:")
        print(f"    PublisherId: {extension['publisher']['publisherId']}")
        print(f"    Publisher Flags: {extension['publisher']['flags']}")
        print(f"    ExtensionId: {extension['extensionId']}")
        print(f"    Extension Flags: {extension['flags']}")
        print(f"    Short Description: {extension['shortDescription']}")

        # Print relevant properties
        for prop in extension["versions"][0]["properties"]:
            if prop['key'] in [
                "Microsoft.VisualStudio.Services.Links.Getstarted",
                "Microsoft.VisualStudio.Services.Links.Support",
                "Microsoft.VisualStudio.Services.Links.Learn",
                "Microsoft.VisualStudio.Services.Links.Source",
                "Microsoft.VisualStudio.Services.Links.GitHub"
            ]:
                print(f"    {prop['key'].split('.')[-1]}: {prop['value']}")
        # Print relevant files
        for file in extension["versions"][0]["files"]:
            if file['assetType'] in [
                "Microsoft.VisualStudio.Services.Content.Changelog",
                "Microsoft.VisualStudio.Services.Content.Details"
            ]:
                print(f"    {file['assetType'].split('.')[-1]}: {file['source']}")
        print(f"\n    More statistics:")
        for stat in extension["statistics"]:
            if stat['statisticName'] in [
                "trendingdaily", "trendingmonthly", "trendingweekly",
                "updateCount", "weightedRating"
            ]:
                print(f"      {stat['statisticName']}: {stat['value']}")

    if analyze:
        suspicious_checks, total_checks, warnings = analyze_extension(extension)
        print(f"\n  Suspiciousness: {suspicious_checks}/{total_checks}")
        for warning in warnings:
            print(f"    Warning: {warning}")


def process_extensions(extensions, analyze=False, info=False, do_download=False):
    """
    Unified function to display, analyze, and/or download a list of extensions.
    """
    for ext in extensions:
        display_extension_details(ext, analyze=analyze, info=info)
        if do_download:
            download_vsix(ext)


def monitor_loop(keywords, tags, date_type, range_days, analyze, info, do_download, interval, use_discord=False):
    """
    Runs a daemon-style loop, every `interval` minutes:
      1. Fetches extensions per user’s params
      2. Checks previously fetched JSON file
      3. Prints which ones were previously analyzed
      4. Notifies Discord for changes (only if --discord is set)
      5. Waits for next iteration
    """
    while True:
        print("\n[Monitor] Fetching extensions in monitor mode...")
        current_extensions = fetch_extensions(keywords=keywords, tags=tags)
        current_extensions = filter_extensions_by_date(current_extensions, range_days, date_type)
        current_extensions = unique_extensions(current_extensions)

        previously_fetched = load_previously_fetched()  # dict

        current_ids = set()
        for ext in current_extensions:
            key = f"{ext['publisher']['publisherName']}.{ext['extensionName']}"
            current_ids.add(key)

        new_extensions = []
        for ext in current_extensions:
            key = f"{ext['publisher']['publisherName']}.{ext['extensionName']}"
            if key in previously_fetched:
                print(f"Previously analyzed: {key}")
            else:
                new_extensions.append(ext)

        if new_extensions:
            msg_lines = []
            for ext in new_extensions:
                key = f"{ext['publisher']['publisherName']}.{ext['extensionName']}"
                previously_fetched[key] = {
                    "fetchedAt": datetime.now(timezone.utc).isoformat(),
                    "version": ext["versions"][0]["version"],
                }
                msg_lines.append(f"New extension found: {key}")

            if msg_lines:
                final_msg = "\n".join(msg_lines)
                if use_discord:
                    print(f"\n[Monitor] Sending Discord alert:\n{final_msg}")
                    send_to_discord(final_msg)

            process_extensions(new_extensions, analyze=analyze, info=info, do_download=do_download)

        save_previously_fetched(previously_fetched)
        print(f"[Monitor] Sleeping for {interval} minute(s)...")
        time.sleep(interval * 60)


def main():
    parser = argparse.ArgumentParser(description="Fetch and display VSCode extensions from the Marketplace.")
    parser.add_argument("--keywords", type=str, help="Comma-separated keywords to search for extensions.")
    parser.add_argument("--tags", type=str, help="Semicolon-separated tags to filter for extensions, e.g. 'tag1;tag2'")
    parser.add_argument("--date-type", type=str, default="publishedDate", help="releaseDate, publishedDate or lastUpdated")
    parser.add_argument("--range-days", type=int, default=7, help="Number of days to filter extensions by date.")

    parser.add_argument("--download", action="store_true", help="Download and unzip VSIX files for matched extensions.")
    parser.add_argument("--download-only", type=str, help="Download a specific VSIX file by publisher.extensionname.")
    parser.add_argument("--analyze", action="store_true", help="Analyze extensions for suspicious characteristics.")
    parser.add_argument("--info", action="store_true", help="Display additional informational fields for extensions.")
    parser.add_argument("--info-only", type=str, help="Fetch and display full information for a specific publisher.extension.")

    # Monitor args
    parser.add_argument("--monitor", action="store_true", help="Run in daemon mode, checking updates every X minutes.")
    parser.add_argument("--every", type=int, default=5, help="Interval in minutes for the monitor (default: 5).")

    # Discord
    parser.add_argument("--discord", action="store_true", help="Send monitor messages to Discord (default off).")
    parser.add_argument("--discord-hook", type=str, help="Set a custom Discord webhook. Otherwise uses DISCORD_WEBHOOK from environment variable or code default.")

    args = parser.parse_args()

    # Handle Discord overrides
    if args.discord:
        global DISCORD_WEBHOOK
        DISCORD_WEBHOOK_ENV = os.environ.get("DISCORD_WEBHOOK")
        if args.discord_hook:
            DISCORD_WEBHOOK = args.discord_hook
        elif DISCORD_WEBHOOK_ENV:
            DISCORD_WEBHOOK = DISCORD_WEBHOOK_ENV
        else:
            print("\n[Monitor] Discord webhook missing. Use --discord-hook or env DISCORD_WEBHOOK")
            args.discord = False

    # Normal (non-monitor) flow
    keywords_list = []
    if args.keywords:
        keywords_list = [kw.strip() for kw in args.keywords.split(",") if kw.strip()]

    # Parse tags if provided
    tags_list = []
    if args.tags:
        tags_list = [t.strip() for t in args.tags.split(";") if t.strip()]

    # If user didn't pass keywords or tags, do nothing
    if not keywords_list and not tags_list:
        print("No keywords or tags provided. Nothing to fetch.")
        return

    # 1) Handle --info-only
    if args.info_only:
        if any([args.keywords, args.download, args.download_only, args.info, args.range_days != 7, args.monitor]):
            print("Error: --info-only cannot be used with other options.")
            return
        exts = fetch_extension_by_name(args.info_only)
        if exts:
            display_extension_details(exts[0], analyze=args.analyze, info=True)
        return

    # 2) Handle --download-only
    if args.download_only:
        if any([args.keywords, args.range_days != 7, args.analyze, args.download, args.monitor]):
            print("Error: --download-only cannot be used with other options.")
            return
        exts = fetch_extension_by_name(args.download_only)
        if exts:
            download_vsix(exts[0])
        return

    # 3) Monitor mode
    if args.monitor:
        if not args.keywords and not args.tags:
            print("Error: --monitor requires --keywords and/or --tags")
            return
        monitor_loop(
            keywords=keywords_list,
            tags=tags_list,
            date_type=args.date_type,
            range_days=args.range_days,
            analyze=args.analyze,
            info=args.info,
            do_download=args.download,
            interval=args.every,
            use_discord=args.discord
        )
        return

    fetched_exts = fetch_extensions(keywords=keywords_list, tags=tags_list)
    fetched_exts = filter_extensions_by_date(fetched_exts, args.range_days, args.date_type)
    fetched_exts = unique_extensions(fetched_exts)

    process_extensions(
        fetched_exts,
        analyze=args.analyze,
        info=args.info,
        do_download=args.download
    )


if __name__ == "__main__":
    main()
