import os
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


def format_date(date_str):
    """Format ISO date to DD/MM/YYYY at HH:MM:SS."""
    dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    return dt.strftime("%d/%m/%Y at %H:%M:%S")


def fetch_extensions(keywords, page_size=100):
    """Fetch extensions from the Marketplace for the given keywords."""
    all_extensions = []
    for keyword in keywords:
        print(f"Fetching extensions for keyword: {keyword}")
        body = {
            "filters": [
                {
                    "criteria": [
                        {"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                        {"filterType": 10, "value": keyword}
                    ],
                    "pageNumber": 1,
                    "pageSize": page_size,
                    "sortBy": 4,
                    "sortOrder": 0
                }
            ],
            "assetTypes": [],
            "flags": 914
        }

        response = requests.post(API_URL, headers=HEADERS, json=body)
        response.raise_for_status()
        extensions = response.json()["results"][0]["extensions"]
        all_extensions.extend(extensions)

    return all_extensions


def filter_extensions_by_date(extensions, days):
    """Filter extensions that were published, updated, or released within the last `days` days."""
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    filtered_extensions = []

    for ext in extensions:
        dates = {
            "publishedDate": datetime.fromisoformat(ext.get("publishedDate", "1970-01-01T00:00:00.000+00:00").replace("Z", "+00:00")),
            "lastUpdated": datetime.fromisoformat(ext.get("lastUpdated", "1970-01-01T00:00:00.000+00:00").replace("Z", "+00:00")),
            "releaseDate": datetime.fromisoformat(ext.get("releaseDate", "1970-01-01T00:00:00.000+00:00").replace("Z", "+00:00")),
        }

        if any(date >= cutoff_date for date in dates.values()):
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
    vsix_url = next(file["source"] for file in extension["versions"][0]["files"] if file["assetType"] == "Microsoft.VisualStudio.Services.VSIXPackage")

    response = requests.get(vsix_url)
    response.raise_for_status()

    # Create the ext_downloads directory if it doesn't exist
    downloads_dir = "ext_downloads"
    os.makedirs(downloads_dir, exist_ok=True)

    output_dir = os.path.join(downloads_dir, f"{publisher}.{name}_{version}")
    os.makedirs(output_dir, exist_ok=True)

    with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
        zip_file.extractall(output_dir)
    print(f"  VSIX downloaded and unzipped to {output_dir}")


def download_only(publisher_extension):
    """Download a specific VSIX file by publisher.extensionname."""
    publisher, extension_name = publisher_extension.split(".")
    print(f"Fetching {publisher_extension}...")
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

    response = requests.post(API_URL, headers=HEADERS, json=body)
    response.raise_for_status()
    extensions = response.json()["results"][0]["extensions"]

    if extensions:
        ext = extensions[0]
        if ext["publisher"]["publisherName"] == publisher:
            download_vsix(ext)
        else:
            print(f"Error: {publisher_extension} not found.")
    else:
        print(f"Error: {publisher_extension} not found.")


def analyze_extension(extension):
    """Analyze an extension for suspicious characteristics."""
    total_checks = 5
    suspicious_checks = 0
    warnings = []

    # Check if domain is verified
    if not extension["publisher"]["isDomainVerified"]:
        suspicious_checks += 1
        warnings.append("Domain is not verified.")

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
    repo_url = next((prop["value"] for prop in extension["versions"][0]["properties"] if prop["key"] == "Microsoft.VisualStudio.Services.Links.Source"), None)
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


def display_extension_details(extension, analyze=False):
    """Print all the information about an extension in a human-readable format."""
    full_name = f"[{extension['publisher']['publisherName']}.{extension['extensionName']}]"
    print(f"")
    print(full_name)
    print(f"  Display Name: {extension['displayName']}")
    print(f"  Publisher: {extension['publisher']['displayName']} ({extension['publisher']['publisherName']})")
    print(f"  Domain: {extension['publisher']['domain'] or 'N/A'} (Verified: {extension['publisher']['isDomainVerified']})")
    print(f"  Published Date: {format_date(extension.get('publishedDate'))}")
    print(f"  Last Updated: {format_date(extension.get('lastUpdated'))}")
    print(f"  Release Date: {format_date(extension.get('releaseDate'))}")
    print(f"  Description: {extension.get('shortDescription')}")

    if analyze:
        suspicious_checks, total_checks, warnings = analyze_extension(extension)
        print(f"  Suspiciousness: {suspicious_checks}/{total_checks}")
        for warning in warnings:
            print(f"    Warning: {warning}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Fetch and display VSCode extensions from the Marketplace.")
    parser.add_argument("--keywords", type=str, help="Comma-separated keywords to search for extensions.")
    parser.add_argument("--range-days", type=int, default=7, help="Number of days to filter extensions by date.")
    parser.add_argument("--download", action="store_true", help="Download and unzip VSIX files for all matched extensions.")
    parser.add_argument("--download-only", type=str, help="Download a specific VSIX file by publisher.extensionname.")
    parser.add_argument("--analyze", action="store_true", help="Analyze extensions for suspicious characteristics.")
    args = parser.parse_args()

    if args.download_only:
        if any([args.keywords, args.range_days != 7, args.analyze, args.download]):
            print("Error: --download-only cannot be used with other options.")
            return
        download_only(args.download_only)
        return

    # Convert keywords into a list
    keywords = [kw.strip() for kw in args.keywords.split(",")] if args.keywords else []

    # Fetch and process extensions
    extensions = fetch_extensions(keywords)
    extensions = filter_extensions_by_date(extensions, args.range_days)
    extensions = unique_extensions(extensions)

    # Display and optionally analyze/download extensions
    for ext in extensions:
        display_extension_details(ext, analyze=args.analyze)
        if args.download:
            download_vsix(ext)


if __name__ == "__main__":
    main()
