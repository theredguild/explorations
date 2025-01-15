#!/bin/bash

# Check if required tools are installed
if ! command -v jq &> /dev/null || ! command -v curl &> /dev/null || ! command -v unzip &> /dev/null; then
    echo "This tool requires 'jq', 'curl', and 'unzip' to be installed."
    exit 1
fi

# Help function
show_help() {
    echo "Usage: $0 <command> <args>"
    echo
    echo "Commands:"
    echo "  download <publisher.extension>    Download and unzip a VS Code extension."
    echo "  score <publisher.extension>       Analyze and score a VS Code extension for potential risks."
    exit 1
}

# Function to validate the API response
validate_response() {
    RESPONSE="$1"
    if [ -z "$RESPONSE" ] || [ "$(echo "$RESPONSE" | jq -r '.results[0].extensions | length')" -eq 0 ]; then
        echo "Error: Extension not found or no metadata available for analysis."
        exit 1
    fi
}

# Download function
download_extension() {
    EXTENSION_NAME="$1"

    # Query the marketplace for the extension
    RESPONSE=$(curl -s -X POST "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json;api-version=3.0-preview.1" \
        -d "{
              \"filters\": [
                  {
                      \"criteria\": [
                          {
                              \"filterType\": 7,
                              \"value\": \"$EXTENSION_NAME\"
                          }
                      ]
                  }
              ],
              \"flags\": 131
            }")

    # Validate response
    validate_response "$RESPONSE"

    # Extract the VSIX download URL
    VSIX_URL=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].versions[0].files[] | select(.assetType == "Microsoft.VisualStudio.Services.VSIXPackage") | .source')

    if [ -z "$VSIX_URL" ]; then
        echo "Error: Could not find a download URL for extension '$EXTENSION_NAME'."
        exit 1
    fi

    # Download the VSIX file
    VSIX_FILENAME="${EXTENSION_NAME}.vsix"
    echo "Downloading VSIX package for '$EXTENSION_NAME'..."
    curl -o "$VSIX_FILENAME" "$VSIX_URL"

    if [ $? -ne 0 ]; then
        echo "Error: Failed to download the VSIX package."
        exit 1
    fi

    # Unzip the VSIX file
    UNZIP_DIR="${EXTENSION_NAME}_unzipped"
    echo "Unzipping the VSIX package to '$UNZIP_DIR'..."
    mkdir -p "$UNZIP_DIR"
    unzip -q "$VSIX_FILENAME" -d "$UNZIP_DIR"

    if [ $? -eq 0 ]; then
        echo "Unzip completed. Files extracted to: $UNZIP_DIR"
    else
        echo "Error: Failed to unzip the VSIX package."
        exit 1
    fi
}

# Score/Audit function
score_extension() {
    EXTENSION_NAME="$1"

    # Query the marketplace for the extension
    RESPONSE=$(curl -s -X POST "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json;api-version=3.0-preview.1" \
        -d "{
              \"filters\": [
                  {
                      \"criteria\": [
                          {
                              \"filterType\": 7,
                              \"value\": \"$EXTENSION_NAME\"
                          }
                      ]
                  }
              ],
              \"flags\": 131
            }")

    # Validate response
    validate_response "$RESPONSE"

    # Extract metadata
    PUBLISHER=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].publisher.publisherName')
    DISPLAY_NAME=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].displayName')
    LAST_UPDATED=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].versions[0].lastUpdated')
    DOWNLOADS=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].statistics[] | select(.statisticName == "install") | .value')
    RATING=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].statistics[] | select(.statisticName == "averagerating") | .value')
    REVIEW_COUNT=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].statistics[] | select(.statisticName == "ratingcount") | .value')
    EXTENSION_VERSION=$(echo "$RESPONSE" | jq -r '.results[0].extensions[0].versions[0].version')

    # Additional validation
    if [ -z "$PUBLISHER" ] || [ -z "$DISPLAY_NAME" ]; then
        echo "Error: Missing critical metadata (e.g., publisher or display name)."
        exit 1
    fi

    # Analyze publisher metadata
    NUM_EXTENSIONS=$(echo "$RESPONSE" | jq -r '.results[0].extensions | length')

    # Scoring and warnings
    SCORE=100
    WARNINGS=""

    echo "Analyzing '$EXTENSION_NAME'..."
    echo "Publisher: $PUBLISHER"
    echo "Display Name: $DISPLAY_NAME"
    echo "Version: $EXTENSION_VERSION"
    echo "Last Updated: $LAST_UPDATED"
    echo "Downloads: $DOWNLOADS"
    echo "Rating: $RATING"
    echo "Review Count: $REVIEW_COUNT"
    echo "Other Extensions by Publisher: $NUM_EXTENSIONS"

    # Scoring criteria
    if [ -z "$LAST_UPDATED" ] || [[ "$LAST_UPDATED" < $(date -d '1 year ago' '+%Y-%m-%d') ]]; then
        WARNINGS+="Extension hasn't been updated in over a year.\n"
        SCORE=$((SCORE - 20))
    fi

    if [ "$DOWNLOADS" -lt 1000 ]; then
        WARNINGS+="Low number of downloads ($DOWNLOADS).\n"
        SCORE=$((SCORE - 20))
    fi

    if (( $(echo "$RATING < 3.5" | bc -l) )); then
        WARNINGS+="Low average rating ($RATING).\n"
        SCORE=$((SCORE - 20))
    fi

    if [ "$REVIEW_COUNT" -lt 10 ]; then
        WARNINGS+="Few reviews ($REVIEW_COUNT).\n"
        SCORE=$((SCORE - 10))
    fi

    if [ "$NUM_EXTENSIONS" -lt 2 ]; then
        WARNINGS+="Publisher has very few extensions ($NUM_EXTENSIONS).\n"
        SCORE=$((SCORE - 10))
    fi

    # Output score and warnings
    echo "Risk Score: $SCORE/100"
    if [ -n "$WARNINGS" ]; then
        echo -e "Warnings:\n$WARNINGS"
    else
        echo "No significant warnings found."
    fi
}

# Main logic
if [ "$#" -lt 2 ]; then
    show_help
fi

COMMAND="$1"
EXTENSION_NAME="$2"

case "$COMMAND" in
    download)
        download_extension "$EXTENSION_NAME"
        ;;
    score | audit)
        score_extension "$EXTENSION_NAME"
        ;;
    *)
        show_help
        ;;
esac
