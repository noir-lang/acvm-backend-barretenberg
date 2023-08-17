#!/bin/bash

USERNAME="AztecProtocol"
REPO="barretenberg"
TAG="barretenberg-v0.3.6" # TODO: We can make this automatically fetch the latest version
DEST_FOLDER="binaries"

# Create the destination folder if it doesn't exist
mkdir -p $DEST_FOLDER

API_URL="https://api.github.com/repos/$USERNAME/$REPO/releases/tags/$TAG"

# Get the download URLs for the assets from the specified tag release.
download_urls=$(curl -s $API_URL | jq -r '.assets[] | .browser_download_url')

# Download each asset, extract it to a new folder based on its name inside the binaries directory.
IFS=$'\n' # Set Internal Field Separator to newline for loop iteration
for url in $download_urls; do
    temp_file="$(mktemp)"
    curl -Lo "$temp_file" "$url"
    
    # Get the base name of the file without extension
    file_basename=$(basename "$url" .tar.gz)
    
    # Create a directory for the extracted contents
    extract_path="$DEST_FOLDER/$file_basename"
    mkdir -p "$extract_path"
    
    # Extract the .tar.gz contents into the new directory
    tar -xf "$temp_file" -C "$extract_path"
    rm "$temp_file"
done
