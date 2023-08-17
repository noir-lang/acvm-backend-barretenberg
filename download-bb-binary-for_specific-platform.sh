#!/bin/bash

# This script will download the zipped binaries for the specified tag release of the barretenberg GitHub repository.
# for a particular OS. If it is windows, then we use NPM. 
# 
# It will extract the binary from zip file and store it in `DEST_FOLDER` and then use the `NARGO_BINARIES_PATH` environment variable
# to save the location of the binary.
#
# This is used to call the binary from the Rust program.
#
# Observations:
# For now this script is setting the NARGO_BINARIES_PATH environment variable to the binary path. 
# This should be done by Nargo itself, but for now this is a workaround.

USERNAME="AztecProtocol"
REPO="barretenberg"
VERSION="0.3.6"
TAG="barretenberg-v${VERSION}"
DEST_FOLDER="$HOME/.nargo/backends/acvm-backend-barretenberg"
BINARY_NAME="backend_binary"

# Create the destination folder if it doesn't exist
mkdir -p $DEST_FOLDER

API_URL="https://api.github.com/repos/$USERNAME/$REPO/releases/tags/$TAG"

# Identify the system's OS
os_type="$(uname | tr '[:upper:]' '[:lower:]')"

# Map the output of uname to common naming conventions for operating systems in GitHub releases
case "$os_type" in
    darwin)
        binary_os="mac"
        ;;
    linux)
        binary_os="ubuntu"
        ;;
    msys*|mingw*|cygwin*|windows*)
        binary_os="windows"
        ;;
    *)
        echo "Unsupported operating system: $os_type"
        exit 1
        ;;
esac

# Only download binaries on non-Windows platforms
if [[ "$binary_os" != "windows" ]]; then
    # Get the download URLs for the assets from the specified tag release.
    download_urls=$(curl -s $API_URL | jq -r --arg os "$binary_os" '.assets[] | select(.browser_download_url | contains($os)) | .browser_download_url')

    # Set NARGO_BINARIES_PATH to the path of the binary
    DEST_PATH="$DEST_FOLDER/$BINARY_NAME"

    # Download each asset, extract it to a new folder based on its name inside the binaries directory.
    IFS=$'\n' # Set Internal Field Separator to newline for loop iteration
    for url in $download_urls; do
        temp_file="$(mktemp)"
        curl -Lo "$temp_file" "$url"
        
        # Temporary directory for the extracted contents
        temp_extract="$(mktemp -d)"
        
        # Extract the .tar.gz contents into the temporary directory
        tar -xf "$temp_file" -C "$temp_extract"
        
        # Find the binary, move it to the DEST_FOLDER and rename
        # Assuming the binary is an executable and not a directory
        find "$temp_extract" -type f -executable -exec mv {} "$DEST_PATH" \;

        # Clean up: Remove the temporary file and directory
        rm "$temp_file"
        rm -r "$temp_extract"
    done
else
    # TODO: this does not check if NPM/node are available.
    # TODO we also do not check if the npm package is already installed
    # TODO: this does not work because it cannot install npm packages due to it not forwarding to dest/node/main.js -- It keeps looking for dest/main.js
    #
    # TODO: THIS SHOULD LIKELY BE IN THE BUILD SCRIPT
    # TODO because we cannot run bash on native windows
    NPM_PACKAGE="@aztec/bb.js"
    npm install -g $NPM_PACKAGE@$VERSION
    
    BINARY_PATH=$(npm bin -g)/$NPM_PACKAGE
    if [[ ! -f "$BINARY_PATH" ]]; then
        echo "Error: Failed to find binary for npm package $BINARY_PATH"
        exit 1
    fi
    
    # Set NARGO_BINARIES_PATH to the npm package binary
    DEST_PATH="$BINARY_PATH"
fi

# Add the binary to the environment variable in ~/.bashrc (or appropriate shell config) if it isn't there already
if ! grep -q "export NARGO_BINARIES_PATH=$DEST_PATH" ~/.bashrc; then
    echo "export NARGO_BINARIES_PATH=$DEST_PATH" >> ~/.bashrc
fi

# Add the binary to the environment variable in ~/.zshrc if it isn't there already
if ! grep -q "export NARGO_BINARIES_PATH=$DEST_PATH" ~/.zshrc; then
    echo "export NARGO_BINARIES_PATH=$DEST_PATH" >> ~/.zshrc
fi

# Inform the user to source their shell configuration or start a new session to use the environment variable.
echo "Please run 'source ~/.bashrc' or 'source ~/.zshrc' or start a new shell session to access the NARGO_BINARIES_PATH environment variable."