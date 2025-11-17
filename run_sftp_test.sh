#!/bin/bash

# This script is designed to help debug the SFTP server.
# It has been updated to be more verbose and easier to use.

echo "--- SFTP Debug Script (Verbose) ---"

# Step 1: Stop any old processes
echo
echo "--- [1/5] Stopping any process on port 2222..."
PID=$(lsof -t -i:2222)
if [ -n "$PID" ]; then
    echo "Found process with PID $PID on port 2222. Stopping it now."
    kill -9 $PID
else
    echo "No process found on port 2222. Good to go."
fi

# Step 2: Set environment variables
echo
echo "--- [2/5] Setting environment variables..."
export APP_USER="admin"
export APP_PASS="password"
export MONGODB_URI="mongodb://localhost:27017"
export DB_NAME="filedrop"
export COLLECTION_NAME="files"
export ENCRYPTION_KEY="1234567890123456789012345678901234567890123456789012345678901234"
export SESSION_KEY="a_very_secret_session_key_that_is_32_or_64_bytes_long"
echo "Environment variables set."

# Step 3: Run the application in the background
echo
echo "--- [3/5] Starting the application in the background..."
# The application logs will be printed to the console after the script is done.
go run . &
APP_PID=$!
echo "Application started with PID $APP_PID."

# Step 4: Wait for the server to start
echo
echo "--- [4/5] Waiting for 5 seconds for the server to initialize..."
sleep 5

# Step 5: Connect with SFTP and run 'ls'
echo
echo "--- [5/5] Attempting to connect with SFTP and list files..."
sftp -o PreferredAuthentications=password -o StrictHostKeyChecking=no -P 2222 admin@localhost <<EOF
ls
EOF

# Stop the application
echo
echo "---"
echo "Stopping the application (PID $APP_PID)..."
kill $APP_PID

echo
echo "---"
echo "Please provide all the output from this script, starting from the '--- SFTP Debug Script (Verbose) ---' line."
echo "The application logs will be printed above."
echo "---"