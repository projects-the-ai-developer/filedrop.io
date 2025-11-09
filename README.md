# Go-Shad FileDrop

Go-Shad FileDrop is a simple, secure, and self-hostable file sharing application inspired by the aesthetics of shadcn/ui. It provides a clean web interface for uploading, downloading, and managing files, with a strong focus on security through end-to-end encryption and data integrity checks.

The application is written in Go and uses MongoDB as its data store. It is designed to be lightweight and easy to deploy using Docker.

*Note: You can add a screenshot of the running application here.*

## Features

- **Secure by Design:**
    - **End-to-End Encryption:** Files are encrypted (AES-GCM) on the server before being stored and decrypted only when downloaded.
    - **Data Integrity:** A SHA256 hash of the original file is stored and verified upon download to ensure it hasn't been tampered with.
    - **Compression:** Files are compressed (Gzip) before encryption to save storage space.
    - **Secure Authentication:** Access is protected by Basic Authentication.
- **Simple & Clean UI:** A minimalist web interface for managing files, styled with a theme inspired by shadcn/ui.
- **Self-Hostable:** Easily deployable on any platform that supports Docker containers (e.g., Railway, your own server).
- **Lightweight:** Built with Go and a minimal Docker image for efficient performance.
- **CI/CD Ready:** Includes a `.woodpecker.yml` for automated builds and deployments.

## Architecture

The application follows a monolithic architecture, with all core logic contained within the `main.go` file.

1.  **Backend (`main.go`):**
    - **HTTP Server:** A standard Go `net/http` server.
    - **Routing:** Maps URLs to specific handler functions for different actions (index, upload, download, delete).
    - **Authentication:** A `basicAuth` middleware function protects all routes.
    - **File Processing Pipeline:**
        - **Upload:** `HTTP Request` -> `Read File` -> `SHA256 Hash` -> `Gzip Compress` -> `AES-GCM Encrypt` -> `Base64 Encode` -> `Store in MongoDB`.
        - **Download:** `HTTP Request` -> `Fetch from MongoDB` -> `Base64 Decode` -> `AES-GCM Decrypt` -> `Gzip Decompress` -> `Verify SHA256 Hash` -> `Serve File`.
    - **Database:** Uses the official MongoDB driver for Go to interact with the database.

2.  **Frontend (`templates/index.html` & `static/shadcn-style.css`):**
    - A single HTML file rendered using Go's `html/template` engine.
    - A CSS file provides the styling, mimicking the look and feel of shadcn/ui.

3.  **Containerization (`Dockerfile`):**
    - A multi-stage `Dockerfile` is used to create a minimal and secure production image.
    - **Stage 1 (Builder):** Compiles the Go application into a static binary.
    - **Stage 2 (Final):** Copies the binary and necessary static assets into a `scratch` image, resulting in a very small final image size.

4.  **CI/CD (`.woodpecker.yml`):**
    - Defines a pipeline for continuous integration and deployment.
    - On a push to the `main` branch, it automatically:
        1.  Builds the Docker image.
        2.  Pushes the image to a container registry (configured for Codeberg by default).
        3.  Triggers a deployment on Railway.

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/get-started)
- A MongoDB database (you can get a free one from [MongoDB Atlas](https://www.mongodb.com/cloud/atlas))
- A 32-byte (64 hex characters) encryption key. You can generate one with: `openssl rand -hex 32`

### Local Development

1.  **Clone the repository:**
    ```bash
    git clone https://codeberg.org/theprivatehomelabber/filedrop.theprivatehomelabber.in.git
    cd go-shad-filedrop
    ```

2.  **Create a `.env` file:**
    Create a file named `.env` in the root of the project and add the following environment variables:
    ```env
    # MongoDB connection string
    MONGODB_URI="mongodb+srv://<user>:<password>@<cluster-url>/<db-name>?retryWrites=true&w=majority"
    DB_NAME="filedrop"
    COLLECTION_NAME="files"

    # Basic Auth credentials
    APP_USER="admin"
    APP_PASS="your-secure-password"

    # 32-byte (64 hex characters) encryption key
    ENCRYPTION_KEY="your-64-character-hex-key"

    # Port to run the application on
    PORT="8080"
    ```

3.  **Run the application:**
    ```bash
    go run main.go
    ```
    The application will be available at `http://localhost:8080`.

### Deployment with Docker

1.  **Build the Docker image:**
    ```bash
    docker build -t go-shad-filedrop .
    ```

2.  **Run the Docker container:**
    Make sure to pass your environment variables to the container.
    ```bash
    docker run -p 8080:8080 \
      -e MONGODB_URI="your-mongo-uri" \
      -e DB_NAME="filedrop" \
      -e COLLECTION_NAME="files" \
      -e APP_USER="admin" \
      -e APP_PASS="your-secure-password" \
      -e ENCRYPTION_KEY="your-64-character-hex-key" \
      -e PORT="8080" \
      go-shad-filedrop
    ```

## Configuration

The application is configured entirely through environment variables.

| Variable          | Description                                                              | Required |
| ----------------- | ------------------------------------------------------------------------ | -------- |
| `MONGODB_URI`     | The full connection string for your MongoDB database.                    | Yes      |
| `DB_NAME`         | The name of the database to use.                                         | Yes      |
| `COLLECTION_NAME` | The name of the collection to store file metadata in.                    | Yes      |
| `APP_USER`        | The username for Basic Authentication.                                   | Yes      |
| `APP_PASS`        | The password for Basic Authentication.                                   | Yes      |
| `ENCRYPTION_KEY`  | A 32-byte (64 hex characters) key for AES-256 encryption.                | Yes      |
| `PORT`            | The port on which the application will listen. Defaults to `8080`.       | No       |

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
