# Dockerfile

# --- Stage 1: Build ---
# Use the official Go image to build our application.
# 'alpine' is a small Linux distribution.
FROM golang:1.22-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy all project files into the container
COPY . .

# Build the Go app, creating a static, single binary.
# CGO_ENABLED=0 is important for a truly static binary.
RUN CGO_ENABLED=0 go build -o /filedrop .

# --- Stage 2: Final Image ---
# Use 'scratch', an empty base image, for maximum security and minimal size.
FROM scratch

# Copy the compiled binary from the 'builder' stage
COPY --from=builder /filedrop /filedrop

# Copy our HTML templates and CSS files
COPY templates /templates
COPY static /static

# Create the uploads directory where files will be stored inside the container
RUN mkdir /uploads

# Expose port 8080 to the outside world
EXPOSE 8080

# Tell Docker what command to run when the container starts
ENTRYPOINT ["/filedrop"]