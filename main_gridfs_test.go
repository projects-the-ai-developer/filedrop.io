// main_gridfs_test.go
package main

import (
	"bytes"
	"context"
	"compress/gzip"
	"encoding/hex"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/gridfs"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// setupTestDB initializes a test MongoDB connection and GridFS bucket.
func setupTestDB(t *testing.T) (*mongo.Client, *mongo.Collection, *sessions.CookieStore) {
	// Load environment variables for testing
	os.Setenv("MONGODB_URI", "mongodb://localhost:27017") // Use a local MongoDB for testing
	os.Setenv("DB_NAME", "filedrop_test_db")
	os.Setenv("COLLECTION_NAME", "filedrop_test_files")
	os.Setenv("APP_USER", "testuser")
	os.Setenv("APP_PASS", "testpass")
	os.Setenv("ENCRYPTION_KEY", "6368616e676520746869732070617373776f726420746f206120736563726574") // 32-byte key
	os.Setenv("SESSION_KEY", "a-very-secret-key-for-testing-sessions-12345") // 32-byte key

	mongoURI = os.Getenv("MONGODB_URI")
	dbName = os.Getenv("DB_NAME")
	collName = os.Getenv("COLLECTION_NAME")
	user = os.Getenv("APP_USER")
	pass = os.Getenv("APP_PASS")
	encryptionKeyHex := os.Getenv("ENCRYPTION_KEY")
	sessionKey = os.Getenv("SESSION_KEY")

	if encryptionKeyHex == "" {
		t.Fatal("ENCRYPTION_KEY environment variable not set for tests.")
	}
	if sessionKey == "" {
		t.Fatal("SESSION_KEY environment variable not set for tests.")
	}

	key, err := hex.DecodeString(encryptionKeyHex)
	if err != nil {
		t.Fatalf("Could not decode encryption key: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("Encryption key must be 32 bytes (64 hex characters), but got %d bytes", len(key))
	}
	encryptionKey = key

	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // For testing, usually false
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		t.Fatalf("Could not connect to MongoDB: %v", err)
	}
	if err = client.Ping(ctx, nil); err != nil {
		t.Fatalf("Could not ping MongoDB: %v", err)
	}

	// Clean up previous test data
	testDB := client.Database(dbName)
	if err := testDB.Drop(ctx); err != nil {
		t.Fatalf("Failed to drop test database: %v", err)
	}

	fileCollection = testDB.Collection(collName)
	gridFSBucket, err = gridfs.NewBucket(
		testDB,
		options.Bucket().SetName("fs"),
	)
	if err != nil {
		t.Fatalf("Could not create GridFS bucket: %v", err)
	}

	return client, fileCollection, store
}

// teardownTestDB closes the MongoDB connection.
func teardownTestDB(t *testing.T, client *mongo.Client) {
	if err := client.Disconnect(ctx); err != nil {
		t.Fatalf("Failed to disconnect from MongoDB: %v", err)
	}
}

// getAuthenticatedCookie simulates a login and returns the authentication cookie.
func getAuthenticatedCookie(t *testing.T) *http.Cookie {
	req, _ := http.NewRequest("POST", "/login", strings.NewReader("username="+user+"&password="+pass))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	loginHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("Login failed, status code: %d", rr.Code)
	}

	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "filedrop-session" {
			return cookie
		}
	}
	t.Fatal("Authentication cookie not found")
	return nil
}

func TestFileUploadAndDownload(t *testing.T) {
	client, _, _ := setupTestDB(t)
	defer teardownTestDB(t, client)

	// Simulate login to get an authenticated session
	authCookie := getAuthenticatedCookie(t)

	// --- Test 1: Upload a file ---
	testFilename := "test_document.txt"
	testContent := "This is a test file content for GridFS upload."
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", testFilename)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.WriteString(part, testContent)
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(authCookie)
	rr := httptest.NewRecorder()

	uploadHandler(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Upload handler returned wrong status code: got %v want %v. Body: %s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}

	// Verify file metadata in MongoDB
	var fileDoc FileDocument
	err = fileCollection.FindOne(ctx, bson.M{"filename": testFilename}).Decode(&fileDoc)
	if err != nil {
		t.Fatalf("Could not find uploaded file metadata in MongoDB: %v", err)
	}
	if fileDoc.FileID == nil {
		t.Error("FileID not set in FileDocument")
	}
	if fileDoc.Filename != testFilename {
		t.Errorf("Expected filename %s, got %s", testFilename, fileDoc.Filename)
	}

	// Verify file content in GridFS
	downloadStream, err := gridFSBucket.OpenDownloadStream(ctx, fileDoc.FileID)
	if err != nil {
		t.Fatalf("Could not open GridFS download stream for uploaded file: %v", err)
	}
	defer downloadStream.Close()
	encryptedContent, err := io.ReadAll(downloadStream)
	if err != nil {
		t.Fatalf("Could not read content from GridFS: %v", err)
	}
	// Decrypt and decompress to verify
	decryptedData, err := decrypt(encryptedContent, encryptionKey)
	if err != nil {
		t.Fatalf("Could not decrypt content from GridFS: %v", err)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(decryptedData))
	if err != nil {
		t.Fatalf("Could not create decompressor for GridFS content: %v", err)
	}
	defer gzipReader.Close()
	finalContent, err := io.ReadAll(gzipReader)
	if err != nil {
		t.Fatalf("Could not decompress content from GridFS: %v", err)
	}
	if string(finalContent) != testContent {
		t.Errorf("GridFS content mismatch: expected %s, got %s", testContent, string(finalContent))
	}

	// --- Test 2: Download the uploaded file ---
	req = httptest.NewRequest("GET", "/files/"+testFilename, nil)
	req.AddCookie(authCookie)
	rr = httptest.NewRecorder()

	downloadHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Download handler returned wrong status code: got %v want %v. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	downloadedContent := rr.Body.String()
	if downloadedContent != testContent {
		t.Errorf("Downloaded content mismatch: expected %s, got %s", testContent, downloadedContent)
	}

	// --- Test 3: Delete the uploaded file ---
	req = httptest.NewRequest("POST", "/delete/"+testFilename, nil)
	req.AddCookie(authCookie)
	rr = httptest.NewRecorder()

	deleteHandler(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("Delete handler returned wrong status code: got %v want %v. Body: %s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}

	// Verify file metadata is deleted from MongoDB
	err = fileCollection.FindOne(ctx, bson.M{"filename": testFilename}).Decode(&fileDoc)
	if err != mongo.ErrNoDocuments {
		t.Errorf("File metadata not deleted from MongoDB, or unexpected error: %v", err)
	}

	// Verify file content is deleted from GridFS (attempt to open download stream should fail)
	_, err = gridFSBucket.OpenDownloadStream(ctx, fileDoc.FileID)
	if err == nil {
		t.Error("File content not deleted from GridFS")
	} else if !strings.Contains(err.Error(), "file not found") && !strings.Contains(err.Error(), "no documents in result") {
		t.Errorf("Unexpected error when checking GridFS deletion: %v", err)
	}
}
