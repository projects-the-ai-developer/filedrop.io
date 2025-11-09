// main.go
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// --- CONFIGURATION ---
var tpl *template.Template
var fileCollection *mongo.Collection
var ctx = context.TODO()
var encryptionKey []byte

// These will be loaded from .env locally or from Railway's variables in production.
var mongoURI = os.Getenv("MONGODB_URI")
var dbName = os.Getenv("DB_NAME")
var collName = os.Getenv("COLLECTION_NAME")
var user = os.Getenv("APP_USER")
var pass = os.Getenv("APP_PASS")
var encryptionKeyHex = os.Getenv("ENCRYPTION_KEY")

type FileDocument struct {
	Filename    string    `bson:"filename"`
	ContentType string    `bson:"contentType"`
	UploadDate  time.Time `bson:"uploadDate"`
	Data        string    `bson:"data"`
	Hash        string    `bson:"hash,omitempty"`
	Compression string    `bson:"compression,omitempty"`
	Encryption  string    `bson:"encryption,omitempty"`
}

// --- END CONFIGURATION ---

// --- CRYPTO HELPERS ---
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// --- END CRYPTO HELPERS ---

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			userMatch := (subtle.ConstantTimeCompare([]byte(username), []byte(user)) == 1)
			passMatch := (subtle.ConstantTimeCompare([]byte(password), []byte(pass)) == 1)
			if userMatch && passMatch {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	var results []FileDocument
	opts := options.Find().SetProjection(bson.M{"filename": 1, "uploadDate": 1, "_id": 0}).SetSort(bson.D{{"uploadDate", -1}})
	cursor, err := fileCollection.Find(ctx, bson.M{}, opts)
	if err != nil {
		http.Error(w, "Could not fetch file list", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	if err = cursor.All(ctx, &results); err != nil {
		http.Error(w, "Could not parse file list", http.StatusInternalServerError)
		return
	}
	tpl.ExecuteTemplate(w, "index.html", results)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Could not get uploaded file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 1. Read original file
	originalBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Could not read file content", http.StatusInternalServerError)
		return
	}

	// 2. Hash original data
	hash := sha256.Sum256(originalBytes)
	hashString := hex.EncodeToString(hash[:])

	// 3. Compress data
	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzipWriter.Write(originalBytes); err != nil {
		http.Error(w, "Could not compress file", http.StatusInternalServerError)
		return
	}
	if err := gzipWriter.Close(); err != nil {
		http.Error(w, "Could not finalize compression", http.StatusInternalServerError)
		return
	}
	compressedBytes := compressedBuf.Bytes()

	// 4. Encrypt compressed data
	encryptedBytes, err := encrypt(compressedBytes, encryptionKey)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		http.Error(w, "Could not secure file", http.StatusInternalServerError)
		return
	}

	// 5. Base64 encode for storage
	encodedData := base64.StdEncoding.EncodeToString(encryptedBytes)
	filename := filepath.Base(header.Filename)

	// 6. Create new FileDocument with all metadata
	newFile := FileDocument{
		Filename:    filename,
		ContentType: http.DetectContentType(originalBytes),
		UploadDate:  time.Now(),
		Data:        encodedData,
		Hash:        "sha256:" + hashString,
		Compression: "gzip",
		Encryption:  "aes-gcm",
	}

	// 7. Insert into DB
	_, err = fileCollection.InsertOne(ctx, newFile)
	if err != nil {
		log.Printf("Error inserting document: %v", err)
		http.Error(w, "Could not save file to database", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(r.URL.Path)
	var result FileDocument

	err := fileCollection.FindOne(ctx, bson.M{"filename": filename}).Decode(&result)
	if err == mongo.ErrNoDocuments {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "Could not retrieve file", http.StatusInternalServerError)
		return
	}

	// 1. Base64 decode
	decodedData, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		http.Error(w, "Could not decode file data", http.StatusInternalServerError)
		return
	}

	// 2. Decrypt if needed
	var processedData []byte
	if result.Encryption == "aes-gcm" {
		decryptedData, err := decrypt(decodedData, encryptionKey)
		if err != nil {
			log.Printf("Decryption error: %v", err)
			http.Error(w, "Could not decrypt file", http.StatusInternalServerError)
			return
		}
		processedData = decryptedData
	} else {
		processedData = decodedData // Old, unencrypted file
	}

	// 3. Decompress if needed
	var finalData []byte
	if result.Compression == "gzip" {
		gzipReader, err := gzip.NewReader(bytes.NewReader(processedData))
		if err != nil {
			http.Error(w, "Could not create decompressor", http.StatusInternalServerError)
			return
		}
		defer gzipReader.Close()

		uncompressedData, err := io.ReadAll(gzipReader)
		if err != nil {
			http.Error(w, "Could not decompress file", http.StatusInternalServerError)
			return
		}
		finalData = uncompressedData
	} else {
		finalData = processedData // Old, uncompressed file
	}

	// 4. Verify hash if it exists
	if result.Hash != "" {
		hash := sha256.Sum256(finalData)
		hashString := "sha256:" + hex.EncodeToString(hash[:])
		if subtle.ConstantTimeCompare([]byte(hashString), []byte(result.Hash)) != 1 {
			log.Printf("Integrity check failed for file: %s", filename)
			http.Error(w, "File is corrupt", http.StatusInternalServerError)
			return
		}
	}

	// 5. Serve file
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Write(finalData)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := filepath.Base(r.URL.Path)
	_, err := fileCollection.DeleteOne(ctx, bson.M{"filename": filename})
	if err != nil {
		log.Printf("Error deleting document: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on host environment variables.")
	}

	// Re-fetch variables after godotenv.Load()
	mongoURI = os.Getenv("MONGODB_URI")
	dbName = os.Getenv("DB_NAME")
	collName = os.Getenv("COLLECTION_NAME")
	user = os.Getenv("APP_USER")
	pass = os.Getenv("APP_PASS")
	encryptionKeyHex = os.Getenv("ENCRYPTION_KEY")

	// Validate and decode encryption key
	if encryptionKeyHex == "" {
		log.Fatal("ENCRYPTION_KEY environment variable not set.")
	}
	key, err := hex.DecodeString(encryptionKeyHex)
	if err != nil {
		log.Fatalf("Could not decode encryption key: %v", err)
	}
	if len(key) != 32 {
		log.Fatalf("Encryption key must be 32 bytes (64 hex characters), but got %d bytes", len(key))
	}
	encryptionKey = key

	// --- Initialize MongoDB Connection ---
	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("Could not connect to MongoDB: %v", err)
	}
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatalf("Could not ping MongoDB: %v", err)
	}
	fileCollection = client.Database(dbName).Collection(collName)
	fmt.Println("Successfully connected to MongoDB Atlas!")

	tpl = template.Must(template.ParseGlob("templates/*.html"))

	staticFileServer := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", staticFileServer))

	http.HandleFunc("/files/", basicAuth(downloadHandler))
	http.HandleFunc("/", basicAuth(indexHandler))
	http.HandleFunc("/upload", basicAuth(uploadHandler))
	http.HandleFunc("/delete/", basicAuth(deleteHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server starting on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}