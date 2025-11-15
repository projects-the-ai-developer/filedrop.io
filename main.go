// main.go - FINAL CORRECTED VERSION
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

var tpl *template.Template
var fileCollection *mongo.Collection
var ctx = context.TODO()
var encryptionKey []byte
var mongoURI, dbName, collName, user, pass, encryptionKeyHex string

type FileDocument struct {
	Filename    string    `bson:"filename"`
	ContentType string    `bson:"contentType"`
	UploadDate  time.Time `bson:"uploadDate"`
	Data        string    `bson:"data"`
	Hash        string    `bson:"hash,omitempty"`
	Compression string    `bson:"compression,omitempty"`
	Encryption  string    `bson:"encryption,omitempty"`
}

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

func forceHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isProd := os.Getenv("RENDER") == "true"
		if isProd && r.Header.Get("X-Forwarded-Proto") == "http" {
			targetURL := "https://" + r.Host + r.URL.RequestURI()
			// Use a TEMPORARY redirect to prevent aggressive browser caching
			http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			if subtle.ConstantTimeCompare([]byte(username), []byte(user)) == 1 && subtle.ConstantTimeCompare([]byte(password), []byte(pass)) == 1 {
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
	originalBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Could not read file content", http.StatusInternalServerError)
		return
	}
	hash := sha256.Sum256(originalBytes)
	hashString := hex.EncodeToString(hash[:])
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
	encryptedBytes, err := encrypt(compressedBuf.Bytes(), encryptionKey)
	if err != nil {
		log.Printf("Encryption error: %v", err)
		http.Error(w, "Could not secure file", http.StatusInternalServerError)
		return
	}
	newFile := FileDocument{
		Filename:    filepath.Base(header.Filename),
		ContentType: http.DetectContentType(originalBytes),
		UploadDate:  time.Now(),
		Data:        base64.StdEncoding.EncodeToString(encryptedBytes),
		Hash:        "sha256:" + hashString,
		Compression: "gzip",
		Encryption:  "aes-gcm",
	}
	if _, err := fileCollection.InsertOne(ctx, newFile); err != nil {
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
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Could not retrieve file", http.StatusInternalServerError)
		}
		return
	}
	decodedData, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		http.Error(w, "Could not decode file data", http.StatusInternalServerError)
		return
	}
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
		processedData = decodedData
	}
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
		finalData = processedData
	}
	if result.Hash != "" {
		hash := sha256.Sum256(finalData)
		hashString := "sha256:" + hex.EncodeToString(hash[:])
		if subtle.ConstantTimeCompare([]byte(hashString), []byte(result.Hash)) != 1 {
			log.Printf("Integrity check failed for file: %s", filename)
			http.Error(w, "File is corrupt", http.StatusInternalServerError)
			return
		}
	}
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
	if _, err := fileCollection.DeleteOne(ctx, bson.M{"filename": filename}); err != nil {
		log.Printf("Error deleting document: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on host environment variables.")
	}
	mongoURI = os.Getenv("MONGODB_URI")
	dbName = os.Getenv("DB_NAME")
	collName = os.Getenv("COLLECTION_NAME")
	user = os.Getenv("APP_USER")
	pass = os.Getenv("APP_PASS")
	encryptionKeyHex = os.Getenv("ENCRYPTION_KEY")
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
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("Could not connect to MongoDB: %v", err)
	}
	if err = client.Ping(ctx, nil); err != nil {
		log.Fatalf("Could not ping MongoDB: %v", err)
	}
	fileCollection = client.Database(dbName).Collection(collName)
	log.Println("Successfully connected to MongoDB Atlas!")
	tpl = template.Must(template.ParseGlob("templates/*.html"))
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/files/", basicAuth(downloadHandler))
	mux.HandleFunc("/", basicAuth(indexHandler))
	mux.HandleFunc("/upload", basicAuth(uploadHandler))
	mux.HandleFunc("/delete/", basicAuth(deleteHandler))
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, forceHTTPS(mux)))
}
