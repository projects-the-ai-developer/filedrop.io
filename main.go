// main.go - Enhanced with Sexy Login
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var tpl *template.Template
var fileCollection *mongo.Collection
var store *sessions.CookieStore
var ctx = context.TODO()
var encryptionKey []byte
var mongoURI, dbName, collName, user, pass, encryptionKeyHex, sessionKey string

type FileDocument struct {
	Filename          string    `bson:"filename"`
	ContentType       string    `bson:"contentType"`
	UploadDate        time.Time `bson:"uploadDate"`
	Data              string    `bson:"data"`
	Hash              string    `bson:"hash,omitempty"`
	Compression       string    `bson:"compression,omitempty"`
	Encryption        string    `bson:"encryption,omitempty"`
	ShareToken        string    `bson:"shareToken,omitempty"`
	SharePassword     string    `bson:"sharePassword,omitempty"`
	ShareExpiry       time.Time `bson:"shareExpiry,omitempty"`
	ShareDownloads    int       `bson:"shareDownloads,omitempty"`
	ShareMaxDownloads int       `bson:"shareMaxDownloads,omitempty"`
}

type ShareSettings struct {
	Password      string `json:"password"`
	ExpiryDays    int    `json:"expiry_days"`
	MaxDownloads  int    `json:"max_downloads"`
}

func generateToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
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
			http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sessionAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "filedrop-session")
		auth, ok := session.Values["authenticated"].(bool)
		if !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		lastActivity, ok := session.Values["last_activity"].(int64)
		if !ok || time.Now().Unix()-lastActivity > 600 { // 10 minutes
			session.Values["authenticated"] = false
			session.Save(r, w)
			http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
			return
		}

		session.Values["last_activity"] = time.Now().Unix()
		session.Save(r, w)
		next.ServeHTTP(w, r)
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "filedrop-session")

	if r.Method == "POST" {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == user && password == pass {
			session.Values["authenticated"] = true
			session.Values["last_activity"] = time.Now().Unix()
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		tpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid username or password"})
		return
	}

	tpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": r.URL.Query().Get("error")})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "filedrop-session")
	session.Values["authenticated"] = false
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	var results []FileDocument
	opts := options.Find().SetProjection(bson.M{"filename": 1, "uploadDate": 1, "shareToken": 1, "_id": 0}).SetSort(bson.D{{"uploadDate", -1}})
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
	serveFile(w, &result)
}

func serveFile(w http.ResponseWriter, result *FileDocument) {
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
		if bytes.Compare([]byte(hashString), []byte(result.Hash)) != 0 {
			log.Printf("Integrity check failed for file: %s", result.Filename)
			http.Error(w, "File is corrupt", http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+result.Filename+"\"")
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

func unshareHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	filename := strings.TrimPrefix(r.URL.Path, "/unshare/")
	update := bson.M{
		"$unset": bson.M{
			"shareToken":        "",
			"sharePassword":     "",
			"shareExpiry":       "",
			"shareMaxDownloads": "",
			"shareDownloads":    "",
		},
	}
	_, err := fileCollection.UpdateOne(ctx, bson.M{"filename": filename}, update)
	if err != nil {
		http.Error(w, "Could not unshare file", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func shareHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := strings.TrimPrefix(r.URL.Path, "/share/")
	var settings ShareSettings
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := generateToken()
	if err != nil {
		http.Error(w, "Could not generate share token", http.StatusInternalServerError)
		return
	}

	var passwordHash string
	if settings.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(settings.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Could not hash password", http.StatusInternalServerError)
			return
		}
		passwordHash = string(hash)
	}

	var expiry time.Time
	if settings.ExpiryDays > 0 {
		expiry = time.Now().AddDate(0, 0, settings.ExpiryDays)
	}

	update := bson.M{
		"$set": bson.M{
			"shareToken":        token,
			"sharePassword":     passwordHash,
			"shareExpiry":       expiry,
			"shareMaxDownloads": settings.MaxDownloads,
			"shareDownloads":    0,
		},
	}

	res, err := fileCollection.UpdateOne(ctx, bson.M{"filename": filename}, update)
	if err != nil {
		http.Error(w, "Could not update file share settings", http.StatusInternalServerError)
		return
	}
	if res.MatchedCount == 0 {
		http.NotFound(w, r)
		return
	}

	scheme := "http"
	if os.Getenv("RENDER") == "true" {
		scheme = "https"
	}
	shareLink := scheme + "://" + r.Host + "/s/" + token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"shareLink": shareLink})
}

func serveSharedFileHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/s/")
	var result FileDocument
	err := fileCollection.FindOne(ctx, bson.M{"shareToken": token}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Could not retrieve file", http.StatusInternalServerError)
		}
		return
	}

	if !result.ShareExpiry.IsZero() && time.Now().After(result.ShareExpiry) {
		http.Error(w, "Link has expired", http.StatusGone)
		return
	}

	if result.ShareMaxDownloads > 0 && result.ShareDownloads >= result.ShareMaxDownloads {
		http.Error(w, "Download limit reached", http.StatusGone)
		return
	}

	if result.SharePassword != "" {
		if r.Method == "POST" {
			password := r.FormValue("password")
			if err := bcrypt.CompareHashAndPassword([]byte(result.SharePassword), []byte(password)); err != nil {
				tpl.ExecuteTemplate(w, "password.html", map[string]interface{}{"Token": token, "Error": "Invalid password"})
				return
			}
		} else {
			tpl.ExecuteTemplate(w, "password.html", map[string]interface{}{"Token": token})
			return
		}
	}

	_, err = fileCollection.UpdateOne(ctx, bson.M{"shareToken": token}, bson.M{"$inc": bson.M{"shareDownloads": 1}})
	if err != nil {
		log.Printf("Failed to increment download count for token %s: %v", token, err)
	}

	serveFile(w, &result)
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
	sessionKey = os.Getenv("SESSION_KEY")

	if encryptionKeyHex == "" {
		log.Fatal("ENCRYPTION_KEY environment variable not set.")
	}
	if sessionKey == "" {
		log.Fatal("SESSION_KEY environment variable not set. Please provide a 32 or 64 byte key.")
	}

	key, err := hex.DecodeString(encryptionKeyHex)
	if err != nil {
		log.Fatalf("Could not decode encryption key: %v", err)
	}
	if len(key) != 32 {
		log.Fatalf("Encryption key must be 32 bytes (64 hex characters), but got %d bytes", len(key))
	}
	encryptionKey = key

	store = sessions.NewCookieStore([]byte(sessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   os.Getenv("RENDER") == "true",
	}

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
	
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/s/", serveSharedFileHandler)

	mux.HandleFunc("/", sessionAuth(indexHandler))
	mux.HandleFunc("/upload", sessionAuth(uploadHandler))
	mux.HandleFunc("/files/", sessionAuth(downloadHandler))
	mux.HandleFunc("/delete/", sessionAuth(deleteHandler))
	mux.HandleFunc("/share/", sessionAuth(shareHandler))
	mux.HandleFunc("/unshare/", sessionAuth(unshareHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, forceHTTPS(mux)))
}
