// main.go
package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/joho/godotenv" // Import for .env support
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// --- CONFIGURATION ---
var tpl *template.Template
var fileCollection *mongo.Collection
var ctx = context.TODO()

// These will be loaded from .env locally, or from Railway's variables in production.
var mongoURI = os.Getenv("MONGODB_URI")
var dbName = os.Getenv("DB_NAME")
var collName = os.Getenv("COLLECTION_NAME")
var user = os.Getenv("APP_USER")
var pass = os.Getenv("APP_PASS")

type FileDocument struct {
	Filename    string    `bson:"filename"`
	ContentType string    `bson:"contentType"`
	UploadDate  time.Time `bson:"uploadDate"`
	Data        string    `bson:"data"`
}

// --- END CONFIGURATION ---

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

	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Could not read file content", http.StatusInternalServerError)
		return
	}

	encodedData := base64.StdEncoding.EncodeToString(fileBytes)
	filename := filepath.Base(header.Filename)

	newFile := FileDocument{
		Filename:    filename,
		ContentType: http.DetectContentType(fileBytes),
		UploadDate:  time.Now(),
		Data:        encodedData,
	}

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

	decodedData, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		http.Error(w, "Could not decode file data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", result.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	w.Write(decodedData)
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
	// Load .env file for local development. In production, it does nothing.
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on host environment variables.")
	}

	// Re-fetch variables after godotenv.Load()
	mongoURI = os.Getenv("MONGODB_URI")
	dbName = os.Getenv("DB_NAME")
	collName = os.Getenv("COLLECTION_NAME")
	user = os.Getenv("APP_USER")
	pass = os.Getenv("APP_PASS")

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
