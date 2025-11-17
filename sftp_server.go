package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pkg/sftp"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/ssh"
)

// FileHandler implements the sftp.Handlers interface
type FileHandler struct {
}

// fileInfo implements the os.FileInfo interface
type fileInfo struct {
	name    string
	size    int64
	modTime time.Time
}

func (fi fileInfo) Name() string {
	return fi.name
}

func (fi fileInfo) Size() int64 {
	return fi.size
}

func (fi fileInfo) Mode() os.FileMode {
	return 0644
}

func (fi fileInfo) ModTime() time.Time {
	return fi.modTime
}

func (fi fileInfo) IsDir() bool {
	return false
}

func (fi fileInfo) Sys() interface{} {
	return nil
}

func (h *FileHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	log.Printf("SFTP: Fileread requested for %s", r.Filepath)
	filename := r.Filepath[1:] // Remove leading "/"

	var result FileDocument
	err := fileCollection.FindOne(ctx, bson.M{"filename": filename}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("SFTP: Fileread failed for %s: file not found", r.Filepath)
			return nil, os.ErrNotExist
		}
		log.Printf("SFTP: Fileread failed for %s: %v", r.Filepath, err)
		return nil, err
	}

	decodedData, err := base64.StdEncoding.DecodeString(result.Data)
	if err != nil {
		log.Printf("SFTP: Fileread failed for %s: could not decode data: %v", r.Filepath, err)
		return nil, err
	}

	var processedData []byte
	if result.Encryption == "aes-gcm" {
		decryptedData, err := decrypt(decodedData, encryptionKey)
		if err != nil {
			log.Printf("SFTP: Fileread failed for %s: could not decrypt data: %v", r.Filepath, err)
			return nil, err
		}
		processedData = decryptedData
	} else {
		processedData = decodedData
	}

	var finalData []byte
	if result.Compression == "gzip" {
		gzipReader, err := gzip.NewReader(bytes.NewReader(processedData))
		if err != nil {
			log.Printf("SFTP: Fileread failed for %s: could not create decompressor: %v", r.Filepath, err)
			return nil, err
		}
		defer gzipReader.Close()
		uncompressedData, err := io.ReadAll(gzipReader)
		if err != nil {
			log.Printf("SFTP: Fileread failed for %s: could not decompress data: %v", r.Filepath, err)
			return nil, err
		}
		finalData = uncompressedData
	} else {
		finalData = processedData
	}

	log.Printf("SFTP: Fileread successful for %s", r.Filepath)
	return bytes.NewReader(finalData), nil
}

func (h *FileHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	log.Printf("SFTP: Filewrite requested for %s", r.Filepath)
	filename := r.Filepath[1:] // Remove leading "/"

	return &fileWriter{
		filename: filename,
	}, nil
}

type fileWriter struct {
	filename string
	buf      bytes.Buffer
}

func (fw *fileWriter) Close() error {
	log.Printf("SFTP: fileWriter.Close called for %s", fw.filename)
	originalBytes := fw.buf.Bytes()
	hash := sha256.Sum256(originalBytes)
	hashString := hex.EncodeToString(hash[:])

	var compressedBuf bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressedBuf)
	if _, err := gzipWriter.Write(originalBytes); err != nil {
		log.Printf("SFTP: fileWriter.Close failed for %s: could not compress data: %v", fw.filename, err)
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		log.Printf("SFTP: fileWriter.Close failed for %s: could not finalize compression: %v", fw.filename, err)
		return err
	}

	encryptedBytes, err := encrypt(compressedBuf.Bytes(), encryptionKey)
	if err != nil {
		log.Printf("SFTP: fileWriter.Close failed for %s: could not encrypt data: %v", fw.filename, err)
		return err
	}

	update := bson.M{
		"$set": bson.M{
			"filename":    fw.filename,
			"contentType": http.DetectContentType(originalBytes),
			"uploadDate":  time.Now(),
			"data":        base64.StdEncoding.EncodeToString(encryptedBytes),
			"hash":        "sha256:" + hashString,
			"compression": "gzip",
			"encryption":  "aes-gcm",
		},
	}

	opts := options.Update().SetUpsert(true)
	_, err = fileCollection.UpdateOne(ctx, bson.M{"filename": fw.filename}, update, opts)
	if err != nil {
		log.Printf("SFTP: fileWriter.Close failed for %s: could not write to database: %v", fw.filename, err)
		return err
	}

	log.Printf("SFTP: fileWriter.Close successful for %s", fw.filename)
	return nil
}

func (fw *fileWriter) WriteAt(p []byte, off int64) (int, error) {
	log.Printf("SFTP: fileWriter.WriteAt called for %s, offset %d, length %d", fw.filename, off, len(p))
	// For simplicity, we're writing the whole file at once.
	// A more robust implementation would handle chunked writes.
	if off == 0 {
		fw.buf.Reset()
	}
	return fw.buf.Write(p)
}

func (h *FileHandler) Filecmd(r *sftp.Request) error {
	log.Printf("SFTP: Filecmd requested: %s %s (target: %s)", r.Method, r.Filepath, r.Target)
	switch r.Method {
	case "rm":
		filename := r.Filepath[1:] // Remove leading "/"
		_, err := fileCollection.DeleteOne(ctx, bson.M{"filename": filename})
		if err != nil {
			log.Printf("SFTP: Filecmd 'rm' failed for %s: %v", r.Filepath, err)
			return err
		}
		log.Printf("SFTP: Filecmd 'rm' successful for %s", r.Filepath)
		return nil
	case "rename":
		oldFilename := r.Filepath[1:] // Remove leading "/"
		newFilename := r.Target[1:]   // Remove leading "/"
		update := bson.M{
			"$set": bson.M{
				"filename": newFilename,
			},
		}
		_, err := fileCollection.UpdateOne(ctx, bson.M{"filename": oldFilename}, update)
		if err != nil {
			log.Printf("SFTP: Filecmd 'rename' failed for %s to %s: %v", r.Filepath, r.Target, err)
			return err
		}
		log.Printf("SFTP: Filecmd 'rename' successful for %s to %s", r.Filepath, r.Target)
		return nil
	}
	log.Printf("SFTP: Filecmd unsupported command: %s", r.Method)
	return fmt.Errorf("unsupported command: %s", r.Method)
}

func (h *FileHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	log.Printf("SFTP: Filelist requested for %s", r.Filepath)
	if r.Filepath == "/" || r.Filepath == "." {
		var files []os.FileInfo
		opts := options.Find().SetProjection(bson.M{"filename": 1, "data": 1, "uploadDate": 1})
		cursor, err := fileCollection.Find(ctx, bson.M{}, opts)
		if err != nil {
			log.Printf("SFTP: Filelist failed for %s: could not query database: %v", r.Filepath, err)
			return nil, err
		}
		defer cursor.Close(ctx)

		for cursor.Next(ctx) {
			var doc FileDocument
			if err := cursor.Decode(&doc); err != nil {
				log.Printf("SFTP: Filelist failed for %s: could not decode document: %v", r.Filepath, err)
				return nil, err
			}
			decodedData, err := base64.StdEncoding.DecodeString(doc.Data)
			if err != nil {
				log.Printf("SFTP: Filelist failed for %s: could not decode data for size calculation: %v", r.Filepath, err)
				// We can still proceed, but the size will be 0
			}

			files = append(files, fileInfo{
				name:    doc.Filename,
				size:    int64(len(decodedData)),
				modTime: doc.UploadDate,
			})
		}

		log.Printf("SFTP: Filelist for %s found %d files", r.Filepath, len(files))
		return listerAt(files), nil
	}

	// If it's not the root directory, try to find a single file.
	// This is not a perfect implementation, as it doesn't handle subdirectories.
	filename := r.Filepath[1:] // Remove leading "/"
	var result FileDocument
	err := fileCollection.FindOne(ctx, bson.M{"filename": filename}).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("SFTP: Filelist failed for %s: file not found", r.Filepath)
			return nil, os.ErrNotExist
		}
		log.Printf("SFTP: Filelist failed for %s: %v", r.Filepath, err)
		return nil, err
	}

	log.Printf("SFTP: Filelist successful for single file %s", r.Filepath)
	return listerAt([]os.FileInfo{fileInfo{
		name:    result.Filename,
		size:    int64(len(result.Data)),
		modTime: result.UploadDate,
	}}), nil
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(f []os.FileInfo, offset int64) (int, error) {
	log.Printf("SFTP: listerAt.ListAt called with offset %d", offset)
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[offset:])
	log.Printf("SFTP: listerAt.ListAt returning %d files", n)
	return n, nil
}

func StartSftpServer() {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(password) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Println("Failed to load private key, generating a new one")
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}

		privateBytes = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

		if err := os.WriteFile("id_rsa", privateBytes, 0600); err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}
		log.Println("Generated and saved a new private key to id_rsa")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key: " + err.Error())
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatalf("Failed to listen on 2222: %v", err)
	}
	log.Println("SFTP server listening on port 2222")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Failed to accept incoming connection: %v", err)
				continue
			}

			go func(conn net.Conn) {
				defer conn.Close()
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					log.Printf("Failed to handshake: %v", err)
					return
				}
				go ssh.DiscardRequests(reqs)

				for newChannel := range chans {
					if newChannel.ChannelType() != "session" {
						newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}
					channel, requests, err := newChannel.Accept()
					if err != nil {
						log.Printf("Could not accept channel: %v", err)
						continue
					}

					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
								req.Reply(true, nil)
							}
						}
					}(requests)

					handler := &FileHandler{}
					server := sftp.NewRequestServer(channel, sftp.Handlers{
						FileGet:  handler,
						FilePut:  handler,
						FileCmd:  handler,
						FileList: handler,
					})

					if err := server.Serve(); err == io.EOF {
						server.Close()
						log.Println("SFTP client exited session.")
					} else if err != nil {
						log.Printf("SFTP server completed with error: %v", err)
					}
				}
			}(conn)
		}
	}()
}
