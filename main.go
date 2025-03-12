package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type Config struct {
	Nodename    string `json:"nodename"`
	JwtKey      string `json:"jwtkey"`
	Webroot     string `json:"webroot"`
	Failed302   string `json:"failed_302"`
}

type FileClaims struct {
	Signer string   `json:"signer"`
	File   string   `json:"file"`
	Method []string `json:"method"`
	Vailed int64    `json:"vailed"`
	Range  bool     `json:"range"`
	jwt.RegisteredClaims
}

var config Config
var jwtKeyFunc jwt.Keyfunc

func main() {
	gin.SetMode(gin.ReleaseMode)
	// Load configuration from config.json
	if err := loadConfig("config.json"); err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Prepare JWT key function with algorithm restriction (only HS256)
	jwtKeyFunc = func(token *jwt.Token) (interface{}, error) {
		// Restrict token signing method to HMAC SHA-256
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(config.JwtKey), nil
	}

	// Create Gin router with default middleware (logger and recovery)
	router := gin.Default()

	// Catch-all route for all requests
	router.Any("/*path", requestHandler)

	// Remove any previous socket file and create a Unix domain socket listener
	sockPath := "/dev/shm/filehost.socket"
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		fmt.Printf("Error creating Unix socket listener: %v\n", err)
		os.Exit(1)
	}
	// Set proper permission on the socket
	_ = os.Chmod(sockPath, 0700)

	fmt.Printf("Server listening on Unix socket: %s\n", sockPath)
	// Start the HTTP server using our custom listener
	server := &http.Server{
		Handler: router,
	}
	if err := server.Serve(ln); err != nil {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}

// loadConfig loads JSON configuration from the specified file.
func loadConfig(path string) error {
	f, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening config file '%s': %v\n", path, err)
		return err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&config); err != nil {
		fmt.Printf("Error decoding JSON from config file '%s': %v\n", path, err)
		return err
	}
	fmt.Printf("Configuration loaded successfully: %+v\n", config)
	return nil
}

// requestHandler processes every request coming to the server.
func requestHandler(c *gin.Context) {
	// Capture the requested path from the URL
	requestedPath := c.Param("path")
	fmt.Printf("Requested URL path: %s\n", requestedPath)

	// Retrieve and parse the JWT token
	sign := c.Query("sign")
	if sign == "" {
		fmt.Println("No sign query parameter found, redirecting to failed path.")
		c.Redirect(http.StatusFound, config.Failed302)
		return
	}
	claims, err := parseJWT(sign)
	if err != nil {
		fmt.Printf("Error parsing JWT token: %v\n", err)
		c.Redirect(http.StatusFound, config.Failed302)
		return
	}
	if time.Now().Unix() > claims.Vailed {
		fmt.Printf("Token expired (current time: %d, expiration time: %d)\n", time.Now().Unix(), claims.Vailed)
		c.Redirect(http.StatusFound, config.Failed302)
		return
	}
	if !isMethodAllowed(c.Request.Method, claims.Method) {
		fmt.Printf("HTTP method '%s' not allowed in the token methods: %v\n", c.Request.Method, claims.Method)
		c.Redirect(http.StatusFound, config.Failed302)
		return
	}

	// Verify that the requested path matches the path embedded in the JWT
	if strings.TrimPrefix(filepath.Clean(requestedPath), "/") != strings.TrimPrefix(filepath.Clean(claims.File), "/") {
		fmt.Printf("Mismatch between requested path (%s) and token file (%s)\n", requestedPath, claims.File)
		c.Redirect(http.StatusFound, config.Failed302)
		return
	}

	// Construct the safe file path using the verified relative path
	safeFilePath := filepath.Join(config.Webroot, strings.TrimPrefix(filepath.Clean(claims.File), "/"))
	fmt.Printf("Resolved safe file path: %s\n", safeFilePath)

	// Ensure the file path is within the allowed webroot directory
	absWebRoot, err := filepath.Abs(config.Webroot)
	if err != nil {
		fmt.Println("Error resolving absolute path for webroot:", err)
		c.Redirect(http.StatusFound, config.Failed302)
		return
	}
	absFilePath, err := filepath.Abs(safeFilePath)
	if err != nil || !strings.HasPrefix(absFilePath, absWebRoot) {
		fmt.Println("Path traversal detected!")
		c.Redirect(http.StatusFound, config.Failed302)
		return
	}

	// Dispatch based on HTTP method (file uploads removed)
	switch c.Request.Method {
	case http.MethodGet, http.MethodHead:
		serveFile(c, safeFilePath, claims.Range)
	default:
		fmt.Printf("HTTP method '%s' not recognized, redirecting to failed path.\n", c.Request.Method)
		c.Redirect(http.StatusFound, config.Failed302)
	}
}

// parseJWT verifies and parses the JWT token.
func parseJWT(tokenStr string) (*FileClaims, error) {
	claims := &FileClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, jwtKeyFunc)
	if err != nil {
		fmt.Printf("Error parsing JWT: %v\n", err)
		return nil, err
	}
	if !token.Valid {
		fmt.Println("Invalid JWT token.")
		return nil, errors.New("invalid token")
	}
	fmt.Printf("JWT parsed successfully: %+v\n", claims)
	return claims, nil
}

// isMethodAllowed checks if the request method is permitted.
func isMethodAllowed(actual string, allowed []string) bool {
	fmt.Printf("Checking if method '%s' is allowed, allowed methods: %v\n", actual, allowed)
	for _, m := range allowed {
		if strings.EqualFold(m, actual) {
			fmt.Println("Method allowed.")
			return true
		}
	}
	fmt.Println("Method not allowed.")
	return false
}

// serveFile serves the requested file for download.
func serveFile(c *gin.Context, filePath string, rangeAllowed bool) {
	fmt.Printf("Attempting to serve file at path: %s\n", filePath)
	fi, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("Error checking file stats for '%s': %v\n", filePath, err)
		if os.IsNotExist(err) {
			fmt.Printf("File does not exist at the path: %s\n", filePath)
		} else {
			fmt.Printf("Other error: %v\n", err)
		}
		c.String(http.StatusNotFound, "File not found or is a directory")
		return
	}
	if fi.IsDir() {
		fmt.Printf("The path '%s' is a directory, not a file.\n", filePath)
		c.String(http.StatusNotFound, "File is a directory, not a file")
		return
	}

	fmt.Printf("File found: %s\n", filePath)

	if rangeAllowed {
		c.Header("Accept-Ranges", "bytes")
	}

	fmt.Printf("Serving file: %s\n", filePath)
	c.File(filePath)
}
