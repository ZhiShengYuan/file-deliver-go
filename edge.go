package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v4"
)

// =====================
//       STRUCTS
// =====================
type Config struct {
    Nodename  string `json:"nodename"`
    JwtKey    string `json:"jwtkey"`
    Webroot   string `json:"webroot"`
    Failed302 string `json:"failed_302"`
}

// Token claims
type FileClaims struct {
    Signer string   `json:"signer"`
    File   string   `json:"file"`
    Method []string `json:"method"`
    Vailed int64    `json:"vailed"`
    Range  bool     `json:"range"`
    jwt.RegisteredClaims
}

// =====================
//   GLOBALS & VARS
// =====================
var (
    config           Config
    jwtKeyFunc       jwt.Keyfunc
    nonExistentCache sync.Map // stores: map[string]time.Time (filepath -> expiration)
    fileAccessTimes  sync.Map // stores: map[string]time.Time (filepath -> lastAccess)
)

// How long we treat an origin 404 as valid nonexistence.
const notExistCacheDuration = 1 * time.Minute

// How long we keep a file locally if it’s not accessed (for demo, 1 minute).
const localFileTTL = 1 * time.Minute

// We want to keep usage below 95%.
const maxDiskUsageFraction = 0.95

func main() {
    gin.SetMode(gin.ReleaseMode)

    // 1) Load config
    if err := loadConfig("config.json"); err != nil {
        fmt.Printf("Error loading config: %v\n", err)
        os.Exit(1)
    }

    // 2) Prepare JWT key function (only HS256 allowed)
    jwtKeyFunc = func(token *jwt.Token) (interface{}, error) {
        if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(config.JwtKey), nil
    }

    // 3) Setup Gin router and add catch-all route
    router := gin.Default()
    router.Any("/*path", requestHandler)

    // 4) Create Unix domain socket
    sockPath := "/dev/shm/filehost.socket"
    _ = os.Remove(sockPath)
    ln, err := net.Listen("unix", sockPath)
    if err != nil {
        fmt.Printf("Error creating Unix socket listener: %v\n", err)
        os.Exit(1)
    }
    _ = os.Chmod(sockPath, 0700)
    fmt.Printf("Server listening on Unix socket: %s\n", sockPath)

    // Start background cleanup routine.
    go startCleanupRoutine()

    // 5) Start HTTP server using the custom listener.
    server := &http.Server{
        Handler: router,
    }
    if err := server.Serve(ln); err != nil {
        fmt.Printf("Server error: %v\n", err)
        os.Exit(1)
    }
}

// =====================
//     LOAD CONFIG
// =====================
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

// =====================
//    REQUEST HANDLER
// =====================
func requestHandler(c *gin.Context) {
    requestedPath := c.Param("path")
    fmt.Printf("Requested URL path: %s\n", requestedPath)

    // 1) Parse JWT token.
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

    // 2) Check token expiration.
    if time.Now().Unix() > claims.Vailed {
        fmt.Printf("Token expired (current: %d, expiration: %d)\n", time.Now().Unix(), claims.Vailed)
        c.Redirect(http.StatusFound, config.Failed302)
        return
    }

    // 3) Verify HTTP method.
    if !isMethodAllowed(c.Request.Method, claims.Method) {
        fmt.Printf("HTTP method '%s' not allowed; allowed methods: %v\n", c.Request.Method, claims.Method)
        c.Redirect(http.StatusFound, config.Failed302)
        return
    }

    // 4) Verify the requested path matches the token's file path.
    cleanRequested := strings.TrimPrefix(filepath.Clean(requestedPath), "/")
    cleanTokenFile := strings.TrimPrefix(filepath.Clean(claims.File), "/")
    if cleanRequested != cleanTokenFile {
        fmt.Printf("Mismatch: requested '%s' vs token file '%s'\n", requestedPath, claims.File)
        c.Redirect(http.StatusFound, config.Failed302)
        return
    }

    // 5) Construct safe file path.
    safeFilePath := filepath.Join(config.Webroot, cleanTokenFile)
    fmt.Printf("Resolved safe file path: %s\n", safeFilePath)
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

    // 6) Serve the file (or fetch from origin if missing) based on HTTP method.
    switch c.Request.Method {
    case http.MethodGet, http.MethodHead:
        serveFile(c, absFilePath, claims.Range)
    default:
        fmt.Printf("HTTP method '%s' not recognized, redirecting to failed path.\n", c.Request.Method)
        c.Redirect(http.StatusFound, config.Failed302)
    }
}

// =====================
//   PARSE JWT TOKEN
// =====================
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

// =====================
//  CHECK METHOD ALLOWANCE
// =====================
func isMethodAllowed(actual string, allowed []string) bool {
    fmt.Printf("Checking if method '%s' is allowed, token methods: %v\n", actual, allowed)
    for _, m := range allowed {
        if strings.EqualFold(m, actual) {
            fmt.Println("Method allowed.")
            return true
        }
    }
    fmt.Println("Method not allowed.")
    return false
}

// =====================
//     SERVE FILE
// =====================
func serveFile(c *gin.Context, filePath string, rangeAllowed bool) {
    fi, err := os.Stat(filePath)
    if err != nil {
        if os.IsNotExist(err) {
            handleMissingFile(c, filePath)
        } else {
            fmt.Printf("Error checking file '%s': %v\n", filePath, err)
            c.String(http.StatusNotFound, "File not found or is a directory")
        }
        return
    }
    if fi.IsDir() {
        fmt.Printf("'%s' is a directory, not a file.\n", filePath)
        c.String(http.StatusNotFound, "File is a directory")
        return
    }

    // Update last access time.
    fileAccessTimes.Store(filePath, time.Now())
    if rangeAllowed {
        c.Header("Accept-Ranges", "bytes")
    }
    fmt.Printf("Serving file: %s\n", filePath)
    c.File(filePath)
}

// =====================
//  HANDLE MISSING FILE
// =====================
func handleMissingFile(c *gin.Context, filePath string) {
    // 1) Check if file is cached as non-existent.
    if expRaw, ok := nonExistentCache.Load(filePath); ok {
        if expireTime, ok := expRaw.(time.Time); ok && time.Now().Before(expireTime) {
            fmt.Printf("File marked non-existent until %v. Returning 404.\n", expireTime)
            c.String(http.StatusNotFound, "File not found (cached 404)")
            return
        }
        nonExistentCache.Delete(filePath)
    }

    // 2) Build origin URL (remove "/lfs" prefix if present).
    cleaned := strings.Replace(filePath, config.Webroot, "", 1)
    cleaned = strings.TrimPrefix(cleaned, "/")
    cleaned = strings.TrimPrefix(cleaned, "lfs/")
    originURL := fmt.Sprintf("%s/origin/%s", Config.Failed302,cleaned)
    fmt.Printf("Local file missing. Redirecting client to origin: %s\n", originURL)

    // 3) Launch background download of the file.
    go func(filePath, originURL string) {
        resp, err := http.Get(originURL)
        if err != nil {
            fmt.Printf("Error fetching from origin in background: %v\n", err)
            return
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusNotFound {
            expiry := time.Now().Add(notExistCacheDuration)
            nonExistentCache.Store(filePath, expiry)
            fmt.Printf("Background download: origin returned 404. Caching non-existence until %v.\n", expiry)
            return
        } else if resp.StatusCode != http.StatusOK {
            fmt.Printf("Background download: origin responded with status %d.\n", resp.StatusCode)
            return
        }

        if err := saveFileLocally(filePath, resp.Body); err != nil {
            fmt.Printf("Error saving file locally in background: %v\n", err)
            return
        }
        fileAccessTimes.Store(filePath, time.Now())
        fmt.Printf("Background download complete and file cached: %s\n", filePath)
    }(filePath, originURL)

    // 4) Immediately redirect the client.
    c.Redirect(http.StatusFound, originURL)
}


func saveFileLocally(filePath string, r io.Reader) error {
    dir := filepath.Dir(filePath)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return err
    }
    tmp := filePath + ".tmp"
    f, err := os.Create(tmp)
    if err != nil {
        return err
    }
    _, err = io.Copy(f, r)
    f.Close()
    if err != nil {
        os.Remove(tmp)
        return err
    }
    return os.Rename(tmp, filePath)
}

// =====================
//  CLEANUP / EVICTION
// =====================
func startCleanupRoutine() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    for range ticker.C {
        if err := performCleanup(); err != nil {
            fmt.Printf("Cleanup error: %v\n", err)
        }
    }
}

func performCleanup() error {
    now := time.Now()
    var toRemove []string

    err := filepath.Walk(config.Webroot, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if info.IsDir() {
            return nil
        }
        if valRaw, ok := fileAccessTimes.Load(path); ok {
            lastAccess, _ := valRaw.(time.Time)
            if now.Sub(lastAccess) > localFileTTL {
                toRemove = append(toRemove, path)
            }
        } else {
            toRemove = append(toRemove, path)
        }
        return nil
    })
    if err != nil {
        fmt.Printf("Error scanning webroot: %v\n", err)
    }
    for _, path := range toRemove {
        fmt.Printf("Deleting unused file: %s\n", path)
        os.Remove(path)
        fileAccessTimes.Delete(path)
    }

    usage, err := getDiskUsagePercent(config.Webroot)
    if err != nil {
        fmt.Printf("Error getting disk usage: %v\n", err)
        return nil
    }
    if usage > maxDiskUsageFraction {
        usageLoop := usage
        for usageLoop > maxDiskUsageFraction {
            oldestFile, _ := findOldestFile()
            if oldestFile == "" {
                break
            }
            fmt.Printf("Disk usage %.2f > 95%%, removing oldest file: %s\n", usageLoop, oldestFile)
            os.Remove(oldestFile)
            fileAccessTimes.Delete(oldestFile)
            usageLoop, _ = getDiskUsagePercent(config.Webroot)
        }
    }
    return nil
}

func getDiskUsagePercent(rootPath string) (float64, error) {
    var statfs syscall.Statfs_t
    err := syscall.Statfs(rootPath, &statfs)
    if err != nil {
        return 0, err
    }
    free := float64(statfs.Bavail)
    total := float64(statfs.Blocks)
    usedFrac := 1.0 - free/total
    return usedFrac, nil
}

func findOldestFile() (string, time.Time) {
    var oldestPath string
    oldestTime := time.Now()
    fileAccessTimes.Range(func(key, value interface{}) bool {
        fp, _ := key.(string)
        t, _ := value.(time.Time)
        if t.Before(oldestTime) {
            oldestTime = t
            oldestPath = fp
        }
        return true
    })
    return oldestPath, oldestTime
}
