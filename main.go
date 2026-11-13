package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	httpAddress  = ":80"
	httpsAddress = ":443"
	dataDir      = "data"
	certDir      = "certs"
	staticDir    = "assets"
	indexFile    = "index.html"
	infoFile     = "info.html"

	hostapdService = "hostapd.service"
)

type Pedido struct {
	ID        int      `json:"id"`
	Nombre    string   `json:"nombre"`
	Agregados []string `json:"agregados"`
	Fecha     string   `json:"fecha"`
}

type PedidoResponse struct {
	OK      bool     `json:"ok"`
	Total   int      `json:"total"`
	Pedidos []Pedido `json:"pedidos"`
}

type ErrorResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type APIResponse struct {
	OK      bool        `json:"ok"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type configEntry struct {
	Key   string
	Value string
}

var (
	pedidos   []Pedido
	pedidosMu sync.RWMutex
	nextID    = 1

	apiToken string

	wirelessInterfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.:-]+$`)
	iwconfigModeRegex      = regexp.MustCompile(`Mode:\s*([A-Za-z]+)`)
	ansiEscapeRegex        = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")
)

func main() {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Fatal(err)
	}

	if err := loadPedidos(); err != nil {
		log.Printf("[WARN] No se pudieron cargar los pedidos: %v", err)
	}

	token, err := ensureHotspotToken()
	if err != nil {
		log.Fatalf("[HOTSPOT] No se pudo preparar el token: %v", err)
	}
	apiToken = token

	if err := ensureCertificate(); err != nil {
		log.Fatalf("[TLS] No se pudo preparar el certificado: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/pedido/", pedidosHandler)

	mux.HandleFunc("/info", infoHandler)
	mux.HandleFunc("/info/", infoHandler)

	mux.Handle("/assets/",
		http.StripPrefix("/assets/", http.FileServer(http.Dir(staticDir))),
	)

	mux.HandleFunc("/api/hotspot/", hotspotHandler)

	mux.HandleFunc("/", indexHandler)

	httpServer := &http.Server{
		Addr:              httpAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	httpsServer := &http.Server{
		Addr:              httpsAddress,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errorsChannel := make(chan error, 2)

	go func() {
		log.Printf("[HTTP] Escuchando en %s", httpAddress)
		errorsChannel <- httpServer.ListenAndServe()
	}()

	go func() {
		log.Printf("[HTTPS] Escuchando en %s", httpsAddress)

		errorsChannel <- httpsServer.ListenAndServeTLS(
			filepath.Join(certDir, "server.crt"),
			filepath.Join(certDir, "server.key"),
		)
	}()

	err = <-errorsChannel

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[SERVER] Error: %v", err)
	}
}

// ============================================================
// PEDIDOS
// ============================================================

func pedidosHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		getPedidos(w)

	case http.MethodPost:
		postPedido(w, r)

	case http.MethodOptions:
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)

	default:
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, "Metodo no permitido")
	}
}

func getPedidos(w http.ResponseWriter) {
	pedidosMu.RLock()

	result := make([]Pedido, len(pedidos))
	copy(result, pedidos)

	pedidosMu.RUnlock()

	writeJSON(w, http.StatusOK, PedidoResponse{
		OK:      true,
		Total:   len(result),
		Pedidos: result,
	})
}

func postPedido(w http.ResponseWriter, r *http.Request) {
	mediaType := strings.ToLower(strings.TrimSpace(
		strings.Split(r.Header.Get("Content-Type"), ";")[0],
	))

	switch mediaType {
	case "application/x-www-form-urlencoded":
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "Formulario invalido")
			return
		}

	case "multipart/form-data":
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

		if err := r.ParseMultipartForm(10 << 20); err != nil {
			writeError(w, http.StatusBadRequest, "Formulario multipart invalido")
			return
		}

	default:
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type no soportado")
		return
	}

	nombre := strings.TrimSpace(r.Form.Get("nombre"))

	if nombre == "" {
		writeError(w, http.StatusBadRequest, "El campo nombre es obligatorio")
		return
	}

	agregados := append([]string{}, r.Form["agregados"]...)
	agregados = append(agregados, r.Form["agregados[]"]...)

	cleanAgregados := make([]string, 0, len(agregados))

	for _, agregado := range agregados {
		agregado = strings.TrimSpace(agregado)

		if agregado != "" {
			cleanAgregados = append(cleanAgregados, agregado)
		}
	}

	pedidosMu.Lock()

	pedido := Pedido{
		ID:        nextID,
		Nombre:    nombre,
		Agregados: cleanAgregados,
		Fecha:     time.Now().Format(time.RFC3339),
	}

	pedidos = append(pedidos, pedido)
	nextID++

	if err := savePedidosLocked(); err != nil {
		pedidos = pedidos[:len(pedidos)-1]
		nextID--
		pedidosMu.Unlock()

		log.Printf("[PEDIDOS] Error guardando pedido: %v", err)
		writeError(w, http.StatusInternalServerError, "No se pudo guardar el pedido")
		return
	}

	pedidosMu.Unlock()

	pedidosEvents.broadcast("pedido", pedido)

	log.Printf("[PEDIDOS] Pedido #%d registrado: %s", pedido.ID, pedido.Nombre)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"ok":      true,
		"mensaje": "Pedido registrado correctamente",
		"pedido":  pedido,
	})
}

// ============================================================
// HOTSPOT: TIPOS Y CONSTANTES
// ============================================================

type wifiBackend string

const (
	backendNetworkManager wifiBackend = "networkmanager"
	backendHostapd        wifiBackend = "hostapd"
	backendNone           wifiBackend = "none"
)

const (
	envHotspotProfile = "OPENSTICK_HOTSPOT_PROFILE"
	envHostapdConfig  = "OPENSTICK_HOSTAPD_CONFIG"
	sessionCookieName = "os_admin_session"
	sessionTTL        = 8 * time.Hour
)

// HotspotConfigRequest es el cuerpo aceptado por POST /api/hotspot/config.
type HotspotConfigRequest struct {
	Interface  string `json:"interface,omitempty"`
	SSID       string `json:"ssid,omitempty"`
	Password   string `json:"password,omitempty"`
	Security   string `json:"security,omitempty"`
	IPv4Method string `json:"ipv4Method,omitempty"`
}

// MACRequest es el cuerpo aceptado por POST /api/hotspot/mac.
type MACRequest struct {
	Interface string `json:"interface,omitempty"`
	MAC       string `json:"mac"`
}

// SessionRequest es el cuerpo aceptado por POST /api/hotspot/session.
type SessionRequest struct {
	Token string `json:"token"`
}

type HotspotStatus struct {
	OK           bool     `json:"ok"`
	Backend      string   `json:"backend"`
	Enabled      bool     `json:"enabled"`
	Service      string   `json:"service"`
	Profile      string   `json:"profile,omitempty"`
	Interface    string   `json:"interface,omitempty"`
	SSID         string   `json:"ssid,omitempty"`
	MAC          string   `json:"mac,omitempty"`
	PermanentMAC string   `json:"permanentMac,omitempty"`
	Mode         string   `json:"mode,omitempty"`
	Security     string   `json:"security,omitempty"`
	IPv4Method   string   `json:"ipv4Method,omitempty"`
	IPv4Address  []string `json:"ipv4Address,omitempty"`
	Band         string   `json:"band,omitempty"`
	Channel      string   `json:"channel,omitempty"`
	Clients      int      `json:"clients"`
	UpdatedAt    string   `json:"updatedAt"`
	Warnings     []string `json:"warnings,omitempty"`
	clients      []WiFiClient
}

type WiFiClient struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip,omitempty"`
	Interface string `json:"interface,omitempty"`
	Connected bool   `json:"connected"`
	Source    string `json:"source,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Signal    string `json:"signal,omitempty"`
	LastSeen  string `json:"lastSeen,omitempty"`
	ExpiresIn string `json:"expiresIn,omitempty"`
}

type ClientsResponse struct {
	OK        bool            `json:"ok"`
	Total     int             `json:"total"`
	Clients   []WiFiClient    `json:"clients"`
	Available bool            `json:"available"`
	Interface string          `json:"interface,omitempty"`
	Sources   map[string]bool `json:"sources,omitempty"`
	Warnings  []string        `json:"warnings,omitempty"`
}

type InterfaceInfo struct {
	Name         string   `json:"name"`
	MAC          string   `json:"mac,omitempty"`
	PermanentMAC string   `json:"permanentMac,omitempty"`
	Driver       string   `json:"driver,omitempty"`
	Mode         string   `json:"mode,omitempty"`
	OperState    string   `json:"operState,omitempty"`
	Up           bool     `json:"up"`
	Carrier      bool     `json:"carrier"`
	APSupported  string   `json:"apSupported,omitempty"`
	IPv4         []string `json:"ipv4,omitempty"`
	IsHotspot    bool     `json:"isHotspot"`
}

type ServiceInfo struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type Diagnostics struct {
	OK              bool              `json:"ok"`
	Backend         string            `json:"backend"`
	Kernel          string            `json:"kernel"`
	Arch            string            `json:"arch"`
	Distro          string            `json:"distro"`
	Hostname        string            `json:"hostname,omitempty"`
	Uptime          string            `json:"uptime,omitempty"`
	Hotspot         HotspotStatus     `json:"hotspot"`
	Interfaces      []InterfaceInfo   `json:"interfaces"`
	Tools           map[string]string `json:"tools"`
	Services        []ServiceInfo     `json:"services"`
	WifiProperties  map[string]string `json:"wifiProperties,omitempty"`
	HasDefaultRoute bool              `json:"hasDefaultRoute"`
	Warnings        []string          `json:"warnings,omitempty"`
	Limitations     []string          `json:"limitations,omitempty"`
	ClientSources   map[string]bool   `json:"clientSources"`
	GeneratedAt     string            `json:"generatedAt"`
}

// ============================================================
// SESIONES ADMINISTRATIVAS
// ============================================================

type sessionStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

var adminSessions = &sessionStore{entries: make(map[string]time.Time)}

func (s *sessionStore) create() (string, time.Time, error) {
	buf := make([]byte, 32)

	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}

	id := hex.EncodeToString(buf)
	expires := time.Now().Add(sessionTTL)

	s.mu.Lock()
	s.pruneLocked()
	s.entries[id] = expires
	s.mu.Unlock()

	return id, expires, nil
}

func (s *sessionStore) valid(id string) bool {
	if id == "" {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	expires, found := s.entries[id]

	if !found {
		return false
	}

	if time.Now().After(expires) {
		delete(s.entries, id)
		return false
	}

	// Renovacion deslizante mientras la sesion se use.
	s.entries[id] = time.Now().Add(sessionTTL)

	return true
}

func (s *sessionStore) destroy(id string) {
	if id == "" {
		return
	}

	s.mu.Lock()
	delete(s.entries, id)
	s.mu.Unlock()
}

func (s *sessionStore) pruneLocked() {
	now := time.Now()

	for id, expires := range s.entries {
		if now.After(expires) {
			delete(s.entries, id)
		}
	}
}

type authAttempt struct {
	count int
	first time.Time
	until time.Time
}

type authLimiter struct {
	mu       sync.Mutex
	attempts map[string]*authAttempt
	window   time.Duration
	max      int
	block    time.Duration
}

func newAuthLimiter(window time.Duration, max int, block time.Duration) *authLimiter {
	return &authLimiter{
		attempts: make(map[string]*authAttempt),
		window:   window,
		max:      max,
		block:    block,
	}
}

func (l *authLimiter) blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	attempt, found := l.attempts[key]

	if !found {
		return false, 0
	}

	now := time.Now()

	if now.Before(attempt.until) {
		return true, attempt.until.Sub(now)
	}

	if now.Sub(attempt.first) > l.window {
		delete(l.attempts, key)
	}

	return false, 0
}

func (l *authLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	if len(l.attempts) > 2048 {
		l.attempts = make(map[string]*authAttempt)
	}

	attempt, found := l.attempts[key]

	if !found || now.Sub(attempt.first) > l.window {
		l.attempts[key] = &authAttempt{count: 1, first: now}
		return
	}

	attempt.count++

	if attempt.count >= l.max {
		attempt.until = now.Add(l.block)
		attempt.count = 0
		attempt.first = now
	}
}

func (l *authLimiter) success(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

var hotspotAuthLimiter = newAuthLimiter(5*time.Minute, 8, 2*time.Minute)

// ============================================================
// HOTSPOT: ENRUTADOR
// ============================================================

func hotspotHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/hotspot/"), "/")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, POST, DELETE, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch path {
	case "session":
		switch r.Method {
		case http.MethodPost:
			hotspotLoginHandler(w, r)

		case http.MethodGet:
			if !authorizeHotspot(w, r) {
				return
			}
			hotspotSessionHandler(w)

		case http.MethodDelete:
			hotspotLogoutHandler(w, r)

		default:
			methodNotAllowed(w, "GET, POST, DELETE")
		}
		return

	case "":
		writeError(w, http.StatusNotFound, "Endpoint de hotspot no encontrado")
		return
	}

	if !authorizeHotspot(w, r) {
		return
	}

	switch path {
	case "status":
		requireMethod(w, r, http.MethodGet, hotspotStatusHandler)

	case "enable":
		requireMethod(w, r, http.MethodPost, hotspotEnableHandler)

	case "disable":
		requireMethod(w, r, http.MethodPost, hotspotDisableHandler)

	case "config":
		switch r.Method {
		case http.MethodGet:
			hotspotGetConfigHandler(w)

		case http.MethodPost:
			hotspotSetConfigHandler(w, r)

		default:
			methodNotAllowed(w, "GET, POST")
		}

	case "mac":
		switch r.Method {
		case http.MethodGet:
			hotspotGetMACHandler(w, r)

		case http.MethodPost:
			hotspotSetMACHandler(w, r)

		default:
			methodNotAllowed(w, "GET, POST")
		}

	case "clients":
		requireMethod(w, r, http.MethodGet, hotspotClientsHandler)

	case "interfaces":
		requireMethod(w, r, http.MethodGet, hotspotInterfacesHandler)

	case "diagnostics":
		requireMethod(w, r, http.MethodGet, hotspotDiagnosticsHandler)

	case "shell":
		requireMethod(w, r, http.MethodPost, func(w http.ResponseWriter) {
			hotspotShellHandler(w, r)
		})

	case "files":
		requireMethod(w, r, http.MethodGet, func(w http.ResponseWriter) {
			hotspotFilesHandler(w, r)
		})

	case "file":
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("download") == "1" {
				hotspotFileDownloadHandler(w, r)
			} else {
				hotspotFileReadHandler(w, r)
			}
		case http.MethodPost:
			hotspotFileWriteHandler(w, r)
		case http.MethodDelete:
			hotspotFileDeleteHandler(w, r)
		default:
			methodNotAllowed(w, "GET, POST, DELETE")
		}

	case "file/move":
		requireMethod(w, r, http.MethodPost, func(w http.ResponseWriter) {
			hotspotFileMoveHandler(w, r)
		})

	case "file/upload":
		requireMethod(w, r, http.MethodPost, func(w http.ResponseWriter) {
			hotspotFileUploadHandler(w, r)
		})

	case "dhcp":
		requireMethod(w, r, http.MethodGet, hotspotDHCPHandler)

	case "dhcp/restart":
		requireMethod(w, r, http.MethodPost, func(w http.ResponseWriter) {
			hotspotDHCPRestartHandler(w)
		})

	case "dns":
		switch r.Method {
		case http.MethodGet:
			hotspotDNSHandler(w)

		case http.MethodPost:
			hotspotDNSSetHandler(w, r)

		default:
			methodNotAllowed(w, "GET, POST")
		}

	case "events":
		hotspotEventsHandler(w, r)

	default:
		writeError(w, http.StatusNotFound, "Endpoint de hotspot no encontrado")
	}
}

func requireMethod(
	w http.ResponseWriter,
	r *http.Request,
	method string,
	handler func(http.ResponseWriter),
) {
	if r.Method != method {
		methodNotAllowed(w, method)
		return
	}

	handler(w)
}

// ============================================================
// AUTENTICACION
// ============================================================

// defaultAdminToken es el token administrativo de ejemplo para uso local.
// El dispositivo no esta expuesto a Internet; para un despliegue publico
// define OPENSTICK_ADMIN_TOKEN en la unidad systemd.
const defaultAdminToken = "OpenStick2026"

// ensureHotspotToken determina el token administrativo.
// Precedencia: OPENSTICK_ADMIN_TOKEN > token de ejemplo por defecto.
// El token en uso se mantiene sincronizado en data/hotspot.token (0600).
// Nunca se registra ni se devuelve en las respuestas.
func ensureHotspotToken() (string, error) {
	token := strings.TrimSpace(os.Getenv("OPENSTICK_ADMIN_TOKEN"))

	if token == "" {
		token = defaultAdminToken
	}

	path := filepath.Join(dataDir, "hotspot.token")

	if err := os.WriteFile(path, []byte(token+"\n"), 0600); err != nil {
		return "", err
	}

	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}

	log.Println("[HOTSPOT] Token administrativo configurado")

	return token, nil
}

func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)

	if err != nil {
		return r.RemoteAddr
	}

	return host
}

func authorizeHotspot(w http.ResponseWriter, r *http.Request) bool {
	key := clientKey(r)

	if blocked, retry := hotspotAuthLimiter.blocked(key); blocked {
		seconds := int(retry.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeError(
			w,
			http.StatusTooManyRequests,
			"Demasiados intentos de autenticacion fallidos. Intenta de nuevo en "+strconv.Itoa(seconds)+" segundos.",
		)
		return false
	}

	if apiToken == "" {
		writeError(w, http.StatusServiceUnavailable, "El token administrativo no esta inicializado")
		return false
	}

	// 1) Sesion de navegador (cookie HttpOnly, sin token en el cliente).
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if adminSessions.valid(cookie.Value) {
			hotspotAuthLimiter.success(key)
			return true
		}
	}

	// 2) Token directo (compatibilidad con scripts y curl).
	provided := strings.TrimSpace(r.Header.Get("Authorization"))

	if strings.HasPrefix(strings.ToLower(provided), "bearer ") {
		provided = strings.TrimSpace(provided[7:])
	} else {
		provided = strings.TrimSpace(r.Header.Get("X-API-Token"))
	}

	if provided != "" && subtle.ConstantTimeCompare(
		[]byte(provided),
		[]byte(apiToken),
	) == 1 {
		hotspotAuthLimiter.success(key)
		return true
	}

	hotspotAuthLimiter.fail(key)

	writeError(w, http.StatusUnauthorized, "Token administrativo invalido o sesion caducada")
	return false
}

func hotspotLoginHandler(w http.ResponseWriter, r *http.Request) {
	var request SessionRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	key := clientKey(r)

	if blocked, retry := hotspotAuthLimiter.blocked(key); blocked {
		seconds := int(retry.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeError(w, http.StatusTooManyRequests, "Demasiados intentos fallidos. Espera "+strconv.Itoa(seconds)+" segundos.")
		return
	}

	provided := strings.TrimSpace(request.Token)

	if apiToken == "" || provided == "" || subtle.ConstantTimeCompare(
		[]byte(provided),
		[]byte(apiToken),
	) != 1 {
		hotspotAuthLimiter.fail(key)
		writeError(w, http.StatusUnauthorized, "Token administrativo incorrecto")
		return
	}

	sessionID, expires, err := adminSessions.create()

	if err != nil {
		log.Printf("[HOTSPOT] No se pudo crear la sesion: %v", err)
		writeError(w, http.StatusInternalServerError, "No se pudo crear la sesion administrativa")
		return
	}

	hotspotAuthLimiter.success(key)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	})

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Sesion administrativa iniciada",
		Data: map[string]interface{}{
			"authenticated": true,
			"expiresAt":     expires.Format(time.RFC3339),
		},
	})
}

func hotspotSessionHandler(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Sesion valida",
		Data: map[string]interface{}{
			"authenticated": true,
			"tokenTTL":      sessionTTL.Seconds(),
		},
	})
}

func hotspotLogoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		adminSessions.destroy(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Sesion cerrada",
	})
}

// ============================================================
// HOTSPOT: HERRAMIENTAS DEL SISTEMA
// ============================================================

func hasCommand(name string) bool {
	_, err := exec.LookPath(name)

	return err == nil
}

func commandPath(name string) string {
	path, err := exec.LookPath(name)

	if err != nil {
		return ""
	}

	return path
}

func unescapeNM(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))

	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
			builder.WriteByte(value[i])
			continue
		}

		builder.WriteByte(value[i])
	}

	return builder.String()
}

func firstLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)

		if line != "" {
			return unescapeNM(line)
		}
	}

	return ""
}

func nonEmptyLines(value string) []string {
	lines := make([]string, 0, 4)

	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)

		if line != "" {
			lines = append(lines, unescapeNM(line))
		}
	}

	return lines
}

var (
	backendMu     sync.Mutex
	backendCached wifiBackend
	backendAt     time.Time

	profileMu     sync.Mutex
	profileCached string
	profileAt     time.Time
)

func invalidateNMCache() {
	profileMu.Lock()
	profileCached = ""
	profileAt = time.Time{}
	profileMu.Unlock()

	backendMu.Lock()
	backendAt = time.Time{}
	backendMu.Unlock()
}

func detectBackend() wifiBackend {
	backendMu.Lock()
	defer backendMu.Unlock()

	if !backendAt.IsZero() && time.Since(backendAt) < 5*time.Second {
		return backendCached
	}

	backend := backendNone

	if hasCommand("nmcli") {
		if output, err := runCommand(
			4*time.Second,
			"nmcli", "--colors", "no", "-t", "-f", "RUNNING", "general",
		); err == nil {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(output)), "running") {
				backend = backendNetworkManager
			}
		}
	}

	if backend == backendNone && hasCommand("hostapd") {
		backend = backendHostapd
	}

	backendCached = backend
	backendAt = time.Now()

	return backend
}

// nmGetConnectionField lee un campo de un perfil de NetworkManager.
// nmcli devuelve "campo:valor" en algunas variantes y solo "valor" en otras,
// por lo que se toleran ambas formas.
func nmGetConnectionField(profile, field string) (string, error) {
	output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-t", "-g", field, "connection", "show", profile,
	)

	if err != nil {
		return "", err
	}

	line := strings.TrimSpace(output)

	if index := strings.Index(line, ":"); index > 0 {
		if strings.EqualFold(strings.TrimSpace(line[:index]), field) {
			line = line[index+1:]
		}
	}

	return strings.TrimSpace(unescapeNM(line)), nil
}

func nmGetSecretField(profile, field string) (string, error) {
	output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-s", "-t", "-g", field, "connection", "show", profile,
	)

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(unescapeNM(output)), nil
}

// nmSecurityMode traduce el modo de seguridad del perfil a un valor estable
// para la API: "open" o "wpa2".
func nmSecurityMode(profile string) string {
	if profile == "" {
		return ""
	}

	keyManagement, err := nmGetConnectionField(profile, "802-11-wireless-security.key-mgmt")

	if err != nil || keyManagement == "" || strings.EqualFold(keyManagement, "none") {
		return "open"
	}

	return "wpa2"
}

// nmProfileFile localiza el fichero keyfile del perfil de NetworkManager.
func nmProfileFile(profile string) (string, error) {
	if output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-t", "-f", "FILENAME", "connection", "show", profile,
	); err == nil {
		if path := firstLine(output); path != "" && fileExists(path) && strings.HasSuffix(path, ".nmconnection") {
			return path, nil
		}
	}

	matches, _ := filepath.Glob("/etc/NetworkManager/system-connections/*.nmconnection")

	for _, path := range matches {
		content, err := os.ReadFile(path)

		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(content), "\n") {
			if strings.TrimSpace(line) == "id="+profile {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("no se encontro el fichero del perfil %q", profile)
}

// nmSetOpenSecurity deja el punto de acceso sin contrasena.
// NetworkManager 1.30 no permite borrar el secreto psk con
// "nmcli connection modify", asi que se elimina la seccion [wifi-security]
// del keyfile (con copia de seguridad) y se recarga el perfil.
func nmSetOpenSecurity(profile string) error {
	path, err := nmProfileFile(profile)

	if err != nil {
		return err
	}

	content, err := os.ReadFile(path)

	if err != nil {
		return err
	}

	info, err := os.Stat(path)

	if err != nil {
		return err
	}

	backupPath := filepath.Join("/tmp", filepath.Base(path)+".bak")

	if err := os.WriteFile(backupPath, content, 0600); err != nil {
		return fmt.Errorf("no se pudo crear la copia de seguridad: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	result := make([]string, 0, len(lines))
	skipping := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skipping = strings.EqualFold(trimmed, "[wifi-security]")

			if skipping {
				continue
			}
		}

		if skipping {
			continue
		}

		result = append(result, line)
	}

	tempPath := path + ".tmp"

	if err := os.WriteFile(tempPath, []byte(strings.Join(result, "\n")), info.Mode().Perm()); err != nil {
		return err
	}

	if err := os.Chmod(tempPath, 0600); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	output, err := runCommand(10*time.Second, "nmcli", "--colors", "no", "connection", "reload")

	if err != nil {
		return errors.New(commandError("NetworkManager no pudo recargar el perfil", output, err))
	}

	invalidateNMCache()

	return nil
}

// nmSetWPASecurity deja el punto de acceso con WPA2-PSK y la contrasena indicada.
// Se escribe la seccion [wifi-security] en el keyfile porque NetworkManager 1.30
// no la recrea de forma fiable al modificar un perfil que carecia de ella.
func nmSetWPASecurity(profile, password string) error {
	path, err := nmProfileFile(profile)

	if err != nil {
		return err
	}

	content, err := os.ReadFile(path)

	if err != nil {
		return err
	}

	info, err := os.Stat(path)

	if err != nil {
		return err
	}

	backupPath := filepath.Join("/tmp", filepath.Base(path)+".bak")

	if err := os.WriteFile(backupPath, content, 0600); err != nil {
		return fmt.Errorf("no se pudo crear la copia de seguridad: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	result := make([]string, 0, len(lines))
	skipping := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			skipping = strings.EqualFold(trimmed, "[wifi-security]")

			if skipping {
				continue
			}
		}

		if skipping {
			continue
		}

		result = append(result, line)
	}

	section := []string{
		"[wifi-security]",
		"group=ccmp;",
		"key-mgmt=wpa-psk",
		"pairwise=ccmp;",
		"proto=rsn;",
		"psk=" + password,
		"",
	}

	insertAt := len(result)

	for index, line := range result {
		if strings.EqualFold(strings.TrimSpace(line), "[ipv4]") {
			insertAt = index
			break
		}
	}

	newResult := make([]string, 0, len(result)+len(section))
	newResult = append(newResult, result[:insertAt]...)
	newResult = append(newResult, section...)
	newResult = append(newResult, result[insertAt:]...)

	tempPath := path + ".tmp"

	if err := os.WriteFile(tempPath, []byte(strings.Join(newResult, "\n")), info.Mode().Perm()); err != nil {
		return err
	}

	if err := os.Chmod(tempPath, 0600); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	output, err := runCommand(10*time.Second, "nmcli", "--colors", "no", "connection", "reload")

	if err != nil {
		return errors.New(commandError("NetworkManager no pudo recargar el perfil", output, err))
	}

	invalidateNMCache()

	return nil
}

// permanentMAC devuelve la MAC de hardware real cuando el sistema la expone.
// Si la interfaz usa una MAC aleatoria y el driver no la publica, devuelve "".
func permanentMAC(iface string) string {
	if readInterfaceString(iface, "addr_assign_type") == "0" {
		if mac, err := readInterfaceMAC(iface); err == nil {
			return mac
		}
	}

	if hasCommand("ethtool") {
		if output, err := runCommand(4*time.Second, "ethtool", "-P", iface); err == nil {
			marker := "permanent address:"

			if index := strings.Index(strings.ToLower(output), marker); index >= 0 {
				value := strings.TrimSpace(output[index+len(marker):])

				if hardware, parseErr := net.ParseMAC(value); parseErr == nil && len(hardware) == 6 {
					return strings.ToLower(hardware.String())
				}
			}
		}
	}

	return ""
}

func nmGetDeviceField(device, field string) (string, error) {
	output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-t", "-g", field, "device", "show", device,
	)

	if err != nil {
		return "", err
	}

	line := firstLine(output)

	if index := strings.Index(line, ":"); index > 0 {
		if strings.EqualFold(strings.TrimSpace(line[:index]), field) {
			line = line[index+1:]
		}
	}

	return strings.TrimSpace(line), nil
}

func nmConnectionList() ([][2]string, error) {
	output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-t", "-f", "NAME,TYPE", "connection", "show",
	)

	if err != nil {
		return nil, err
	}

	result := make([][2]string, 0, 8)

	for _, line := range nonEmptyLines(output) {
		name, kind, found := strings.Cut(line, ":")

		if !found {
			continue
		}

		result = append(result, [2]string{
			strings.TrimSpace(unescapeNM(name)),
			strings.TrimSpace(unescapeNM(kind)),
		})
	}

	return result, nil
}

// nmHotspotProfile localiza el perfil de NetworkManager en modo AP.
func nmHotspotProfile() (string, error) {
	if candidate := strings.TrimSpace(os.Getenv(envHotspotProfile)); candidate != "" {
		return candidate, nil
	}

	profileMu.Lock()
	defer profileMu.Unlock()

	if profileCached != "" && time.Since(profileAt) < 5*time.Second {
		return profileCached, nil
	}

	connections, err := nmConnectionList()

	if err != nil {
		return "", fmt.Errorf("no se pudo consultar NetworkManager: %w", err)
	}

	for _, connection := range connections {
		if connection[1] != "802-11-wireless" {
			continue
		}

		mode, modeErr := nmGetConnectionField(connection[0], "802-11-wireless.mode")

		if modeErr == nil && strings.EqualFold(mode, "ap") {
			profileCached = connection[0]
			profileAt = time.Now()

			return connection[0], nil
		}
	}

	return "", errors.New(
		"no se encontro ningun perfil Wi-Fi en modo AP (ni OPENSTICK_HOTSPOT_PROFILE)",
	)
}

func nmConnectionActive(profile string) bool {
	output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-t", "-f", "NAME", "connection", "show", "--active",
	)

	if err != nil {
		return false
	}

	for _, line := range nonEmptyLines(output) {
		if strings.EqualFold(unescapeNM(line), profile) {
			return true
		}
	}

	return false
}

func nmProfileForInterface(iface string) (string, error) {
	connections, err := nmConnectionList()

	if err != nil {
		return "", err
	}

	fallback := ""

	for _, connection := range connections {
		if connection[1] != "802-11-wireless" {
			continue
		}

		name := connection[0]

		profileIface, ifaceErr := nmGetConnectionField(name, "connection.interface-name")

		if ifaceErr != nil || profileIface != iface {
			continue
		}

		mode, modeErr := nmGetConnectionField(name, "802-11-wireless.mode")

		if modeErr == nil && strings.EqualFold(mode, "ap") {
			return name, nil
		}

		if fallback == "" {
			fallback = name
		}
	}

	if fallback != "" {
		return fallback, nil
	}

	return "", fmt.Errorf("no hay perfil de NetworkManager para la interfaz %s", iface)
}

// nmActiveAPInterface devuelve la interfaz Wi-Fi que esta emitiendo un AP.
func nmActiveAPInterface() string {
	output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status",
	)

	if err != nil {
		return ""
	}

	for _, line := range nonEmptyLines(output) {
		fields := strings.Split(line, ":")

		if len(fields) < 4 {
			continue
		}

		device := strings.TrimSpace(unescapeNM(fields[0]))
		kind := strings.TrimSpace(fields[1])
		state := strings.TrimSpace(fields[2])
		connection := strings.TrimSpace(unescapeNM(fields[3]))

		if kind != "wifi" || state != "connected" || connection == "" {
			continue
		}

		mode, modeErr := nmGetConnectionField(connection, "802-11-wireless.mode")

		if modeErr == nil && strings.EqualFold(mode, "ap") {
			return device
		}
	}

	return ""
}

// ============================================================
// HOTSPOT: INTERFACES
// ============================================================

func readInterfaceMAC(name string) (string, error) {
	content, err := os.ReadFile(filepath.Join("/sys/class/net", name, "address"))

	if err != nil {
		return "", err
	}

	return strings.ToLower(strings.TrimSpace(string(content))), nil
}

func readInterfaceString(name, file string) string {
	content, err := os.ReadFile(filepath.Join("/sys/class/net", name, file))

	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(content))
}

func interfaceDriver(name string) string {
	target := filepath.Join("/sys/class/net", name, "device", "driver")

	if resolved, err := filepath.EvalSymlinks(target); err == nil {
		return filepath.Base(resolved)
	}

	return ""
}

func interfaceMode(name string) string {
	if !hasCommand("iwconfig") {
		return ""
	}

	output, err := runCommand(4*time.Second, "iwconfig", name)

	if err != nil {
		return ""
	}

	if match := iwconfigModeRegex.FindStringSubmatch(output); len(match) == 2 {
		return match[1]
	}

	return ""
}

func interfaceIPv4(name string) []string {
	device, err := net.InterfaceByName(name)

	if err != nil {
		return nil
	}

	addresses, err := device.Addrs()

	if err != nil {
		return nil
	}

	result := make([]string, 0, len(addresses))

	for _, address := range addresses {
		network, ok := address.(*net.IPNet)

		if !ok || network.IP.To4() == nil {
			continue
		}

		result = append(result, network.String())
	}

	return result
}

func getWirelessInterfaces() []string {
	found := make(map[string]bool)

	for _, pattern := range []string{
		"/sys/class/net/*/wireless",
		"/sys/class/net/*/phy80211",
	} {
		paths, _ := filepath.Glob(pattern)

		for _, path := range paths {
			found[filepath.Base(filepath.Dir(path))] = true
		}
	}

	if len(found) == 0 && hasCommand("nmcli") {
		if output, err := runCommand(
			5*time.Second,
			"nmcli", "--colors", "no", "-t", "-f", "DEVICE,TYPE", "device",
		); err == nil {
			for _, line := range nonEmptyLines(output) {
				name, kind, ok := strings.Cut(line, ":")

				if !ok || kind != "wifi" {
					continue
				}

				found[strings.TrimSpace(name)] = true
			}
		}
	}

	result := make([]string, 0, len(found))

	for name := range found {
		result = append(result, name)
	}

	sort.Strings(result)

	return result
}

func isWirelessInterface(name string) bool {
	if name == "" || !wirelessInterfaceRegex.MatchString(name) {
		return false
	}

	for _, iface := range getWirelessInterfaces() {
		if iface == name {
			return true
		}
	}

	return false
}

// getHotspotInterface resuelve la interfaz que usa el hotspot segun el backend.
func getHotspotInterface() (string, error) {
	switch detectBackend() {
	case backendNetworkManager:
		if profile, err := nmHotspotProfile(); err == nil {
			if name, fieldErr := nmGetConnectionField(profile, "connection.interface-name"); fieldErr == nil && name != "" {
				if isWirelessInterface(name) {
					return name, nil
				}
			}
		}

		if name := nmActiveAPInterface(); name != "" {
			return name, nil
		}

	case backendHostapd:
		if path, err := findHostapdConfig(); err == nil {
			if values, readErr := readHostapdConfig(path); readErr == nil {
				if name := strings.TrimSpace(values["interface"]); name != "" && isWirelessInterface(name) {
					return name, nil
				}
			}
		}
	}

	interfaces := getWirelessInterfaces()

	if len(interfaces) == 0 {
		return "", errors.New("no se detectaron interfaces Wi-Fi en el sistema")
	}

	return interfaces[0], nil
}

func systemdUnitActive(unit string) bool {
	output, err := runCommand(5*time.Second, "systemctl", "is-active", unit)

	return err == nil && strings.TrimSpace(output) == "active"
}

func systemdUnitState(unit string) string {
	output, err := runCommand(5*time.Second, "systemctl", "is-active", unit)
	state := strings.TrimSpace(output)

	if state == "" {
		return "desconocido"
	}

	if err != nil {
		return state
	}

	return state
}

// ============================================================
// HOTSPOT: ESTADO
// ============================================================

func hotspotStatusHandler(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, collectHotspotStatus())
}

func collectHotspotStatus() HotspotStatus {
	status := HotspotStatus{
		OK:        true,
		Backend:   string(detectBackend()),
		UpdatedAt: time.Now().Format(time.RFC3339),
		Warnings:  make([]string, 0, 4),
	}

	iface, ifaceErr := getHotspotInterface()

	if ifaceErr != nil {
		status.Warnings = append(status.Warnings, ifaceErr.Error())
		status.Clients = 0
		status.clients = []WiFiClient{}
		return status
	}

	status.Interface = iface

	if mac, err := readInterfaceMAC(iface); err == nil {
		status.MAC = mac
	}

	status.Mode = interfaceMode(iface)
	status.IPv4Address = interfaceIPv4(iface)

	switch detectBackend() {
	case backendNetworkManager:
		collectNetworkManagerStatus(&status)

	case backendHostapd:
		collectHostapdStatus(&status)

	default:
		status.Service = "no disponible"
		status.Warnings = append(
			status.Warnings,
			"No se detecto NetworkManager ni hostapd: el panel no puede controlar el Wi-Fi.",
		)
	}

	status.clients = collectClients(status.Interface, status.Enabled)
	status.Clients = len(status.clients)

	if status.Enabled && len(status.IPv4Address) == 0 {
		status.Warnings = append(
			status.Warnings,
			"El punto de acceso esta activo pero la interfaz no tiene direccion IPv4.",
		)
	}

	return status
}

func collectNetworkManagerStatus(status *HotspotStatus) {
	profile, err := nmHotspotProfile()

	if err != nil {
		status.Service = "NetworkManager"
		status.Warnings = append(status.Warnings, err.Error())
		applyPermanentMAC(status)
		return
	}

	status.Profile = profile
	status.Service = "NetworkManager/" + profile

	if value, fieldErr := nmGetConnectionField(profile, "connection.interface-name"); fieldErr == nil && value != "" {
		if isWirelessInterface(value) {
			status.Interface = value

			if mac, macErr := readInterfaceMAC(value); macErr == nil {
				status.MAC = mac
			}

			status.IPv4Address = interfaceIPv4(value)
		}
	}

	if value, fieldErr := nmGetConnectionField(profile, "802-11-wireless.ssid"); fieldErr == nil {
		status.SSID = value
	}

	if value, fieldErr := nmGetConnectionField(profile, "ipv4.method"); fieldErr == nil {
		status.IPv4Method = value
	}

	if value, fieldErr := nmGetConnectionField(profile, "802-11-wireless.band"); fieldErr == nil {
		status.Band = value
	}

	if value, fieldErr := nmGetConnectionField(profile, "802-11-wireless.channel"); fieldErr == nil {
		status.Channel = value
	}

	if keyManagement, fieldErr := nmGetConnectionField(profile, "802-11-wireless-security.key-mgmt"); fieldErr == nil && keyManagement != "" {
		switch strings.ToLower(keyManagement) {
		case "none":
			status.Security = "abierta"
		case "wpa-psk":
			status.Security = "WPA2-PSK"
		default:
			status.Security = keyManagement
		}
	} else {
		status.Security = "abierta"
	}

	status.Enabled = nmConnectionActive(profile)

	applyPermanentMAC(status)

	if status.Enabled {
		status.Mode = "Master"
	}

	if strings.EqualFold(status.IPv4Method, "manual") && status.Enabled {
		status.Warnings = append(
			status.Warnings,
			"El perfil usa ipv4.method=manual: no hay servidor DHCP para los clientes. Usa 'shared' para repartir IP y NAT.",
		)
	}

	if strings.EqualFold(status.Security, "abierta") && status.Enabled {
		status.Warnings = append(
			status.Warnings,
			"El punto de acceso esta abierto (sin contrasena): cualquier dispositivo dentro del alcance puede conectarse.",
		)
	}

	if len(getWirelessInterfaces()) == 1 && status.Enabled {
		status.Warnings = append(
			status.Warnings,
			"El dispositivo tiene una sola interfaz Wi-Fi: mientras el hotspot esta encendido no puede usarse como cliente (uplink).",
		)
	}
}

func collectHostapdStatus(status *HotspotStatus) {
	status.Service = hostapdService
	status.Enabled = systemdUnitActive(hostapdService)
	status.Mode = "Master"

	path, err := findHostapdConfig()

	if err != nil {
		status.Warnings = append(status.Warnings, err.Error())
		return
	}

	values, err := readHostapdConfig(path)

	if err != nil {
		status.Warnings = append(status.Warnings, err.Error())
		return
	}

	if values["ssid"] != "" {
		status.SSID = values["ssid"]
	}

	if values["wpa_passphrase"] != "" {
		status.Security = "WPA2-PSK"
	} else {
		status.Security = "abierta"
	}

	applyPermanentMAC(status)
}

func applyPermanentMAC(status *HotspotStatus) {
	if status.Interface == "" {
		return
	}

	if detectBackend() == backendNetworkManager {
		// Si el controlador no expone la MAC de hardware (por ejemplo cuando
		// la interfaz usa una MAC aleatoria) el campo queda vacio: no se
		// inventa un valor ni se asume que la MAC efectiva es la permanente.
		if value := permanentMAC(status.Interface); value != "" {
			status.PermanentMAC = value
		}
	}
}

// ============================================================
// HOTSPOT: CONTROL (ENCENDER / APAGAR)
// ============================================================

var hotspotOpMu sync.Mutex

// acquireHotspotOp evita operaciones administrativas simultaneas sin
// bloquear las consultas de solo lectura (estado, clientes, diagnostico).
func acquireHotspotOp(w http.ResponseWriter) bool {
	if !hotspotOpMu.TryLock() {
		w.Header().Set("Retry-After", "3")
		writeError(
			w,
			http.StatusConflict,
			"Ya hay una operacion administrativa en curso. Espera a que termine.",
		)
		return false
	}

	return true
}

func hotspotEnableHandler(w http.ResponseWriter) {
	if !acquireHotspotOp(w) {
		return
	}
	defer hotspotOpMu.Unlock()

	switch detectBackend() {
	case backendNetworkManager:
		nmHotspotEnable(w)

	case backendHostapd:
		hostapdEnable(w)

	default:
		writeError(
			w,
			http.StatusServiceUnavailable,
			"No hay backend Wi-Fi disponible (ni NetworkManager ni hostapd).",
		)
	}
}

func hotspotDisableHandler(w http.ResponseWriter) {
	if !acquireHotspotOp(w) {
		return
	}
	defer hotspotOpMu.Unlock()

	switch detectBackend() {
	case backendNetworkManager:
		nmHotspotDisable(w)

	case backendHostapd:
		hostapdDisable(w)

	default:
		writeError(
			w,
			http.StatusServiceUnavailable,
			"No hay backend Wi-Fi disponible (ni NetworkManager ni hostapd).",
		)
	}
}

func nmHotspotEnable(w http.ResponseWriter) {
	profile, err := nmHotspotProfile()

	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	if nmConnectionActive(profile) {
		writeJSON(w, http.StatusOK, APIResponse{
			OK:      true,
			Message: "El hotspot ya estaba encendido",
			Data:    collectHotspotStatus(),
		})
		return
	}

	output, err := runCommand(
		40*time.Second,
		"nmcli", "--colors", "no", "connection", "up", profile,
	)

	if err != nil {
		log.Printf("[HOTSPOT] Error activando el perfil %q: %s", profile, output)
		writeError(
			w,
			http.StatusInternalServerError,
			commandError("No se pudo activar el hotspot con NetworkManager", output, err),
		)
		return
	}

	if !waitForConnectionState(profile, true, 8*time.Second) {
		writeError(
			w,
			http.StatusInternalServerError,
			"NetworkManager acepto la activacion pero el hotspot no figura como activo. Revisa el diagnostico.",
		)
		return
	}

	status := collectHotspotStatus()

	log.Printf("[HOTSPOT] Hotspot activado en %s (SSID %q)", status.Interface, status.SSID)

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Hotspot encendido correctamente",
		Data:    status,
	})
}

func nmHotspotDisable(w http.ResponseWriter) {
	profile, err := nmHotspotProfile()

	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	if !nmConnectionActive(profile) {
		writeJSON(w, http.StatusOK, APIResponse{
			OK:      true,
			Message: "El hotspot ya estaba apagado",
			Data:    collectHotspotStatus(),
		})
		return
	}

	output, err := runCommand(
		30*time.Second,
		"nmcli", "--colors", "no", "connection", "down", profile,
	)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			commandError("No se pudo desactivar el hotspot", output, err),
		)
		return
	}

	if !waitForConnectionState(profile, false, 8*time.Second) {
		writeError(
			w,
			http.StatusInternalServerError,
			"El hotspot sigue figurando como activo despues de desactivarlo.",
		)
		return
	}

	log.Println("[HOTSPOT] Hotspot desactivado")

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Hotspot apagado correctamente",
		Data:    collectHotspotStatus(),
	})
}

func waitForConnectionState(profile string, expected bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for {
		if nmConnectionActive(profile) == expected {
			return true
		}

		if time.Now().After(deadline) {
			return false
		}

		time.Sleep(400 * time.Millisecond)
	}
}

func hostapdEnable(w http.ResponseWriter) {
	path, err := findHostapdConfig()

	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	if !fileExists(path) {
		writeError(w, http.StatusServiceUnavailable, "No existe la configuracion de hostapd")
		return
	}

	if !hasCommand("systemctl") {
		writeError(w, http.StatusServiceUnavailable, "systemctl no esta disponible")
		return
	}

	if systemdUnitActive(hostapdService) {
		writeJSON(w, http.StatusOK, APIResponse{
			OK:      true,
			Message: "El hotspot ya estaba encendido",
			Data:    collectHotspotStatus(),
		})
		return
	}

	output, err := runCommand(20*time.Second, "systemctl", "start", hostapdService)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			commandError("No se pudo iniciar hostapd", output, err),
		)
		return
	}

	time.Sleep(2 * time.Second)

	if !systemdUnitActive(hostapdService) {
		output, _ = runCommand(6*time.Second, "journalctl", "-u", hostapdService, "-n", "20", "--no-pager")
		writeError(
			w,
			http.StatusInternalServerError,
			commandError("hostapd no quedo activo", output, errors.New("servicio inactivo")),
		)
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Hotspot encendido correctamente",
		Data:    collectHotspotStatus(),
	})
}

func hostapdDisable(w http.ResponseWriter) {
	if !hasCommand("systemctl") {
		writeError(w, http.StatusServiceUnavailable, "systemctl no esta disponible")
		return
	}

	output, err := runCommand(20*time.Second, "systemctl", "stop", hostapdService)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			commandError("No se pudo detener hostapd", output, err),
		)
		return
	}

	if systemdUnitActive(hostapdService) {
		writeError(w, http.StatusInternalServerError, "hostapd sigue activo despues de detenerlo")
		return
	}

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Hotspot apagado correctamente",
		Data:    collectHotspotStatus(),
	})
}

// ============================================================
// HOTSPOT: CONFIGURACION
// ============================================================

func hotspotGetConfigHandler(w http.ResponseWriter) {
	status := collectHotspotStatus()

	passwordConfigured := false
	securityMode := ""

	switch detectBackend() {
	case backendNetworkManager:
		if status.Profile != "" {
			securityMode = nmSecurityMode(status.Profile)

			if keyManagement, err := nmGetConnectionField(status.Profile, "802-11-wireless-security.key-mgmt"); err == nil && keyManagement != "" && !strings.EqualFold(keyManagement, "none") {
				passwordConfigured = true
			}
		}

	case backendHostapd:
		securityMode = "open"

		if path, err := findHostapdConfig(); err == nil {
			if values, readErr := readHostapdConfig(path); readErr == nil && values["wpa_passphrase"] != "" {
				passwordConfigured = true
				securityMode = "wpa2"
			}
		}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		OK: true,
		Data: map[string]interface{}{
			"backend":             status.Backend,
			"profile":             status.Profile,
			"interface":           status.Interface,
			"ssid":                status.SSID,
			"passwordConfigured":  passwordConfigured,
			"security":            status.Security,
			"securityMode":        securityMode,
			"ipv4Method":          status.IPv4Method,
			"ipv4Address":         status.IPv4Address,
			"band":                status.Band,
			"channel":             status.Channel,
			"mac":                 status.MAC,
			"permanentMac":        status.PermanentMAC,
			"enabled":             status.Enabled,
			"availableInterfaces": getWirelessInterfaces(),
			"warnings":            status.Warnings,
		},
	})
}

func hotspotSetConfigHandler(w http.ResponseWriter, r *http.Request) {
	var request HotspotConfigRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	request.SSID = strings.TrimSpace(request.SSID)
	request.Interface = strings.TrimSpace(request.Interface)
	request.IPv4Method = strings.ToLower(strings.TrimSpace(request.IPv4Method))
	request.Security = strings.ToLower(strings.TrimSpace(request.Security))

	if request.Security != "" && request.Security != "open" && request.Security != "wpa2" {
		writeError(w, http.StatusBadRequest, "Modo de seguridad no valido: usa 'open' o 'wpa2'")
		return
	}

	if request.Security == "open" && request.Password != "" {
		writeError(w, http.StatusBadRequest, "Una red abierta no admite contrasena: deja el campo vacio")
		return
	}

	if request.SSID != "" {
		if len([]byte(request.SSID)) > 32 {
			writeError(w, http.StatusBadRequest, "El SSID no puede superar 32 bytes")
			return
		}

		if containsControlChars(request.SSID) {
			writeError(w, http.StatusBadRequest, "El SSID contiene caracteres no permitidos")
			return
		}
	}

	if request.Password != "" {
		if len([]byte(request.Password)) < 8 || len([]byte(request.Password)) > 63 {
			writeError(w, http.StatusBadRequest, "La contrasena WPA debe tener entre 8 y 63 bytes")
			return
		}

		if containsControlChars(request.Password) {
			writeError(w, http.StatusBadRequest, "La contrasena contiene caracteres no permitidos")
			return
		}
	}

	if request.Interface != "" && !isWirelessInterface(request.Interface) {
		writeError(w, http.StatusBadRequest, "La interfaz indicada no es una interfaz Wi-Fi disponible")
		return
	}

	if request.IPv4Method != "" && request.IPv4Method != "manual" && request.IPv4Method != "shared" {
		writeError(w, http.StatusBadRequest, "Metodo IPv4 no valido: usa 'manual' o 'shared'")
		return
	}

	if request.SSID == "" && request.Password == "" && request.Interface == "" && request.IPv4Method == "" && request.Security == "" {
		writeError(w, http.StatusBadRequest, "No se recibio ningun cambio de configuracion")
		return
	}

	if !acquireHotspotOp(w) {
		return
	}
	defer hotspotOpMu.Unlock()

	switch detectBackend() {
	case backendNetworkManager:
		nmSetConfig(w, request)

	case backendHostapd:
		hostapdSetConfig(w, request)

	default:
		writeError(
			w,
			http.StatusServiceUnavailable,
			"No hay backend Wi-Fi disponible (ni NetworkManager ni hostapd).",
		)
	}
}

func containsControlChars(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}

	return false
}

type configChange struct {
	Field  string `json:"field"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Secure bool   `json:"secure,omitempty"`
}

func nmSetConfig(w http.ResponseWriter, request HotspotConfigRequest) {
	profile, err := nmHotspotProfile()

	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	currentSSID, _ := nmGetConnectionField(profile, "802-11-wireless.ssid")
	currentInterface, _ := nmGetConnectionField(profile, "connection.interface-name")
	currentMethod, _ := nmGetConnectionField(profile, "ipv4.method")
	currentKeyManagement, _ := nmGetConnectionField(profile, "802-11-wireless-security.key-mgmt")

	currentOpen := currentKeyManagement == "" || strings.EqualFold(currentKeyManagement, "none")

	targetSecurity := request.Security

	if targetSecurity == "" {
		switch {
		case request.Password != "":
			targetSecurity = "wpa2"
		case currentOpen:
			targetSecurity = "open"
		default:
			targetSecurity = "wpa2"
		}
	}

	if targetSecurity == "wpa2" && currentOpen && request.Password == "" {
		writeError(
			w,
			http.StatusBadRequest,
			"Para activar WPA2 hace falta una contrasena de 8 a 63 caracteres.",
		)
		return
	}

	args := []string{"--colors", "no", "connection", "modify", profile}
	changes := make([]configChange, 0, 5)

	if request.SSID != "" && request.SSID != currentSSID {
		args = append(args, "802-11-wireless.ssid", request.SSID)
		changes = append(changes, configChange{Field: "ssid", From: currentSSID, To: request.SSID})
	}

	if request.Interface != "" && request.Interface != currentInterface {
		args = append(args, "connection.interface-name", request.Interface)
		changes = append(changes, configChange{Field: "interface", From: currentInterface, To: request.Interface})
	}

	if request.IPv4Method != "" && request.IPv4Method != currentMethod {
		args = append(args, "ipv4.method", request.IPv4Method)
		changes = append(changes, configChange{Field: "ipv4Method", From: currentMethod, To: request.IPv4Method})
	}

	passwordChanged := false
	openChanged := false

	if targetSecurity == "open" {
		if !currentOpen {
			openChanged = true
			changes = append(changes, configChange{Field: "security", From: "WPA2-PSK", To: "abierta"})
		}
	} else if request.Password != "" {
		passwordChanged = true

		if currentOpen {
			changes = append(changes, configChange{Field: "security", From: "abierta", To: "WPA2-PSK"})
		}

		changes = append(changes, configChange{Field: "password", To: "(oculta)", Secure: true})
	}

	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, APIResponse{
			OK:      true,
			Message: "Sin cambios: los valores enviados ya estaban configurados",
			Data: map[string]interface{}{
				"changed":  []configChange{},
				"verified": true,
				"status":   collectHotspotStatus(),
			},
		})
		return
	}

	if len(args) > 5 {
		output, err := runCommand(15*time.Second, "nmcli", args...)

		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				commandError("NetworkManager rechazo la configuracion", output, err),
			)
			return
		}
	}

	if openChanged {
		if err := nmSetOpenSecurity(profile); err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"No se pudo dejar la red abierta: "+err.Error(),
			)
			return
		}
	}

	if targetSecurity == "wpa2" && (currentOpen || request.Password != "") {
		password := request.Password

		if password == "" {
			password, _ = nmGetSecretField(profile, "802-11-wireless-security.psk")
		}

		if password != "" {
			if err := nmSetWPASecurity(profile, password); err != nil {
				writeError(
					w,
					http.StatusInternalServerError,
					"No se pudo configurar WPA2: "+err.Error(),
				)
				return
			}
		}
	}

	wasActive := nmConnectionActive(profile)

	if wasActive {
		_, _ = runCommand(20*time.Second, "nmcli", "--colors", "no", "connection", "down", profile)

		if output, err := runCommand(40*time.Second, "nmcli", "--colors", "no", "connection", "up", profile); err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				commandError("La configuracion se guardo, pero el hotspot no pudo reactivarse", output, err),
			)
			return
		}

		if !waitForConnectionState(profile, true, 8*time.Second) {
			writeError(
				w,
				http.StatusInternalServerError,
				"La configuracion se guardo, pero el hotspot no figura como activo.",
			)
			return
		}
	}

	// Verificacion real de lo aplicado.
	verificationErrors := make([]string, 0, 2)

	if newSSID, fieldErr := nmGetConnectionField(profile, "802-11-wireless.ssid"); fieldErr == nil && request.SSID != "" && newSSID != request.SSID {
		verificationErrors = append(
			verificationErrors,
			fmt.Sprintf("El SSID quedo como %q en lugar de %q", newSSID, request.SSID),
		)
	}

	if newInterface, fieldErr := nmGetConnectionField(profile, "connection.interface-name"); fieldErr == nil && request.Interface != "" && newInterface != request.Interface {
		verificationErrors = append(
			verificationErrors,
			fmt.Sprintf("La interfaz quedo como %q en lugar de %q", newInterface, request.Interface),
		)
	}

	if newMethod, fieldErr := nmGetConnectionField(profile, "ipv4.method"); fieldErr == nil && request.IPv4Method != "" && newMethod != request.IPv4Method {
		verificationErrors = append(
			verificationErrors,
			fmt.Sprintf("El metodo IPv4 quedo como %q en lugar de %q", newMethod, request.IPv4Method),
		)
	}

	if passwordChanged {
		if newPassword, fieldErr := nmGetSecretField(profile, "802-11-wireless-security.psk"); fieldErr != nil || newPassword != request.Password {
			verificationErrors = append(verificationErrors, "La contrasena no quedo guardada en el perfil")
		}
	}

	if targetSecurity == "open" {
		newKeyManagement, _ := nmGetConnectionField(profile, "802-11-wireless-security.key-mgmt")

		if newKeyManagement != "" && !strings.EqualFold(newKeyManagement, "none") {
			verificationErrors = append(
				verificationErrors,
				"El perfil sigue usando seguridad "+newKeyManagement,
			)
		}

		if newPassword, fieldErr := nmGetSecretField(profile, "802-11-wireless-security.psk"); fieldErr == nil && newPassword != "" {
			verificationErrors = append(verificationErrors, "El perfil abierto conserva una contrasena guardada")
		}
	}

	if targetSecurity == "wpa2" {
		newKeyManagement, _ := nmGetConnectionField(profile, "802-11-wireless-security.key-mgmt")

		if !strings.EqualFold(newKeyManagement, "wpa-psk") {
			verificationErrors = append(verificationErrors, "El perfil no quedo con key-mgmt wpa-psk")
		}

		if request.Password != "" {
			if newPassword, fieldErr := nmGetSecretField(profile, "802-11-wireless-security.psk"); fieldErr != nil || newPassword != request.Password {
				verificationErrors = append(verificationErrors, "La contrasena no quedo guardada en el perfil")
			}
		}
	}

	if len(verificationErrors) > 0 {
		writeError(
			w,
			http.StatusInternalServerError,
			"La configuracion no se aplico por completo: "+strings.Join(verificationErrors, "; "),
		)
		return
	}

	invalidateNMCache()

	status := collectHotspotStatus()

	log.Printf("[HOTSPOT] Configuracion actualizada: %d cambio(s)", len(changes))

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Configuracion guardada y verificada correctamente",
		Data: map[string]interface{}{
			"changed":  changes,
			"verified": true,
			"active":   status.Enabled,
			"status":   status,
		},
	})
}

func hostapdSetConfig(w http.ResponseWriter, request HotspotConfigRequest) {
	path, err := findHostapdConfig()

	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	current, err := readHostapdConfig(path)

	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	entries := make([]configEntry, 0, 6)
	changes := make([]configChange, 0, 3)

	if request.SSID != "" && request.SSID != current["ssid"] {
		entries = append(entries, configEntry{Key: "ssid", Value: request.SSID})
		changes = append(changes, configChange{Field: "ssid", From: current["ssid"], To: request.SSID})
	}

	if request.Interface != "" && request.Interface != current["interface"] {
		entries = append(entries, configEntry{Key: "interface", Value: request.Interface})
		changes = append(changes, configChange{Field: "interface", From: current["interface"], To: request.Interface})
	}

	if request.Password != "" {
		entries = append(entries,
			configEntry{Key: "wpa", Value: "2"},
			configEntry{Key: "wpa_key_mgmt", Value: "WPA-PSK"},
			configEntry{Key: "rsn_pairwise", Value: "CCMP"},
			configEntry{Key: "wpa_passphrase", Value: request.Password},
		)
		changes = append(changes, configChange{Field: "password", To: "(oculta)", Secure: true})
	}

	if len(changes) == 0 {
		writeJSON(w, http.StatusOK, APIResponse{
			OK:      true,
			Message: "Sin cambios: los valores enviados ya estaban configurados",
			Data:    map[string]interface{}{"changed": []configChange{}, "verified": true},
		})
		return
	}

	if err := updateHostapdConfig(path, entries); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if systemdUnitActive(hostapdService) {
		if output, err := runCommand(25*time.Second, "systemctl", "restart", hostapdService); err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				commandError("La configuracion se guardo, pero hostapd no pudo reiniciarse", output, err),
			)
			return
		}

		time.Sleep(time.Second)

		if !systemdUnitActive(hostapdService) {
			writeError(w, http.StatusInternalServerError, "La configuracion se guardo, pero hostapd no quedo activo")
			return
		}
	}

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Configuracion guardada y verificada correctamente",
		Data: map[string]interface{}{
			"changed":  changes,
			"verified": true,
			"status":   collectHotspotStatus(),
		},
	})
}

// ============================================================
// HOTSPOT: CONFIGURACION DE HOSTAPD (BACKEND ALTERNATIVO)
// ============================================================

func findHostapdConfig() (string, error) {
	if custom := strings.TrimSpace(os.Getenv(envHostapdConfig)); custom != "" {
		if fileExists(custom) {
			return custom, nil
		}

		return "", fmt.Errorf("no existe OPENSTICK_HOSTAPD_CONFIG: %s", custom)
	}

	for _, path := range []string{
		"/etc/hostapd/hostapd.conf",
		"/etc/hostapd.conf",
	} {
		if fileExists(path) {
			return path, nil
		}
	}

	return "", errors.New("no se encontro la configuracion de hostapd (/etc/hostapd/hostapd.conf)")
}

func readHostapdConfig(path string) (map[string]string, error) {
	content, err := os.ReadFile(path)

	if err != nil {
		return nil, err
	}

	values := make(map[string]string)

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, found := strings.Cut(line, "=")

		if found {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	return values, nil
}

func updateHostapdConfig(path string, entries []configEntry) error {
	content, err := os.ReadFile(path)

	if err != nil {
		return err
	}

	info, err := os.Stat(path)

	if err != nil {
		return err
	}

	backupPath := path + ".bak"

	if err := os.WriteFile(backupPath, content, info.Mode().Perm()); err != nil {
		return fmt.Errorf("no se pudo crear la copia de seguridad: %w", err)
	}

	updates := make(map[string]string)

	for _, entry := range entries {
		updates[entry.Key] = entry.Value
	}

	seen := make(map[string]bool)
	lines := strings.Split(string(content), "\n")
	result := make([]string, 0, len(lines)+len(entries))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			result = append(result, line)
			continue
		}

		key, _, found := strings.Cut(trimmed, "=")

		if !found {
			result = append(result, line)
			continue
		}

		key = strings.TrimSpace(key)
		value, exists := updates[key]

		if !exists {
			result = append(result, line)
			continue
		}

		if !seen[key] {
			result = append(result, key+"="+value)
			seen[key] = true
		}
	}

	for _, entry := range entries {
		if !seen[entry.Key] {
			result = append(result, entry.Key+"="+entry.Value)
		}
	}

	tempPath := path + ".tmp"

	if err := os.WriteFile(tempPath, []byte(strings.Join(result, "\n")), info.Mode().Perm()); err != nil {
		return err
	}

	if err := os.Chmod(tempPath, info.Mode().Perm()); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	return nil
}

// ============================================================
// HOTSPOT: DIRECCION MAC
// ============================================================

type macResult struct {
	Interface    string `json:"interface"`
	Backend      string `json:"backend"`
	Profile      string `json:"profile,omitempty"`
	RequestedMAC string `json:"requestedMac"`
	EffectiveMAC string `json:"effectiveMac,omitempty"`
	PreviousMAC  string `json:"previousMac,omitempty"`
	Applied      bool   `json:"applied"`
	Verified     bool   `json:"verified"`
	Persistent   bool   `json:"persistent"`
	Temporary    bool   `json:"temporary"`
	Pending      bool   `json:"pending"`
	Note         string `json:"note,omitempty"`
}

// parseMAC valida y normaliza una direccion MAC unicast de 48 bits.
func parseMAC(value string) (net.HardwareAddr, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		return nil, errors.New("la direccion MAC esta vacia")
	}

	hardware, err := net.ParseMAC(value)

	if err != nil || len(hardware) != 6 {
		return nil, errors.New("formato de MAC invalido (se espera AA:BB:CC:DD:EE:FF)")
	}

	if hardware[0]&0x01 != 0 {
		return nil, errors.New("la MAC no puede ser multicast ni broadcast")
	}

	zero := true

	for _, octet := range hardware {
		if octet != 0 {
			zero = false
			break
		}
	}

	if zero {
		return nil, errors.New("la MAC no puede ser 00:00:00:00:00:00")
	}

	return hardware, nil
}

func hotspotGetMACHandler(w http.ResponseWriter, r *http.Request) {
	iface := strings.TrimSpace(r.URL.Query().Get("interface"))

	var err error

	if iface == "" {
		iface, err = getHotspotInterface()

		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
	}

	if !isWirelessInterface(iface) {
		writeError(w, http.StatusBadRequest, "La interfaz indicada no es una interfaz Wi-Fi disponible")
		return
	}

	mac, err := readInterfaceMAC(iface)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "No se pudo leer la MAC de "+iface+": "+err.Error())
		return
	}

	data := map[string]interface{}{
		"interface":           iface,
		"mac":                 mac,
		"backend":             string(detectBackend()),
		"multicast":           isMulticastMAC(mac),
		"locallyAdministered": isLocallyAdministeredMAC(mac),
	}

	if hardware, parseErr := net.ParseMAC(mac); parseErr == nil && len(hardware) == 6 {
		data["broadcast"] = hardware[0] == 0xff && hardware[1] == 0xff && hardware[2] == 0xff &&
			hardware[3] == 0xff && hardware[4] == 0xff && hardware[5] == 0xff
	}

	if detectBackend() == backendNetworkManager {
		if value := permanentMAC(iface); value != "" {
			data["permanentMac"] = value
		}

		data["addrAssignType"] = readInterfaceString(iface, "addr_assign_type")

		if profile, profileErr := nmProfileForInterface(iface); profileErr == nil {
			data["profile"] = profile

			if cloned, cloneErr := nmGetConnectionField(profile, "802-11-wireless.cloned-mac-address"); cloneErr == nil {
				data["clonedMacAddress"] = cloned
			}
		}
	}

	writeJSON(w, http.StatusOK, APIResponse{OK: true, Data: data})
}

func isMulticastMAC(value string) bool {
	hardware, err := net.ParseMAC(value)

	return err != nil || hardware[0]&0x01 != 0
}

func isLocallyAdministeredMAC(value string) bool {
	hardware, err := net.ParseMAC(value)

	return err == nil && hardware[0]&0x02 != 0
}

func hotspotSetMACHandler(w http.ResponseWriter, r *http.Request) {
	var request MACRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	request.Interface = strings.TrimSpace(request.Interface)

	hardware, err := parseMAC(request.MAC)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	target := strings.ToLower(hardware.String())

	if !acquireHotspotOp(w) {
		return
	}
	defer hotspotOpMu.Unlock()

	iface := request.Interface

	if iface == "" {
		iface, err = getHotspotInterface()

		if err != nil {
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
	}

	if !isWirelessInterface(iface) {
		writeError(w, http.StatusBadRequest, "La interfaz indicada no es una interfaz Wi-Fi disponible")
		return
	}

	previous, _ := readInterfaceMAC(iface)
	backend := detectBackend()

	if strings.EqualFold(previous, target) {
		writeJSON(w, http.StatusOK, APIResponse{
			OK:      true,
			Message: "La MAC indicada ya es la MAC efectiva de la interfaz",
			Data: macResult{
				Interface:    iface,
				Backend:      string(backend),
				RequestedMAC: target,
				EffectiveMAC: previous,
				PreviousMAC:  previous,
				Applied:      false,
				Verified:     true,
				Persistent:   true,
				Note:         "No fue necesario ningun cambio.",
			},
		})
		return
	}

	if backend == backendNetworkManager {
		applyMACNetworkManager(w, iface, target, previous)

		return
	}

	applyMACDirect(w, iface, target, previous, backend)
}

func applyMACNetworkManager(w http.ResponseWriter, iface, target, previous string) {
	profile, err := nmProfileForInterface(iface)

	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	previousClone, _ := nmGetConnectionField(profile, "802-11-wireless.cloned-mac-address")
	active := nmConnectionActive(profile)

	output, err := runCommand(
		12*time.Second,
		"nmcli", "--colors", "no", "connection", "modify", profile,
		"802-11-wireless.cloned-mac-address", target,
	)

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			commandError("NetworkManager rechazo el cambio de MAC", output, err),
		)
		return
	}

	invalidateNMCache()

	result := macResult{
		Interface:    iface,
		Backend:      string(backendNetworkManager),
		Profile:      profile,
		RequestedMAC: target,
		PreviousMAC:  previous,
		Persistent:   true,
	}

	if !active {
		result.Pending = true
		result.Note = "MAC guardada en el perfil de NetworkManager. Se aplicara al encender el hotspot y persiste tras reiniciar."

		writeJSON(w, http.StatusOK, APIResponse{
			OK:      true,
			Message: "MAC guardada en el perfil (pendiente de aplicar al encender el hotspot)",
			Data:    result,
		})
		return
	}

	_, _ = runCommand(20*time.Second, "nmcli", "--colors", "no", "connection", "down", profile)

	if output, err := runCommand(40*time.Second, "nmcli", "--colors", "no", "connection", "up", profile); err != nil {
		restoreClonedMAC(profile, previousClone)

		writeError(
			w,
			http.StatusInternalServerError,
			commandError("La MAC se guardo, pero el hotspot no pudo reactivarse; se restauro el valor anterior", output, err),
		)
		return
	}

	effective, applied := waitForMAC(iface, target, 15*time.Second)

	result.EffectiveMAC = effective

	if !applied {
		restoreClonedMAC(profile, previousClone)

		writeError(
			w,
			http.StatusInternalServerError,
			"El controlador no aplico la MAC solicitada: la interfaz quedo en "+effective+". Se restauro el valor anterior.",
		)
		return
	}

	result.Applied = true
	result.Verified = true
	result.Note = "MAC aplicada y verificada en /sys/class/net. Persistente en el perfil de NetworkManager."

	log.Printf("[HOTSPOT] MAC de %s cambiada a %s", iface, effective)

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Direccion MAC aplicada y verificada",
		Data:    result,
	})
}

func restoreClonedMAC(profile, previousClone string) {
	_, _ = runCommand(
		12*time.Second,
		"nmcli", "--colors", "no", "connection", "modify", profile,
		"802-11-wireless.cloned-mac-address", previousClone,
	)

	_, _ = runCommand(20*time.Second, "nmcli", "--colors", "no", "connection", "down", profile)
	_, _ = runCommand(40*time.Second, "nmcli", "--colors", "no", "connection", "up", profile)

	invalidateNMCache()
}

func waitForMAC(iface, target string, timeout time.Duration) (string, bool) {
	deadline := time.Now().Add(timeout)
	last := ""

	for {
		if mac, err := readInterfaceMAC(iface); err == nil {
			last = mac

			if strings.EqualFold(mac, target) {
				return mac, true
			}
		}

		if time.Now().After(deadline) {
			return last, false
		}

		time.Sleep(300 * time.Millisecond)
	}
}

func applyMACDirect(w http.ResponseWriter, iface, target, previous string, backend wifiBackend) {
	effective, err := setMACDirect(iface, target)

	result := macResult{
		Interface:    iface,
		Backend:      string(backend),
		RequestedMAC: target,
		PreviousMAC:  previous,
		EffectiveMAC: effective,
		Temporary:    true,
		Note:         "Cambio aplicado solo en tiempo de ejecucion: no persiste tras reiniciar.",
	}

	if err != nil {
		writeError(
			w,
			http.StatusInternalServerError,
			"No se pudo aplicar la MAC: "+err.Error(),
		)
		return
	}

	result.Applied = true
	result.Verified = true

	writeJSON(w, http.StatusOK, APIResponse{
		OK:      true,
		Message: "Direccion MAC aplicada y verificada (cambio temporal)",
		Data:    result,
	})
}

// setMACDirect cambia la MAC usando iproute2 o net-tools y verifica el
// resultado leyendo /sys/class/net/<iface>/address.
func setMACDirect(iface, target string) (string, error) {
	var output string
	var err error

	switch {
	case hasCommand("ip"):
		_, _ = runCommand(6*time.Second, "ip", "link", "set", "dev", iface, "down")
		output, err = runCommand(6*time.Second, "ip", "link", "set", "dev", iface, "address", target)
		_, _ = runCommand(6*time.Second, "ip", "link", "set", "dev", iface, "up")

	case hasCommand("ifconfig"):
		_, _ = runCommand(6*time.Second, "ifconfig", iface, "down")
		output, err = runCommand(6*time.Second, "ifconfig", iface, "hw", "ether", target)
		_, _ = runCommand(6*time.Second, "ifconfig", iface, "up")

	default:
		return "", errors.New("no hay 'ip' ni 'ifconfig' disponibles para cambiar la MAC")
	}

	if err != nil {
		return "", errors.New(commandError("el comando del sistema fallo", output, err))
	}

	time.Sleep(500 * time.Millisecond)

	effective, readErr := readInterfaceMAC(iface)

	if readErr != nil {
		return "", readErr
	}

	if !strings.EqualFold(effective, target) {
		return effective, fmt.Errorf(
			"el controlador no aplico la MAC (la interfaz sigue en %s)",
			effective,
		)
	}

	return effective, nil
}

// ============================================================
// HOTSPOT: CLIENTES CONECTADOS
// ============================================================

type clientAccumulator struct {
	ip        string
	hostname  string
	signal    string
	expiresIn string
	station   bool
	dhcp      bool
	arp       bool
}

func ensureClient(accumulators map[string]*clientAccumulator, order *[]string, mac string) *clientAccumulator {
	accumulator, found := accumulators[mac]

	if !found {
		accumulator = &clientAccumulator{}
		accumulators[mac] = accumulator
		*order = append(*order, mac)
	}

	return accumulator
}

func hotspotClientsHandler(w http.ResponseWriter) {
	status := collectHotspotStatus()

	sources := clientSourceAvailability(status.Interface)
	warnings := make([]string, 0, 2)

	if !status.Enabled {
		warnings = append(warnings, "El hotspot esta apagado: no hay clientes asociados.")
	}

	if status.Enabled && !sources["station"] {
		warnings = append(
			warnings,
			"iw no esta disponible: los clientes se infieren de las concesiones DHCP y de la tabla ARP real del dispositivo.",
		)
	}

	writeJSON(w, http.StatusOK, ClientsResponse{
		OK:        true,
		Total:     len(status.clients),
		Clients:   status.clients,
		Available: status.Enabled,
		Interface: status.Interface,
		Sources:   sources,
		Warnings:  warnings,
	})
}

func collectClients(iface string, enabled bool) []WiFiClient {
	result := make([]WiFiClient, 0, 8)

	if iface == "" || !enabled {
		return result
	}

	accumulators := make(map[string]*clientAccumulator)
	order := make([]string, 0, 8)

	// 1) Estaciones asociadas via nl80211 (si iw esta disponible).
	if hasCommand("iw") {
		if output, err := runCommand(6*time.Second, "iw", "dev", iface, "station", "dump"); err == nil {
			current := ""

			for _, line := range strings.Split(output, "\n") {
				trimmed := strings.TrimSpace(line)
				fields := strings.Fields(trimmed)

				if len(fields) >= 2 && fields[0] == "Station" {
					current = strings.ToLower(fields[1])

					if _, err := parseMAC(current); err != nil {
						current = ""
						continue
					}

					ensureClient(accumulators, &order, current).station = true

					continue
				}

				if current != "" && strings.HasPrefix(trimmed, "signal:") {
					accumulators[current].signal = strings.TrimSpace(strings.TrimPrefix(trimmed, "signal:"))
				}
			}
		}
	}

	// 2) Concesiones DHCP (solo aportan IP/nombre si hay servidor DHCP).
	for _, lease := range readDHCPLeases(iface) {
		if _, err := parseMAC(lease.MAC); err != nil {
			continue
		}

		accumulator := ensureClient(accumulators, &order, lease.MAC)
		accumulator.dhcp = true

		if accumulator.ip == "" {
			accumulator.ip = lease.IP
		}

		if accumulator.hostname == "" && lease.Hostname != "" && lease.Hostname != "*" {
			accumulator.hostname = lease.Hostname
		}

		if lease.ExpiresIn != "" {
			accumulator.expiresIn = lease.ExpiresIn
		}
	}

	// 3) Tabla ARP real del dispositivo, limitada a la interfaz del hotspot.
	for _, entry := range readARPEntries(iface) {
		accumulator := ensureClient(accumulators, &order, entry.MAC)
		accumulator.arp = true

		if accumulator.ip == "" {
			accumulator.ip = entry.IP
		}
	}

	for _, mac := range order {
		accumulator := accumulators[mac]

		sourceParts := make([]string, 0, 3)

		if accumulator.station {
			sourceParts = append(sourceParts, "nl80211")
		}

		if accumulator.dhcp {
			sourceParts = append(sourceParts, "dhcp")
		}

		if accumulator.arp {
			sourceParts = append(sourceParts, "arp")
		}

		// Sin nl80211 (iw) no existe una fuente autoritativa de asociacion.
		// Solo se marca conectado lo confirmado por ARP (trafico real y
		// reciente en la interfaz del hotspot). Una concesion DHCP aislada
		// puede estar caducada y se muestra como observada.
		connected := accumulator.station || accumulator.arp

		result = append(result, WiFiClient{
			MAC:       mac,
			IP:        accumulator.ip,
			Interface: iface,
			Connected: connected,
			Source:    strings.Join(sourceParts, "+"),
			Hostname:  accumulator.hostname,
			Signal:    accumulator.signal,
			ExpiresIn: accumulator.expiresIn,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].MAC < result[j].MAC
	})

	return result
}

func clientSourceAvailability(iface string) map[string]bool {
	return map[string]bool{
		"station": hasCommand("iw"),
		"dhcp":    len(readDHCPLeases(iface)) > 0,
		"arp":     hasCommand("cat") || fileExists("/proc/net/arp"),
	}
}

type dhcpLease struct {
	MAC       string
	IP        string
	Hostname  string
	ExpiresIn string
}

// interfaceSubnets devuelve las redes IPv4 configuradas en una interfaz.
func interfaceSubnets(iface string) []*net.IPNet {
	device, err := net.InterfaceByName(iface)

	if err != nil {
		return nil
	}

	addresses, err := device.Addrs()

	if err != nil {
		return nil
	}

	subnets := make([]*net.IPNet, 0, len(addresses))

	for _, address := range addresses {
		network, ok := address.(*net.IPNet)

		if !ok || network.IP.To4() == nil {
			continue
		}

		subnets = append(subnets, network)
	}

	return subnets
}

func ipInSubnets(ip net.IP, subnets []*net.IPNet) bool {
	for _, subnet := range subnets {
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

// readDHCPLeases lee concesiones DHCP atribuibles a la interfaz del hotspot.
// Los ficheros globales solo se aceptan si la IP pertenece a una red
// configurada en esa interfaz, para no mezclar concesiones de otras
// interfaces (por ejemplo la red del tethering USB).
func readDHCPLeases(iface string) []dhcpLease {
	leases := make([]dhcpLease, 0, 8)

	if iface == "" {
		return leases
	}

	type leaseSource struct {
		path         string
		interfaceOwn bool
	}

	sources := []leaseSource{
		{
			path:         filepath.Join("/var/lib/NetworkManager", "dnsmasq-"+iface+".leases"),
			interfaceOwn: true,
		},
		{path: "/var/lib/misc/dnsmasq.leases"},
		{path: "/var/lib/dnsmasq/dnsmasq.leases"},
	}

	subnets := interfaceSubnets(iface)
	seen := make(map[string]bool)
	now := time.Now().Unix()

	for _, source := range sources {
		content, err := os.ReadFile(source.path)

		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Fields(line)

			if len(fields) < 5 {
				continue
			}

			expiryRaw, macRaw, ipRaw := fields[0], fields[1], fields[2]

			mac, err := parseMAC(macRaw)
			ip := net.ParseIP(ipRaw)

			if err != nil || ip == nil || ip.To4() == nil {
				continue
			}

			if !source.interfaceOwn && !ipInSubnets(ip, subnets) {
				continue
			}

			normalized := strings.ToLower(mac.String())

			if seen[normalized] {
				continue
			}

			lease := dhcpLease{
				MAC:      normalized,
				IP:       ipRaw,
				Hostname: fields[3],
			}

			if expiry, expiryErr := strconv.ParseInt(expiryRaw, 10, 64); expiryErr == nil && expiry > 0 {
				if expiry < now {
					continue
				}

				lease.ExpiresIn = (time.Duration(expiry-now) * time.Second).Round(time.Minute).String()
			}

			seen[normalized] = true
			leases = append(leases, lease)
		}
	}

	return leases
}

type arpEntry struct {
	IP  string
	MAC string
}

func readARPEntries(iface string) []arpEntry {
	entries := make([]arpEntry, 0, 8)

	content, err := os.ReadFile("/proc/net/arp")

	if err != nil {
		return entries
	}

	for _, line := range strings.Split(string(content), "\n")[1:] {
		fields := strings.Fields(line)

		if len(fields) < 6 {
			continue
		}

		if iface != "" && fields[5] != iface {
			continue
		}

		flags, err := strconv.ParseInt(fields[2], 16, 64)

		if err != nil || flags&0x2 == 0 {
			continue
		}

		hardware, err := parseMAC(fields[3])

		if err != nil {
			continue
		}

		if net.ParseIP(fields[0]) == nil {
			continue
		}

		entries = append(entries, arpEntry{
			IP:  fields[0],
			MAC: strings.ToLower(hardware.String()),
		})
	}

	return entries
}

// ============================================================
// HOTSPOT: INTERFACES Y DIAGNOSTICO
// ============================================================

func hotspotInterfacesHandler(w http.ResponseWriter) {
	status := collectHotspotStatus()

	writeJSON(w, http.StatusOK, APIResponse{
		OK: true,
		Data: map[string]interface{}{
			"interfaces": buildInterfaceInfos(status),
			"hotspot":    status.Interface,
			"backend":    status.Backend,
		},
	})
}

func buildInterfaceInfos(status HotspotStatus) []InterfaceInfo {
	names := getWirelessInterfaces()
	result := make([]InterfaceInfo, 0, len(names))

	for _, name := range names {
		info := InterfaceInfo{
			Name:      name,
			IsHotspot: name == status.Interface,
		}

		if mac, err := readInterfaceMAC(name); err == nil {
			info.MAC = mac
		}

		info.Driver = interfaceDriver(name)
		info.Mode = interfaceMode(name)
		info.OperState = readInterfaceString(name, "operstate")
		info.Up = info.OperState == "up"
		info.Carrier = readInterfaceString(name, "carrier") == "1"
		info.APSupported = interfaceAPSupport(name)
		info.IPv4 = interfaceIPv4(name)

		if detectBackend() == backendNetworkManager {
			if value := permanentMAC(name); value != "" {
				info.PermanentMAC = value
			}
		}

		result = append(result, info)
	}

	return result
}

func interfaceAPSupport(name string) string {
	if detectBackend() == backendNetworkManager {
		if value, err := nmGetDeviceField(name, "WIFI-PROPERTIES.AP"); err == nil {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "yes":
				return "si"
			case "no":
				return "no"
			}
		}
	}

	if mode := interfaceMode(name); strings.EqualFold(mode, "master") {
		return "si (AP activo)"
	}

	return "desconocido"
}

func detectTools() map[string]string {
	tools := make(map[string]string)
	names := []string{
		"nmcli", "iw", "ip", "ifconfig", "iwconfig",
		"hostapd", "hostapd_cli", "rfkill", "dnsmasq",
		"wpa_cli", "wpa_supplicant", "systemctl", "journalctl", "timeout",
	}

	for _, name := range names {
		if path := commandPath(name); path != "" {
			tools[name] = path
		} else {
			tools[name] = "no instalado"
		}
	}

	return tools
}

func detectServices() []ServiceInfo {
	units := []ServiceInfo{
		{Name: "openstick-web.service"},
		{Name: "NetworkManager.service"},
		{Name: "hostapd.service"},
		{Name: "dnsmasq.service"},
	}

	for index := range units {
		units[index].State = systemdUnitState(units[index].Name)

		if units[index].State == "" {
			units[index].State = "desconocido"
		}
	}

	return units
}

func wifiProperties(iface string) map[string]string {
	if iface == "" || detectBackend() != backendNetworkManager {
		return nil
	}

	output, err := runCommand(
		6*time.Second,
		"nmcli", "--colors", "no", "-t", "-f", "WIFI-PROPERTIES", "device", "show", iface,
	)

	if err != nil {
		return nil
	}

	properties := make(map[string]string)

	for _, line := range nonEmptyLines(output) {
		key, value, found := strings.Cut(line, ":")

		if !found {
			continue
		}

		key = strings.TrimPrefix(strings.TrimSpace(key), "WIFI-PROPERTIES.")
		properties[key] = strings.TrimSpace(value)
	}

	return properties
}

func readTrimmedFile(path string) string {
	content, err := os.ReadFile(path)

	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(content))
}

func distroName() string {
	content, err := os.ReadFile("/etc/os-release")

	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(content), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")

		if found && key == "PRETTY_NAME" {
			return strings.Trim(value, `"`)
		}
	}

	return ""
}

func hostUptime() string {
	content, err := os.ReadFile("/proc/uptime")

	if err != nil {
		return ""
	}

	fields := strings.Fields(string(content))

	if len(fields) == 0 {
		return ""
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)

	if err != nil {
		return ""
	}

	total := time.Duration(seconds) * time.Second
	days := int(total.Hours()) / 24
	hours := int(total.Hours()) % 24
	minutes := int(total.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%d d %02d h %02d min", days, hours, minutes)
	}

	return fmt.Sprintf("%02d h %02d min", hours, minutes)
}

func hasDefaultRoute() bool {
	content, err := os.ReadFile("/proc/net/route")

	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(content), "\n")[1:] {
		fields := strings.Fields(line)

		if len(fields) < 4 {
			continue
		}

		if fields[1] != "00000000" {
			continue
		}

		flags, err := strconv.ParseInt(fields[3], 16, 64)

		if err == nil && flags&0x1 != 0 {
			return true
		}
	}

	return false
}

func buildLimitations(status HotspotStatus) []string {
	limitations := make([]string, 0, 6)

	if !hasCommand("iw") {
		limitations = append(
			limitations,
			"iw no esta instalado: no se puede consultar nl80211 (estaciones asociadas ni capacidades del phy). Los clientes se infieren de DHCP y de la tabla ARP real.",
		)
	}

	if !hasCommand("ip") {
		limitations = append(
			limitations,
			"iproute2 (ip) no esta instalado: los cambios de MAC usan ifconfig (net-tools).",
		)
	}

	if !hasCommand("hostapd") {
		limitations = append(
			limitations,
			"hostapd no esta instalado: el punto de acceso lo gestiona NetworkManager con su hostapd interno.",
		)
	}

	if !hasCommand("rfkill") {
		limitations = append(
			limitations,
			"rfkill no esta instalado: no se puede comprobar el bloqueo por software del radio.",
		)
	}

	if len(getWirelessInterfaces()) <= 1 {
		limitations = append(
			limitations,
			"El dispositivo tiene una sola interfaz Wi-Fi: el modo AP y el modo cliente (uplink) son excluyentes. Al encender el hotspot se interrumpe la conexion Wi-Fi de subida.",
		)
	}

	if status.Enabled && strings.EqualFold(status.IPv4Method, "manual") {
		limitations = append(
			limitations,
			"El perfil del hotspot usa ipv4.method=manual: no reparte direcciones IP ni hace NAT. Para que los clientes naveguen, cambia el metodo IPv4 a 'shared'.",
		)
	}

	if status.Interface != "" && status.PermanentMAC == "" {
		limitations = append(
			limitations,
			"El controlador no expone la MAC permanente de "+status.Interface+" mientras la interfaz usa una MAC aleatoria. La MAC mostrada es la efectiva y verificada en /sys/class/net.",
		)
	}

	return limitations
}

func hotspotDiagnosticsHandler(w http.ResponseWriter) {
	status := collectHotspotStatus()

	hostname, _ := os.Hostname()

	diagnostics := Diagnostics{
		OK:              true,
		Backend:         status.Backend,
		Kernel:          readTrimmedFile("/proc/sys/kernel/osrelease"),
		Arch:            runtime.GOARCH,
		Distro:          distroName(),
		Hostname:        hostname,
		Uptime:          hostUptime(),
		Hotspot:         status,
		Interfaces:      buildInterfaceInfos(status),
		Tools:           detectTools(),
		Services:        detectServices(),
		WifiProperties:  wifiProperties(status.Interface),
		HasDefaultRoute: hasDefaultRoute(),
		Warnings:        append([]string{}, status.Warnings...),
		Limitations:     buildLimitations(status),
		ClientSources:   clientSourceAvailability(status.Interface),
		GeneratedAt:     time.Now().Format(time.RFC3339),
	}

	if !diagnostics.HasDefaultRoute {
		diagnostics.Warnings = append(
			diagnostics.Warnings,
			"No hay ruta por defecto: el dispositivo no tiene salida a Internet en este momento.",
		)
	}

	writeJSON(w, http.StatusOK, diagnostics)
}

// ============================================================
// SISTEMA: SHELL, ARCHIVOS, DHCP Y DNS
// ============================================================

type shellRequest struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type shellResponse struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exitCode"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"durationMs"`
	Truncated  bool   `json:"truncated"`
}

type fileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	Mtime string `json:"mtime"`
}

type fileMoveRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type fileWriteRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty"`
}

type fileUploadRequest struct {
	Path string `json:"path"`
	Data string `json:"data"`
	Mode string `json:"mode,omitempty"`
}

func hotspotShellHandler(w http.ResponseWriter, r *http.Request) {
	var request shellRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	command := strings.TrimSpace(request.Command)

	if command == "" {
		writeError(w, http.StatusBadRequest, "El comando esta vacio")
		return
	}

	timeout := 30 * time.Second

	if request.Timeout > 0 {
		if request.Timeout > 120 {
			request.Timeout = 120
		}

		timeout = time.Duration(request.Timeout) * time.Second
	}

	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = "/"

	stdoutBuf := &limitedBuffer{limit: 64 * 1024}
	stderrBuf := &limitedBuffer{limit: 64 * 1024}
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	err := cmd.Run()

	response := shellResponse{
		OK:         err == nil,
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		DurationMs: time.Since(start).Milliseconds(),
		Truncated:  stdoutBuf.truncated || stderrBuf.truncated,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			response.ExitCode = exitErr.ExitCode()
		} else {
			response.ExitCode = -1

			if response.Stderr == "" {
				response.Stderr = err.Error()
			}
		}
	}

	writeJSON(w, http.StatusOK, response)
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len() >= b.limit {
		b.truncated = true
		return len(p), nil
	}

	remaining := b.limit - b.buf.Len()

	if len(p) > remaining {
		b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}

	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

func cleanSystemPath(value string) (string, error) {
	value = strings.TrimSpace(value)

	if value == "" {
		value = "/"
	}

	if !filepath.IsAbs(value) {
		return "", errors.New("la ruta debe ser absoluta")
	}

	cleaned := filepath.Clean(value)

	if strings.Contains(cleaned, "..") {
		return "", errors.New("ruta no valida")
	}

	return cleaned, nil
}

func hotspotFilesHandler(w http.ResponseWriter, r *http.Request) {
	path, err := cleanSystemPath(r.URL.Query().Get("path"))

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	info, err := os.Stat(path)

	if err != nil {
		writeError(w, http.StatusNotFound, "No se pudo acceder a la ruta: "+err.Error())
		return
	}

	if !info.IsDir() {
		writeError(w, http.StatusBadRequest, "La ruta no es un directorio")
		return
	}

	entries, err := os.ReadDir(path)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "No se pudo leer el directorio: "+err.Error())
		return
	}

	result := make([]fileEntry, 0, len(entries))

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
		entryInfo, statErr := entry.Info()

		if statErr != nil {
			continue
		}

		result = append(result, fileEntry{
			Name:  entry.Name(),
			Path:  fullPath,
			IsDir: entry.IsDir(),
			Size:  entryInfo.Size(),
			Mode:  entryInfo.Mode().String(),
			Mtime: entryInfo.ModTime().Format(time.RFC3339),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}

		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"path":    path,
		"entries": result,
	})
}

func hotspotFileReadHandler(w http.ResponseWriter, r *http.Request) {
	path, err := cleanSystemPath(r.URL.Query().Get("path"))

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	info, err := os.Stat(path)

	if err != nil {
		writeError(w, http.StatusNotFound, "Archivo no encontrado: "+err.Error())
		return
	}

	if info.IsDir() {
		writeError(w, http.StatusBadRequest, "La ruta es un directorio")
		return
	}

	if info.Size() > 2*1024*1024 {
		writeError(w, http.StatusRequestEntityTooLarge, "El archivo supera 2 MB. Usa la descarga.")
		return
	}

	content, err := os.ReadFile(path)

	if err != nil {
		writeError(w, http.StatusInternalServerError, "No se pudo leer el archivo: "+err.Error())
		return
	}

	if bytes.Contains(content, []byte{0}) {
		writeError(w, http.StatusUnsupportedMediaType, "El archivo es binario. Usa la descarga.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"path":    path,
		"size":    info.Size(),
		"mode":    info.Mode().String(),
		"mtime":   info.ModTime().Format(time.RFC3339),
		"content": string(content),
	})
}

func hotspotFileDownloadHandler(w http.ResponseWriter, r *http.Request) {
	path, err := cleanSystemPath(r.URL.Query().Get("path"))

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	info, err := os.Stat(path)

	if err != nil || info.IsDir() {
		writeError(w, http.StatusNotFound, "Archivo no encontrado")
		return
	}

	file, err := os.Open(path)

	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer file.Close()

	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))

	_, _ = io.Copy(w, file)
}

func hotspotFileWriteHandler(w http.ResponseWriter, r *http.Request) {
	var request fileWriteRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	path, err := cleanSystemPath(request.Path)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if request.Mode == "append" {
		existing, _ := os.ReadFile(path)
		request.Content = string(existing) + request.Content
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := os.WriteFile(path, []byte(request.Content), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "No se pudo escribir el archivo: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":   true,
		"path": path,
		"size": len(request.Content),
	})
}

func hotspotFileDeleteHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Path      string `json:"path"`
		Recursive bool   `json:"recursive"`
	}

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	path := ""

	if request.Path != "" {
		path = request.Path
	} else {
		path = r.URL.Query().Get("path")
	}

	cleaned, err := cleanSystemPath(path)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	path = cleaned

	if path == "/" {
		writeError(w, http.StatusBadRequest, "No se puede borrar el directorio raiz")
		return
	}

	if request.Recursive {
		if err := os.RemoveAll(path); err != nil {
			writeError(w, http.StatusInternalServerError, "No se pudo borrar: "+err.Error())
			return
		}
	} else {
		if err := os.Remove(path); err != nil {
			writeError(w, http.StatusInternalServerError, "No se pudo borrar: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":   true,
		"path": path,
	})
}

func hotspotFileMoveHandler(w http.ResponseWriter, r *http.Request) {
	var request fileMoveRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	from, err := cleanSystemPath(request.From)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	to, err := cleanSystemPath(request.To)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := os.MkdirAll(filepath.Dir(to), 0755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := os.Rename(from, to); err != nil {
		writeError(w, http.StatusInternalServerError, "No se pudo mover/renombrar: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":   true,
		"from": from,
		"to":   to,
	})
}

func hotspotFileUploadHandler(w http.ResponseWriter, r *http.Request) {
	var request fileUploadRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	path, err := cleanSystemPath(request.Path)

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	data, err := base64.StdEncoding.DecodeString(request.Data)

	if err != nil {
		writeError(w, http.StatusBadRequest, "Datos base64 invalidos: "+err.Error())
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "No se pudo subir el archivo: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":   true,
		"path": path,
		"size": len(data),
	})
}

func hotspotDHCPHandler(w http.ResponseWriter) {
	leases := make([]map[string]interface{}, 0, 8)
	leaseFiles := []string{
		"/var/lib/NetworkManager/dnsmasq-wlan0.leases",
		"/var/lib/NetworkManager/dnsmasq-usb0.leases",
		"/var/lib/misc/dnsmasq.leases",
		"/var/lib/dnsmasq/dnsmasq.leases",
	}

	seen := make(map[string]bool)

	for _, path := range leaseFiles {
		content, err := os.ReadFile(path)

		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(content), "\n") {
			fields := strings.Fields(line)

			if len(fields) < 3 {
				continue
			}

			mac, macErr := parseMAC(fields[1])

			if macErr != nil {
				continue
			}

			normalized := strings.ToLower(mac.String())

			if seen[normalized] {
				continue
			}

			seen[normalized] = true

			lease := map[string]interface{}{
				"mac":    normalized,
				"ip":     fields[2],
				"source": path,
			}

			if len(fields) >= 4 {
				lease["hostname"] = fields[3]
			}

			if expiry, err := strconv.ParseInt(fields[0], 10, 64); err == nil && expiry > 0 {
				now := time.Now().Unix()

				if expiry > now {
					lease["expiresIn"] = (time.Duration(expiry-now) * time.Second).Round(time.Minute).String()
				} else {
					lease["expired"] = true
				}
			}

			leases = append(leases, lease)
		}
	}

	processes := make([]string, 0, 4)

	if output, err := runCommand(5*time.Second, "ps", "-ef"); err == nil {
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "dnsmasq") && !strings.Contains(line, "grep") {
				processes = append(processes, strings.TrimSpace(line))
			}
		}
	}

	configFiles := make(map[string]string)

	for _, path := range []string{
		"/etc/dnsmasq.conf",
		"/etc/NetworkManager/NetworkManager.conf",
	} {
		if content, err := os.ReadFile(path); err == nil {
			configFiles[path] = string(content)
		}
	}

	sharedDir := "/etc/NetworkManager/dnsmasq-shared.d"
	sharedEntries := make([]string, 0, 4)

	if entries, err := os.ReadDir(sharedDir); err == nil {
		for _, entry := range entries {
			sharedEntries = append(sharedEntries, filepath.Join(sharedDir, entry.Name()))
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":            true,
		"leases":        leases,
		"leaseCount":    len(leases),
		"processes":     processes,
		"configFiles":   configFiles,
		"sharedDir":     sharedDir,
		"sharedEntries": sharedEntries,
		"resolvConf":    readTrimmedFile("/etc/resolv.conf"),
	})
}

func hotspotDNSHandler(w http.ResponseWriter) {
	configFiles := make(map[string]string)

	for _, path := range []string{
		"/etc/resolv.conf",
		"/etc/hosts",
		"/etc/dnsmasq.conf",
	} {
		if content, err := os.ReadFile(path); err == nil {
			configFiles[path] = string(content)
		}
	}

	nameservers := make([]string, 0, 4)

	for _, line := range strings.Split(readTrimmedFile("/etc/resolv.conf"), "\n") {
		fields := strings.Fields(line)

		if len(fields) >= 2 && fields[0] == "nameserver" {
			nameservers = append(nameservers, fields[1])
		}
	}

	records, upstream := collectDNSRecords()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":          true,
		"nameservers": nameservers,
		"upstream":    upstream,
		"records":     records,
		"configFiles": configFiles,
		"hostname":    readTrimmedFile("/etc/hostname"),
	})
}

func hotspotDHCPRestartHandler(w http.ResponseWriter) {
	if profile, err := nmHotspotProfile(); err == nil && nmConnectionActive(profile) {
		_, _ = runCommand(20*time.Second, "nmcli", "--colors", "no", "connection", "down", profile)

		if output, err := runCommand(40*time.Second, "nmcli", "--colors", "no", "connection", "up", profile); err != nil {
			writeError(w, http.StatusInternalServerError, commandError("No se pudo reiniciar el hotspot", output, err))
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":      true,
			"message": "Hotspot reiniciado (dnsmasq recargado)",
		})

		return
	}

	output, err := runCommand(20*time.Second, "systemctl", "restart", "dnsmasq")

	if err != nil {
		writeError(w, http.StatusInternalServerError, commandError("No se pudo reiniciar dnsmasq", output, err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"message": "dnsmasq reiniciado",
	})
}

// ============================================================
// EVENTOS EN TIEMPO REAL (SSE)
// ============================================================

type eventBroker struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

var pedidosEvents = &eventBroker{clients: make(map[chan string]struct{})}

func (b *eventBroker) subscribe() chan string {
	ch := make(chan string, 16)

	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	return ch
}

func (b *eventBroker) unsubscribe(ch chan string) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()

	close(ch)
}

func (b *eventBroker) broadcast(eventType string, payload interface{}) {
	data, err := json.Marshal(map[string]interface{}{
		"type": eventType,
		"data": payload,
	})

	if err != nil {
		return
	}

	message := "event: " + eventType + "\ndata: " + string(data) + "\n\n"

	b.mu.Lock()
	defer b.mu.Unlock()

	for ch := range b.clients {
		select {
		case ch <- message:
		default:
		}
	}
}

func hotspotEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !authorizeHotspot(w, r) {
		return
	}

	flusher, ok := w.(http.Flusher)

	if !ok {
		writeError(w, http.StatusInternalServerError, "El servidor no soporta streaming")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := pedidosEvents.subscribe()
	defer pedidosEvents.unsubscribe(ch)

	fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	statusTicker := time.NewTicker(5 * time.Second)
	pingTicker := time.NewTicker(25 * time.Second)
	defer statusTicker.Stop()
	defer pingTicker.Stop()

	sendStatus := func() {
		status := collectHotspotStatus()
		data, err := json.Marshal(status)

		if err != nil {
			return
		}

		fmt.Fprintf(w, "event: status\ndata: %s\n\n", string(data))
		flusher.Flush()

		clients := status.clients

		if clients == nil {
			clients = []WiFiClient{}
		}

		cdata, err := json.Marshal(map[string]interface{}{
			"ok":        true,
			"total":     len(clients),
			"clients":   clients,
			"available": status.Enabled,
			"interface": status.Interface,
		})

		if err == nil {
			fmt.Fprintf(w, "event: clients\ndata: %s\n\n", string(cdata))
			flusher.Flush()
		}
	}

	sendStatus()

	for {
		select {
		case message := <-ch:
			_, _ = w.Write([]byte(message))
			flusher.Flush()

		case <-statusTicker.C:
			sendStatus()

		case <-pingTicker.C:
			_, _ = fmt.Fprintf(w, ": ping\\n\\n")
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
}

// ============================================================
// DNS: GESTION DE SERVIDOR DNS (dnsmasq)
// ============================================================

type dnsRecord struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

type dnsSetRequest struct {
	Upstream []string `json:"upstream"`
	Records  []struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"records"`
	Apply bool `json:"apply"`
}

const openstickDNSConfig = "/etc/NetworkManager/dnsmasq-shared.d/openstick-dns.conf"

func collectDNSRecords() ([]dnsRecord, []string) {
	records := make([]dnsRecord, 0, 16)
	upstream := make([]string, 0, 4)
	seenUpstream := make(map[string]bool)

	files := make([]string, 0, 8)
	for _, dir := range []string{
		"/etc/dnsmasq.d",
		"/etc/NetworkManager/dnsmasq-shared.d",
	} {
		entries, err := os.ReadDir(dir)

		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}

	files = append(files, "/etc/dnsmasq.conf")

	for _, path := range files {
		content, err := os.ReadFile(path)

		if err != nil {
			continue
		}

		for _, rawLine := range strings.Split(string(content), "\n") {
			line := strings.TrimSpace(rawLine)

			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			switch {
			case strings.HasPrefix(line, "address="):
				value := strings.TrimPrefix(line, "address=")
				parts := strings.SplitN(value, "/", 3)

				if len(parts) >= 2 {
					name := parts[1]
					val := ""

					if len(parts) >= 3 {
						val = parts[2]
					}

					if val == "#" {
						val = "(NXDOMAIN)"
					}

					records = append(records, dnsRecord{
						Type:   "A",
						Name:   name,
						Value:  val,
						Source: path,
					})
				}

			case strings.HasPrefix(line, "cname="):
				value := strings.TrimPrefix(line, "cname=")
				parts := strings.SplitN(value, ",", 2)

				if len(parts) == 2 {
					records = append(records, dnsRecord{
						Type:   "CNAME",
						Name:   strings.TrimSpace(parts[0]),
						Value:  strings.TrimSpace(parts[1]),
						Source: path,
					})
				}

			case strings.HasPrefix(line, "txt-record="):
				value := strings.TrimPrefix(line, "txt-record=")
				parts := strings.SplitN(value, ",", 2)

				if len(parts) == 2 {
					records = append(records, dnsRecord{
						Type:   "TXT",
						Name:   strings.TrimSpace(parts[0]),
						Value:  strings.Trim(strings.TrimSpace(parts[1]), "\""),
						Source: path,
					})
				}

			case strings.HasPrefix(line, "ptr-record="):
				value := strings.TrimPrefix(line, "ptr-record=")
				parts := strings.SplitN(value, ",", 2)

				if len(parts) == 2 {
					records = append(records, dnsRecord{
						Type:   "PTR",
						Name:   strings.TrimSpace(parts[0]),
						Value:  strings.TrimSpace(parts[1]),
						Source: path,
					})
				}

			case strings.HasPrefix(line, "server="):
				value := strings.TrimPrefix(line, "server=")

				if strings.Contains(value, "/") {
					parts := strings.SplitN(value, "/", 3)

					if len(parts) >= 2 {
						records = append(records, dnsRecord{
							Type:   "forward",
							Name:   parts[1],
							Value:  parts[0],
							Source: path,
						})
					}
				} else if value != "" && !seenUpstream[value] {
					seenUpstream[value] = true
					upstream = append(upstream, value)
				}
			}
		}
	}

	return records, upstream
}

func hotspotDNSSetHandler(w http.ResponseWriter, r *http.Request) {
	var request dnsSetRequest

	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var builder strings.Builder
	builder.WriteString("# Gestionado por OpenStickWeb - no editar a mano\n")

	if len(request.Upstream) > 0 {
		builder.WriteString("# Servidores DNS upstream\n")

		for _, server := range request.Upstream {
			server = strings.TrimSpace(server)

			if server == "" {
				continue
			}

			fmt.Fprintf(&builder, "server=%s\n", server)
		}
	}

	if len(request.Records) > 0 {
		builder.WriteString("# Registros DNS locales\n")

		for _, record := range request.Records {
			recordType := strings.ToUpper(strings.TrimSpace(record.Type))
			name := strings.TrimSpace(record.Name)
			value := strings.TrimSpace(record.Value)

			if name == "" {
				continue
			}

			switch recordType {
			case "A":
				fmt.Fprintf(&builder, "address=/%s/%s\n", name, value)

			case "CNAME":
				fmt.Fprintf(&builder, "cname=%s,%s\n", name, value)

			case "TXT":
				fmt.Fprintf(&builder, "txt-record=%s,\"%s\"\n", name, value)

			case "PTR":
				fmt.Fprintf(&builder, "ptr-record=%s,%s\n", name, value)

			case "FORWARD":
				fmt.Fprintf(&builder, "server=/%s/%s\n", name, value)
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(openstickDNSConfig), 0755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := os.WriteFile(openstickDNSConfig, []byte(builder.String()), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "No se pudo escribir la configuracion DNS: "+err.Error())
		return
	}

	applied := false
	applyWarning := ""

	if request.Apply {
		if profile, perr := nmHotspotProfile(); perr == nil && nmConnectionActive(profile) {
			_, _ = runCommand(20*time.Second, "nmcli", "--colors", "no", "connection", "down", profile)

			if output, err := runCommand(40*time.Second, "nmcli", "--colors", "no", "connection", "up", profile); err == nil {
				applied = true
			} else {
				applyWarning = commandError("No se pudo reactivar el hotspot para aplicar el DNS", output, err)
			}
		} else {
			applied = true
			applyWarning = "El hotspot esta apagado: la configuracion se aplicara al encenderlo."
		}
	}

	records, upstream := collectDNSRecords()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"message":    "Configuracion DNS guardada",
		"records":    records,
		"upstream":   upstream,
		"applied":    applied,
		"warning":    applyWarning,
		"configPath": openstickDNSConfig,
	})
}

// ============================================================
// UTILIDADES DE COMANDOS
// ============================================================

func runCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)

	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(ansiEscapeRegex.ReplaceAllString(string(output), ""))

	if ctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("tiempo de espera agotado ejecutando %s", name)
	}

	if err != nil {
		return text, fmt.Errorf("%s: %w", name, err)
	}

	return text, nil
}

func commandError(message, output string, err error) string {
	details := strings.TrimSpace(output)

	if details != "" {
		return message + ": " + details
	}

	return message + ": " + err.Error()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)

	return err == nil && !info.IsDir()
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination interface{}) error {
	if r.Body == nil {
		return errors.New("cuerpo de la solicitud vacio")
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("JSON invalido: %w", err)
	}

	var extra interface{}

	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("la solicitud contiene mas de un objeto JSON")
		}

		return fmt.Errorf("contenido adicional invalido: %w", err)
	}

	return nil
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "Metodo no permitido")
}

// ============================================================
// INFO Y PAGINAS
// ============================================================

func infoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "Metodo no permitido")
		return
	}

	serveHTML(w, r, infoFile)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Captura cualquier ruta y host no ocupado por nosotros y muestra index.html.
	serveHTML(w, r, indexFile)
}

func serveHTML(w http.ResponseWriter, r *http.Request, filename string) {
	content, err := os.ReadFile(filename)

	if err != nil {
		log.Printf("[STATIC] No se pudo leer %s: %v", filename, err)
		http.Error(w, "Archivo no encontrado: "+filename, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	if r.Method != http.MethodHead {
		_, _ = w.Write(content)
	}
}

// ============================================================
// RESPUESTAS HTTP
// ============================================================

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("[JSON] Error escribiendo respuesta: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, ErrorResponse{
		OK:    false,
		Error: message,
	})
}

// ============================================================
// PERSISTENCIA DE PEDIDOS
// ============================================================

func loadPedidos() error {
	path := filepath.Join(dataDir, "pedidos.json")

	content, err := os.ReadFile(path)

	if os.IsNotExist(err) {
		pedidos = []Pedido{}
		nextID = 1
		return nil
	}

	if err != nil {
		return err
	}

	var loaded []Pedido

	if err := json.Unmarshal(content, &loaded); err != nil {
		return err
	}

	if loaded == nil {
		loaded = []Pedido{}
	}

	maxID := 0

	for _, pedido := range loaded {
		if pedido.ID > maxID {
			maxID = pedido.ID
		}
	}

	pedidosMu.Lock()
	pedidos = loaded
	nextID = maxID + 1
	pedidosMu.Unlock()

	log.Printf("[PEDIDOS] Cargados %d pedidos", len(loaded))

	return nil
}

func savePedidosLocked() error {
	path := filepath.Join(dataDir, "pedidos.json")
	tempPath := path + ".tmp"

	content, err := json.MarshalIndent(pedidos, "", "  ")

	if err != nil {
		return err
	}

	if err := os.WriteFile(tempPath, content, 0644); err != nil {
		return err
	}

	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	return nil
}

// ============================================================
// CERTIFICADO TLS
// ============================================================

func ensureCertificate() error {
	certPath := filepath.Join(certDir, "server.crt")
	keyPath := filepath.Join(certDir, "server.key")

	if _, err := os.Stat(certPath); err == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			log.Println("[TLS] Certificado existente")
			return nil
		}
	}

	log.Println("[TLS] Generando certificado autofirmado...")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialLimit)

	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "OpenStick Web Server",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	interfaces, err := net.Interfaces()

	if err == nil {
		for _, iface := range interfaces {
			addresses, addressErr := iface.Addrs()

			if addressErr != nil {
				continue
			}

			for _, address := range addresses {
				var ip net.IP

				switch value := address.(type) {
				case *net.IPNet:
					ip = value.IP
				case *net.IPAddr:
					ip = value.IP
				}

				if ip == nil || ip.IsLoopback() {
					continue
				}

				if ip4 := ip.To4(); ip4 != nil {
					template.IPAddresses = append(template.IPAddresses, ip4)
				} else if ip6 := ip.To16(); ip6 != nil {
					template.IPAddresses = append(template.IPAddresses, ip6)
				}
			}
		}
	}

	uniqueIPs := make(map[string]net.IP)

	for _, ip := range template.IPAddresses {
		uniqueIPs[ip.String()] = ip
	}

	template.IPAddresses = template.IPAddresses[:0]

	for _, ip := range uniqueIPs {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	sort.Slice(template.IPAddresses, func(i, j int) bool {
		return template.IPAddresses[i].String() < template.IPAddresses[j].String()
	})

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)

	if err != nil {
		return err
	}

	certFile, err := os.Create(certPath)

	if err != nil {
		return err
	}

	if err := pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		certFile.Close()
		return err
	}

	if err := certFile.Close(); err != nil {
		return err
	}

	keyFile, err := os.OpenFile(
		keyPath,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)

	if err != nil {
		return err
	}

	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		keyFile.Close()
		return err
	}

	if err := keyFile.Close(); err != nil {
		return err
	}

	log.Printf("[TLS] Certificado creado: %s", certPath)

	return nil
}
