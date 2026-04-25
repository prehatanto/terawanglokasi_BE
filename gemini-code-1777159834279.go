package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/argon2"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var db *sql.DB

func main() {
	var err error
	// Sesuaikan [PASSWORD_KAMU] dengan password database Supabase
	connStr := "postgresql://postgres:[PASSWORD_KAMU]@db.hghwslxuxsnhvqjzpbck.supabase.co:5432/postgres"

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/login", loginHandler)
	fmt.Println("Server jalan di :8080 (Argon2i Mode)")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var storedHash string
	err := db.QueryRow("SELECT password FROM credentials WHERE username = $1", req.Username).Scan(&storedHash)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verifikasi menggunakan fungsi pembantu Argon2
	match, err := comparePasswordAndHash(req.Password, storedHash)
	if err != nil || !match {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Login Berhasil!"})
}

// Fungsi untuk memverifikasi password Argon2
func comparePasswordAndHash(password, encodedHash string) (bool, error) {
	// Format umum hash Argon2: $argon2i$v=19$m=65536,t=3,p=2$salt$hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("format hash tidak valid")
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	// Generate hash dari password input menggunakan parameter yang sama
	keyLen := uint32(len(decodedHash))
	comparisonHash := argon2.Key([]byte(password), salt, iterations, memory, parallelism, keyLen)

	// Gunakan subtle.ConstantTimeCompare untuk mencegah side-channel attacks
	if subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1 {
		return true, nil
	}
	return false, nil
}