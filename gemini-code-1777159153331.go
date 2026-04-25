package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq" // Driver Postgres
	"golang.org/x/crypto/bcrypt"
)

// Struktur data untuk request login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var db *sql.DB

func main() {
	var err error
	// Ganti [PASSWORD_KAMU] dengan password database Supabase-mu
	connStr := "postgresql://postgres:[PASSWORD_KAMU]@db.hghwslxuxsnhvqjzpbck.supabase.co:5432/postgres"
	
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/login", loginHandler)

	fmt.Println("Server jalan di :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method tidak diizinkan", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Gagal membaca input", http.StatusBadRequest)
		return
	}

	// 1. Cari user di tabel 'credentials' berdasarkan username
	var hashedPassword string
	query := "SELECT password FROM credentials WHERE username = $1"
	err = db.QueryRow(query, req.Username).Scan(&hashedPassword)

	if err == sql.ErrNoRows {
		http.Error(w, "Username atau password salah", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Kesalahan server", http.StatusInternalServerError)
		return
	}

	// 2. Verifikasi password dengan Bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		// Jika password tidak cocok
		http.Error(w, "Username atau password salah", http.StatusUnauthorized)
		return
	}

	// 3. Login Berhasil
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login berhasil!",
		"user":    req.Username,
	})
}