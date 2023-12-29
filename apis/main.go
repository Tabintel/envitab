package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
)

// User struct represents a user of the Envitab system
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// TrashRequest struct represents a request for trash pickup
type TrashRequest struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Location  string    `json:"location"`
	CreatedAt time.Time `json:"created_at"`
}

var users = []User{
	{ID: "1", Username: "user1", Password: "password1"},
	{ID: "2", Username: "user2", Password: "password2"},
}

var trashRequests []TrashRequest

var jwtKey = []byte("secret_key")

// Authentication middleware
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Handler for user authentication
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds User
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	for _, user := range users {
		if user.Username == creds.Username && user.Password == creds.Password {
			expirationTime := time.Now().Add(5 * time.Minute)
			claims := &jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			}

			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			tokenString, err := token.SignedString(jwtKey)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			w.Write([]byte(tokenString))
			return
		}
	}

	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// Handler for creating a trash pickup request
func createTrashRequestHandler(w http.ResponseWriter, r *http.Request) {
	var request TrashRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	request.ID = fmt.Sprintf("%d", len(trashRequests)+1)
	request.CreatedAt = time.Now()

	trashRequests = append(trashRequests, request)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(request)
}

// Handler for retrieving all trash pickup requests
func getTrashRequestsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trashRequests)
}

func main() {
	r := mux.NewRouter()

	// Authentication endpoint
	r.HandleFunc("/login", loginHandler).Methods("POST")

	// Authenticated endpoints
	authRouter := r.PathPrefix("/api").Subrouter()
	authRouter.Use(authenticate)

	// Trash pickup endpoints
	authRouter.HandleFunc("/trash", createTrashRequestHandler).Methods("POST")
	authRouter.HandleFunc("/trash", getTrashRequestsHandler).Methods("GET")

	// Start the server
	fmt.Println("Server listening on :8080")
	http.ListenAndServe(":8080", r)
}
