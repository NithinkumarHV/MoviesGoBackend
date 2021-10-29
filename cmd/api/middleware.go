package main

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pascaldekloe/jwt"
)

func (app *application) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		next.ServeHTTP(w, r)
	})
}

func (app *application) checkToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Authorization")

		authHeader := r.Header.Get("Authorization")

		headerParts := strings.Split(authHeader, " ")
		if len(headerParts) != 2 {
			app.errorJSON(w, errors.New("invalid auth header"))
			return
		}

		if headerParts[0] != "Bearer" {
			app.errorJSON(w, errors.New("unauthorized - no bearer"))
			return
		}

		token := headerParts[1]

		cliams, err := jwt.HMACCheck([]byte(token), []byte(app.config.jwt.secret))
		if err != nil {
			app.errorJSON(w, errors.New("unauthorized - failed HMAC check"), http.StatusForbidden)
			return
		}

		if !cliams.Valid(time.Now()) {
			app.errorJSON(w, errors.New("unauthorized - token not valid"), http.StatusForbidden)
			return
		}

		if !cliams.AcceptAudience("mydomain.com") {
			app.errorJSON(w, errors.New("unauthorized - invalid audience"), http.StatusForbidden)
			return
		}

		if cliams.Issuer != "mydomain" {
			app.errorJSON(w, errors.New("unauthorized - invalid issuer"), http.StatusForbidden)
			return
		}

		UserID, err := strconv.ParseInt(cliams.Subject, 10, 64)
		if err != nil {
			app.errorJSON(w, errors.New("unauthorized"), http.StatusForbidden)
			return
		}

		log.Println("Valid user", UserID)
		next.ServeHTTP(w, r)
	})
}
