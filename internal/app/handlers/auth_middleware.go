package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
)

type key string

const (
	cookieName          = "session"
	cookiePath          = "/"
	cookieMaxAge        = 60 * 60 * 24
	userIDKey       key = "userID"
	signatureLength     = 32
	invalidCookie       = "Invalid cookie"
)

func checkSignature(cookieValue string, secretKey []byte) (string, error) {
	session, err := hex.DecodeString(cookieValue)
	if err != nil {
		return "", err
	}

	if len(session) <= signatureLength {
		return "", fmt.Errorf("invalid cookie length")
	}

	userIDLength := len(session) - signatureLength
	userID := session[:userIDLength]

	key := sha256.Sum256(secretKey)
	h := hmac.New(sha256.New, key[:])
	h.Write(userID)
	sign := h.Sum(nil)

	if hmac.Equal(sign, session[userIDLength:]) {
		return string(userID), nil
	} else {
		return "", fmt.Errorf("invalid signature")
	}
}

func authHandle(secretKey string) (ah func(http.Handler) http.Handler) {
	ah = func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionCookie, err := r.Cookie(cookieName)

			if err != nil {
				http.Redirect(w, r, "/login", 302)
				log.Println(err)
				return
			} else {
				cookieValue := sessionCookie.Value
				userID, err := checkSignature(cookieValue, []byte(secretKey))
				if err != nil {
					http.Redirect(w, r, "/login", 302)
					log.Println(err)
					return
				}
				ctx := context.WithValue(r.Context(), userIDKey, userID)
				h.ServeHTTP(w, r.WithContext(ctx))
			}
		})
	}
	return
}
