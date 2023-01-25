package api

import (
	"ApiGateway/internal/core/auth"
	"ApiGateway/internal/core/errorsCore"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	ErrNoToken = errors.New("no token provided in Authorization header")
	IsLocal    bool
)

const (
	authHeader     = "Authorization"
	headerSegments = 2
)

func (gw *gateWay) verifyToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gw.conf.IsLocal {
			IsLocal = true
		}
		if r.Method == http.MethodOptions {
			return
		}
		receivedToken := r.Header.Get(authHeader)
		if receivedToken == "" {
			gw.warning(w, http.StatusBadRequest, ErrNoToken, ErrNoToken.Error())

			return
		}
		token := strings.Split(receivedToken, " ")
		if len(token) != headerSegments {
			gw.warning(w, http.StatusBadRequest, errorsCore.ErrParseHeader, "can't split authHeader")

			return
		}
		providedToken := token[1]
		payload, err := parseToken(providedToken)
		if err != nil {
			if errors.Is(err, errorsCore.ErrTokenExpired) {
				payload, err = updateToken(providedToken, r)
				if err != nil {
					gw.warning(w, http.StatusUnauthorized, errorsCore.ErrParseHeader, err.Error())

					return
				}
				r.Header.Set("ExpiredIn", fmt.Sprint(payload.ExpiredIn.Unix()))
				id := payload.ProfileID
				r.Header.Set(userID, id.String())
				next.ServeHTTP(w, r)

				return
			}
			gw.warning(w, http.StatusUnauthorized, errorsCore.ErrInvalidToken, err.Error())

			return
		}

		if payload == (&auth.Payload{}) {
			gw.warning(w, http.StatusUnauthorized, errorsCore.ErrInvalidToken, errorsCore.ErrInvalidToken.Error())

			return
		}
		next.ServeHTTP(w, r)
	})
}

func parseToken(token string) (*auth.Payload, error) {
	maker, err := auth.NewJWTMaker()
	if err != nil {
		return nil, errorsCore.WrapError("error while creating NewJWTMaker", err)
	}
	payload, err := maker.VerifyToken(token)
	if err != nil {
		return nil, errorsCore.WrapError(errorsCore.ErrInvalidToken.Error(), err)
	}

	return payload, nil
}

func updateToken(token string, r *http.Request) (*auth.Payload, error) {
	maker, err := auth.NewJWTMaker()
	if err != nil {
		return nil, errorsCore.WrapError("error while creating NewJWTMaker", err)
	}
	payload, _ := maker.ParseExpiredToken(token)
	if time.Now().Before(payload.ExpiredIn) && r.URL.Path == "/api/v1/login/token/" || r.URL.Path == "/api/v1/logout" {
		if err != nil {
			return nil, errorsCore.WrapError("while refreshing expired token", err)
		}
	} else {
		return nil, errorsCore.ErrTokenExpired
	}

	return payload, nil
}
