package auth

import (
	"ApiGateway/internal/core/errorsCore"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

type JWTMaker struct {
	secretKey string
}

type Maker interface {
	VerifyToken(token string) (*Payload, error)
	ParseExpiredToken(token string) (*Payload, error)
}

func NewJWTMaker() (Maker, error) { //nolint:ireturn
	return &JWTMaker{os.Getenv("SECRET_JWT")}, nil
}

func (maker *JWTMaker) VerifyToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, errorsCore.ErrInvalidToken
		}

		return []byte(maker.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &Payload{}, keyFunc)
	if err != nil {
		var verr *jwt.ValidationError
		if errors.As(err, &verr) {
			return nil, errorsCore.WrapError("validation error while parsing with claims", err)
		}

		return nil, errorsCore.WrapError("can't parse token with claims", err)
	}

	payload, ok := jwtToken.Claims.(*Payload)
	if !ok {
		return nil, errorsCore.ErrInvalidToken
	}

	return payload, nil
}

func (maker *JWTMaker) ParseExpiredToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, errorsCore.ErrInvalidToken
		}

		return []byte(maker.secretKey), nil
	}

	jwtToken, _ := jwt.ParseWithClaims(token, &Payload{}, keyFunc)

	payload, ok := jwtToken.Claims.(*Payload)
	if !ok {
		return nil, errorsCore.ErrInvalidToken
	}

	return payload, nil
}
