package auth

import (
	"ApiGateway/internal/core/errorsCore"
	"github.com/google/uuid"
	"time"
)

type Payload struct {
	TokenID   uuid.UUID `json:"tokenId"`
	ProfileID uuid.UUID `json:"profileId"`
	RtokenID  uuid.UUID `json:"rtokenID"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiredAt time.Time `json:"expiredAt"`
	ExpiredIn time.Time `json:"expiredIn"`
}

func NewPayload(profileID uuid.UUID, duration time.Duration) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, errorsCore.WrapError("error while creating payload", err)
	}

	payload := Payload{
		TokenID:   tokenID,
		ProfileID: profileID,
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(duration),
	}

	return &payload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().After(payload.ExpiredAt) {
		return errorsCore.ErrTokenExpired
	}

	return nil
}
