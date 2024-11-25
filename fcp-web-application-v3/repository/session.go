package repository

import (
	"a21hc3NpZ25tZW50/db/filebased"
	"a21hc3NpZ25tZW50/model"
	"errors"
	"time"
)

type SessionRepository interface {
	AddSessions(session model.Session) error
	DeleteSession(token string) error
	UpdateSessions(session model.Session) error
	SessionAvailEmail(email string) (model.Session, error)
	SessionAvailToken(token string) (model.Session, error)
	TokenExpired(session model.Session) bool
}

type sessionsRepo struct {
	filebasedDb *filebased.Data
}

func NewSessionsRepo(filebasedDb *filebased.Data) *sessionsRepo {
	return &sessionsRepo{filebasedDb}
}

func (u *sessionsRepo) AddSessions(session model.Session) error {
	return u.filebasedDb.AddSession(session)
}

func (u *sessionsRepo) DeleteSession(token string) error {
	return u.filebasedDb.DeleteSession(token)
}

func (u *sessionsRepo) UpdateSessions(session model.Session) error {
	return u.filebasedDb.UpdateSession(session)
}

func (u *sessionsRepo) SessionAvailEmail(email string) (model.Session, error) {
	session, err := u.filebasedDb.SessionAvailEmail(email)
	if err != nil {
		return model.Session{}, err
	}
	if session.Email == "" {
		return model.Session{}, errors.New("session not found")
	}
	return session, nil
}

func (u *sessionsRepo) SessionAvailToken(token string) (model.Session, error) {
	session, err := u.filebasedDb.SessionAvailToken(token)
	if err != nil {
		return model.Session{}, err
	}
	if session.Token == "" {
		return model.Session{}, errors.New("session not found")
	}
	return session, nil
}

func (u *sessionsRepo) TokenExpired(session model.Session) bool {
	return session.Expiry.Before(time.Now())
}
