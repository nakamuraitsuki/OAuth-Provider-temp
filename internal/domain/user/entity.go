package user

import "github.com/google/uuid"

// User は認証の主体を表すエンティティ。
type User struct {
	id           uuid.UUID
	username     string
	displayName  string
}

func NewUser(id uuid.UUID, username, displayName string) *User {
	return &User{
		id:          id,
		username:    username,
		displayName: displayName,
	}
}

func (u *User) ID() uuid.UUID {
	return u.id
}

func (u *User) Username() string {
	return u.username
}

func (u *User) DisplayName() string {
	return u.displayName
}
