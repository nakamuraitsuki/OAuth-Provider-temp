package user

// User は認証の主体を表すエンティティ。
type User struct {
	id           string
	username     string
	displayName  string
}

func NewUser(id, username, displayName string) *User {
	return &User{
		id:          id,
		username:    username,
		displayName: displayName,
	}
}

func (u *User) ID() string {
	return u.id
}

func (u *User) Username() string {
	return u.username
}

func (u *User) DisplayName() string {
	return u.displayName
}
