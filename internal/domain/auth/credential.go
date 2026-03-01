package auth

// PasswordCredential はユーザーの認証情報を保持する。
// User.ID と 1:1 または 1:N の関係を持つ。
type PasswordCredential struct {
	userID       string
	passwordHash string
}

func NewPasswordCredential(userID, passwordHash string) *PasswordCredential {
	return &PasswordCredential{
		userID:       userID,
		passwordHash: passwordHash,
	}
}

func (c *PasswordCredential) UserID() string {
	return c.userID
}

func (c *PasswordCredential) PasswordHash() string {
	return c.passwordHash
}
