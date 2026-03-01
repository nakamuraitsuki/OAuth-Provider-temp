package auth

// PasswordCredential はユーザーの認証情報を保持する。
// User.ID と 1:1 または 1:N の関係を持つ。
type PasswordCredential struct {
	UserID       string
	PasswordHash string
}
