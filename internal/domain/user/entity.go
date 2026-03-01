package user

// User は認証の主体を表すエンティティ。
type User struct {
	ID           string
	Username     string
	DisplayName  string
}
