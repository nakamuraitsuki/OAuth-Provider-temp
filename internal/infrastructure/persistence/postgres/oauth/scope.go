package oauth

import "example.com/m/internal/domain/oauth/value"

// Scope の定義とテーブルはメモリに逃して簡易実装。
// どうせScopeは動的にいじったりしないので

var ScopesTable = map[int]string{
	1: value.ScopeProfileRead,
	2: value.ScopeOpenID,
}

// 逆引き用
var ScopeIDs = map[string]int{
	value.ScopeProfileRead: 1,
	value.ScopeOpenID:      2,
}
