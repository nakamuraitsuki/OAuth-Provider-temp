package auth

type LoginRequest struct {
	Username string `form:"username" validate:"required"`
	Password string `form:"password" validate:"required"`
}

type UserResponse struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}
