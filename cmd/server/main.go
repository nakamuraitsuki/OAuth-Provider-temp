package main

import (
	"html/template"
	"io"

	"example.com/m/internal/infrastructure/authentication/bcrypt"
	"example.com/m/internal/infrastructure/env"
	"example.com/m/internal/infrastructure/persistence/postgres"
	"example.com/m/internal/infrastructure/persistence/postgres/auth"
	"example.com/m/internal/infrastructure/persistence/postgres/oauth"
	oauthRepoMem "example.com/m/internal/infrastructure/persistence/memory/oauth"
	"example.com/m/internal/infrastructure/persistence/postgres/user"
	hash "example.com/m/internal/infrastructure/security/bcrypt"
	"example.com/m/internal/infrastructure/security/crypto"
	webAdapter "example.com/m/internal/interface/http"
	authH "example.com/m/internal/interface/http/auth"
	oauthH "example.com/m/internal/interface/http/oauth"
	authUC "example.com/m/internal/usecase/auth"
	oauthUC "example.com/m/internal/usecase/oauth"
	userUC "example.com/m/internal/usecase/user"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type TemplateRenderer struct {
	templates *template.Template
}

func (r *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return r.templates.ExecuteTemplate(w, name, data)
}

func main() {
	dbCfg := postgres.NewPostgresConfig()
	db, err := postgres.NewClient(dbCfg)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	userRepo := user.NewUserRepository(db)
	authRepo := auth.NewCredentialRepository(db)
	clientRepo := oauthRepoMem.NewClientRepository()
	codeRepo := oauth.NewCodeRepository(db)
	tokenRepo := oauth.NewTokenRepository(db)
	passSvc := bcrypt.NewBCryptPasswordService()
	clientHash := hash.NewSecretHashService()
	codeGen := crypto.NewCodeGenerator()
	codeValidator := crypto.NewCodeValidator()
	tokenGen := crypto.NewTokenGenerator()
	tokenCredential := crypto.NewTokenCredential()

	issuerURL := env.GetString("ISSUER_URL", "http://127.0.0.2:8080")
	aUC := authUC.NewAuthInteractor(userRepo, authRepo, passSvc, issuerURL)
	uUC := userUC.NewUserInteractor(userRepo)
	authorizeUC := oauthUC.NewAuthorizeInteractor(clientRepo, codeRepo, codeGen)
	tokenUC := oauthUC.NewIssueTokenInteractor(clientRepo, codeRepo, tokenRepo, clientHash, tokenGen, codeValidator)
	refreshTokenUC := oauthUC.NewRefreshTokenInteractor(tokenRepo, tokenCredential, tokenGen)

	authHandler := authH.NewAuthHandler(aUC, uUC)
	oauthHandler := oauthH.NewOauthHandler(authorizeUC, tokenUC, refreshTokenUC)

	e := echo.New()

	cookieSecret := env.GetString("COOKIE_SECRET", "default_secret")
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(cookieSecret))))

	e.Renderer = &TemplateRenderer{
		templates: template.Must(template.ParseGlob("web/templates/*.html")),
	}

	webAdapter.InitRoutes(e, authHandler, oauthHandler)

	e.Logger.Fatal(e.Start(":8080"))
}
