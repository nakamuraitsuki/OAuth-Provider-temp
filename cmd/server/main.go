package main

import (
	"html/template"
	"io"
	"net/http"

	"example.com/m/internal/infrastructure/authentication/bcrypt"
	"example.com/m/internal/infrastructure/env"
	oauthRepoMem "example.com/m/internal/infrastructure/persistence/memory/oauth"
	"example.com/m/internal/infrastructure/persistence/postgres"
	"example.com/m/internal/infrastructure/persistence/postgres/auth"
	"example.com/m/internal/infrastructure/persistence/postgres/oauth"
	"example.com/m/internal/infrastructure/persistence/postgres/user"
	hash "example.com/m/internal/infrastructure/security/bcrypt"
	"example.com/m/internal/infrastructure/security/crypto"
	jw "example.com/m/internal/infrastructure/security/oidc"
	webAdapter "example.com/m/internal/interface/http"
	authH "example.com/m/internal/interface/http/auth"
	oauthH "example.com/m/internal/interface/http/oauth"
	oidcH "example.com/m/internal/interface/http/oidc"
	userH "example.com/m/internal/interface/http/user"
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

	issuerURL := env.GetString("ISSUER_URL", "http://127.0.0.2:8080")
	jwtSecret, err := jw.LoadPrivateKey("creds/private.pem")
	if err != nil {
		panic(err)
	}
	kid, err := jw.GenerateKID(jwtSecret)
	if err != nil {
		panic(err)
	}

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
	identityService := jw.NewIdentityService(jwtSecret, kid)

	aUC := authUC.NewAuthInteractor(userRepo, authRepo, passSvc, issuerURL)
	uUC := userUC.NewUserInteractor(userRepo)
	authorizeUC := oauthUC.NewAuthorizeInteractor(clientRepo, codeRepo, codeGen)
	tokenUC := oauthUC.NewIssueTokenInteractor(userRepo, clientRepo, codeRepo, tokenRepo, clientHash, tokenGen, codeValidator, identityService, issuerURL)
	refreshTokenUC := oauthUC.NewRefreshTokenInteractor(tokenRepo, tokenCredential, tokenGen)
	verifyTokenUC := oauthUC.NewVerifyTokenUseCase(tokenRepo, tokenCredential)

	authHandler := authH.NewAuthHandler(aUC, uUC)
	oauthHandler := oauthH.NewOauthHandler(authorizeUC, tokenUC, refreshTokenUC)
	userHandler := userH.NewUserHandler(uUC, verifyTokenUC)
	oidcHandler := oidcH.NewJWKSHandler(jw.NewJWKSResonse(jwtSecret, kid))

	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		// フロントエンドのドメイン（開発中は http://localhost:3000 など）を指定
		// もしくは、全てのオリジンを許可する場合は AllowOrigins: []string{"*"}
		// ただし、AllowCredentials: true のときは "*" は使えないので具体的に書くのが安全
		AllowOrigins: []string{"http://localhost", "http://localhost:3000", "http://127.0.0.1:3000"},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		// クッキー（セッション）をフロントエンドとやり取りするために必須
		AllowCredentials: true,
	}))
	cookieSecret := env.GetString("COOKIE_SECRET", "default_secret")
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())
	store := sessions.NewCookieStore([]byte(cookieSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}
	e.Use(session.Middleware(store))

	e.Renderer = &TemplateRenderer{
		templates: template.Must(template.ParseGlob("web/templates/*.html")),
	}

	// OIDC Discovery 関連をグループ化
	wellKnown := e.Group("/.well-known")
	{
		// GET /.well-known/jwks.json
		wellKnown.GET("/jwks.json", oidcHandler.Handle)
	}

	webAdapter.InitRoutes(e, authHandler, oauthHandler, userHandler)

	e.Logger.Fatal(e.Start(":8080"))
}
