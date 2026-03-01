package server

import (
	"html/template"
	"io"
	"os"

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
	secretKey := os.Getenv("SESSION_SECRET_KEY")
	if secretKey == "" {
		panic("SESSION_SECRET_KEY environment variable is required")
	}
	e := echo.New()

	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())
	e.Use(session.Middleware(sessions.NewCookieStore([]byte(secretKey))))

	renderer := &TemplateRenderer{
		templates: template.Must(
			template.ParseGlob("web/template/*.html"),
		),
	}
	e.Renderer = renderer
}
