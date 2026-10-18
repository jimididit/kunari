package hub

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui/*
var uiContent embed.FS

func uiFileSystem() http.FileSystem {
	sub, err := fs.Sub(uiContent, "ui")
	if err != nil {
		panic("hub: embed ui subtree: " + err.Error())
	}
	return http.FS(sub)
}

func (h *Hub) handleUIRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/ui/", http.StatusFound)
}

func uiStaticHandler() http.Handler {
	files := http.StripPrefix("/ui", http.FileServer(uiFileSystem()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self'; img-src 'self' data:; "+
				"style-src 'self'; script-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		files.ServeHTTP(w, r)
	})
}
