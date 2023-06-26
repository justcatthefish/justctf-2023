package main

import (
	"net/http"
	"os"
)

func basicAuthFunc(username, password string) func(h http.HandlerFunc) http.HandlerFunc {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != username || pass != password {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", 401)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

func run() error {
	Log.Info("starting server")

	if err := CleanAllSandbox(); err != nil {
		return err
	}

	db, err := NewDB()
	if err != nil {
		return err
	}
	if err := db.Init(); err != nil {
		return err
	}

	authFunc := basicAuthFunc("p4", Config.HttpPassword)

	mux1 := http.NewServeMux()
	if len(Config.HttpPassword) > 0 {
		mux1.HandleFunc("/", authFunc(SandboxHandler(db)))
	} else {
		mux1.HandleFunc("/", SandboxHandler(db))
	}

	mux2 := http.NewServeMux()
	mux2.HandleFunc("/", ProxyHandler(db))

	return http.ListenAndServe(Config.Listen, &redirectByHostHandler{
		db:             db,
		handlerSandbox: mux1,
		handlerProxy:   mux2,
	})
}

func main() {
	if err := run(); err != nil {
		Log.WithError(err).Error("server shutdown with error")
		os.Exit(1)
	}
}
