package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	hub := NewHub()
	go hub.Run()

	http.HandleFunc("/", serveHome)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWS(hub, w, r)
	})

	// Archivos estáticos (CSS, JS)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("Chat E2E - Servidor iniciado")
	log.Printf("Puerto: %s", port)
	log.Println("WebSocket endpoint: /ws")
	log.Println("Archivos estáticos: ./static")

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(" Error iniciando servidor:", err)
	}
}

// serveHome sirve la página principal del chat E2E
func serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "index.html")
}
