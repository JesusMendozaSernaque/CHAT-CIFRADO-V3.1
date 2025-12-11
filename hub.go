package main

import (
	"encoding/json"
	"log"
)

// Hub mantiene el conjunto de clientes activos y difunde mensajes cifrados.
// Importante: el servidor NO descifra mensajes, solo entiende mínimamente el tipo
// para poder reenviar claves públicas ECDH a los clientes que se conectan después.
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client

	// Mensajes de tipo "key" que ya se enviaron (claves públicas ECDH).
	// Se reenvían a los nuevos clientes al conectarse para que todos
	// puedan derivar la misma clave compartida.
	keyMessages [][]byte
}

// NewHub crea una nueva instancia del hub E2E.
func NewHub() *Hub {
	return &Hub{
		clients:     make(map[*Client]bool),
		broadcast:   make(chan []byte, 256),
		register:    make(chan *Client, 64),
		unregister:  make(chan *Client, 64),
		keyMessages: make([][]byte, 0, 16),
	}
}

// Run inicia el loop principal del hub.
func (h *Hub) Run() {
	log.Println("Hub E2E iniciado, esperando conexiones...")
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
			log.Printf("Cliente conectado. Total: %d", len(h.clients))

			// Enviar al nuevo cliente todas las claves públicas conocidas
		keyLoop:
			for _, km := range h.keyMessages {
				select {
				case client.send <- km:
				default:
					// Si el canal está lleno, cerramos el cliente problemático
					close(client.send)
					delete(h.clients, client)
					break keyLoop
				}
			}

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				log.Printf("Cliente desconectado. Total: %d", len(h.clients))
			}

		case message := <-h.broadcast:
			// Detectar tipo de mensaje
			var meta struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(message, &meta); err == nil {
				// Guardar mensajes de tipo "key" para nuevos clientes
				if meta.Type == "key" {
					h.keyMessages = append(h.keyMessages, message)
					log.Println("📥 Guardando clave pública para reenvío a nuevos clientes")
				}

				// Los mensajes de heartbeat también se retransmiten para sincronización
				if meta.Type == "heartbeat" {
					log.Println("💓 Heartbeat recibido, retransmitiendo...")
				}
			}

			// Retransmitir a todos los clientes.
			for c := range h.clients {
				select {
				case c.send <- message:
				default:
					close(c.send)
					delete(h.clients, c)
				}
			}
		}
	}
}
