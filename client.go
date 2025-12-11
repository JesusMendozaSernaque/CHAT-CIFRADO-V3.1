package main

import (
	"bytes"
	"log"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 4096
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

// Client representa un cliente WebSocket activo.
// El servidor NO conoce claves ni descifra mensajes.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// readPump lee mensajes desde el WebSocket y los envía al hub.
// Los mensajes ya vienen cifrados desde el cliente.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Error WebSocket: %v", err)
			}
			break
		}
		message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))

		// El mensaje es JSON ya cifrado (ciphertext, IV, tipo, etc.).
		// Solo lo reenviamos al hub.
		select {
		case c.hub.broadcast <- message:
		default:
			log.Println("Hub ocupado, descartando mensaje")
		}
	}
}

// writePump escribe mensajes desde el hub hacia la conexión WebSocket.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Canal cerrado desde el hub.
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
