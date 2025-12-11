# 🔐 Chat E2E con Diffie‑Hellman (Go + WebSockets)

Sistema de chat **punto a punto** donde los mensajes se cifran **end‑to‑end** entre navegadores.
El servidor en Go **solo retransmite JSON cifrado** y nunca ve el contenido en texto plano.

## 🎯 Objetivo

- Intercambio de claves **Diffie‑Hellman (ECDH P‑256)** entre clientes.
- Derivación de clave simétrica mediante **KDF‑SHA256**.
- Cifrado de mensajes con **AES‑GCM (256 bits)**.
- Servidor actúa como **relay tonto** (solo reenvía).
- Autenticación ligera mediante **fingerprint** de la clave compartida.
- Historial local opcional (el navegador puede conservar los mensajes ya descifrados).

## 📁 Estructura

```text
CHAT/
├── main.go          # Servidor HTTP + rutas
├── hub.go           # Gestión de clientes y broadcast (solo mensajes cifrados)
├── client.go        # Bombas de lectura/escritura WebSocket
├── websocket.go     # Upgrade HTTP → WebSocket
├── index.html       # Interfaz del chat E2E (Bootstrap)
├── static/
│   ├── style.css    # Estilos modernos
│   └── script.js    # Lógica ECDH + KDF‑SHA256 + AES‑GCM en el navegador
└── go.mod           # Módulo Go
```

## 🧠 Flujo Criptográfico (lado cliente)

1. Cada cliente genera un par de claves **ECDH P‑256** con WebCrypto.
2. Publica su **clave pública** en el canal WebSocket (`type: "key"`).
3. Al recibir la clave pública de otro usuario:
   - Aplica **ECDH** para obtener una clave compartida cruda (bits).
   - Aplica **SHA‑256** sobre esos bits (KDF‑SHA256) para obtener `keyMaterial`.
   - Importa `keyMaterial` como clave **AES‑GCM 256**.
   - Calcula un **fingerprint** (primeros 8 bytes del SHA‑256 en hex) y lo muestra en la UI.
4. Para enviar un mensaje:
   - Cifra con **AES‑GCM** (`iv` aleatorio de 12 bytes).
   - Envía por WebSocket un JSON con `{type:"msg", from, iv, ciphertext}`.
5. Para recibir:
   - Usa la misma clave AES‑GCM para descifrar y mostrar el texto plano.

👉 El servidor nunca recibe el texto plano, solo `ciphertext` e IV en base64.

## 🚀 Ejecutar

```bash
cd CHAT
go run *.go
```

Luego abre en el navegador:

```text
http://localhost:8080
```

Abre **dos pestañas o dos navegadores** distintos, ingresa nombres de usuario y conecta;
se intercambiarán claves públicas ECDH, se derivará una clave compartida y verás el
**fingerprint** para verificar por un canal externo.

## 🔒 Autenticación ligera

- Cada lado ve un **fingerprint** (hex) de la clave compartida.
- Si los dos usuarios comparan ese fingerprint por otro canal (voz, WhatsApp, etc.) y coincide,
  tienen seguridad de que no hay atacante Man‑in‑the‑Middle (dentro del modelo ligero).

## 💾 Historial local cifrado

- Los mensajes recibidos se guardan automáticamente en `localStorage` **en formato cifrado** (IV + ciphertext en base64).
- Solo se pueden descifrar cuando existe la clave compartida correspondiente.
- Usa el botón **"Cargar historial"** para descifrar y mostrar mensajes anteriores (requiere tener la clave compartida activa).
- Usa el botón **"Limpiar historial"** para eliminar todos los mensajes guardados.
- El historial se limita a los últimos 100 mensajes por usuario.

## 👥 Manejo de múltiples clientes

El sistema está diseñado para manejar múltiples clientes simultáneamente:

1. **Hub central**: el servidor Go mantiene un `Hub` que gestiona todos los clientes WebSocket conectados en un mapa thread-safe.

2. **Intercambio de claves**: cuando un cliente nuevo se conecta, el servidor le reenvía automáticamente todas las claves públicas ECDH que otros clientes han enviado previamente. Esto permite que cualquier par de usuarios establezca una clave compartida independientemente del orden de conexión.

3. **Claves independientes**: cada par de usuarios deriva su propia clave compartida mediante ECDH. Si hay 3 usuarios (A, B, C), A-B tienen una clave, A-C tienen otra, y B-C tienen otra distinta.

4. **Broadcast selectivo**: aunque el servidor retransmite mensajes a todos los clientes conectados, cada cliente solo puede descifrar los mensajes destinados a él (aquellos cifrados con la clave compartida que tiene establecida).

5. **Aislamiento**: el servidor nunca ve texto plano ni claves privadas. Solo ve JSON con `type`, `from`, `iv`, `ciphertext` y claves públicas, actuando como un relay ciego.

## 📌 Notas para tu informe / tarea

- **DH / ECDH**: implementado con `crypto.subtle` (WebCrypto) curva `P‑256`.
- **KDF‑SHA256**: se usa `deriveBits` + `digest("SHA-256")` para derivar la clave simétrica.
- **AES‑GCM**: cifrado autenticado con IV aleatorio de 96 bits, longitud de clave 256 bits.
- **Servidor Go**: no interpreta el contenido, solo reenvía JSON; actúa como "servidor tonto".
- **Historial local cifrado**: los mensajes se guardan en `localStorage` **en formato cifrado** (IV + ciphertext).
  Solo se pueden descifrar cuando existe la clave compartida. Incluye botones para cargar y limpiar el historial.
- **Manejo de múltiples clientes**: el servidor mantiene un `Hub` central que gestiona todos los clientes WebSocket conectados.
  Cuando un cliente nuevo se conecta, el servidor le reenvía automáticamente todas las claves públicas ECDH anteriores,
  permitiendo que cualquier par de usuarios establezca una clave compartida independientemente del orden de conexión.
  Cada cliente mantiene su propia clave compartida derivada con su interlocutor, y el servidor solo retransmite mensajes
  cifrados sin conocer el contenido ni las claves privadas.



