// Chat E2E con ECDH (P-256) + KDF-SHA256 + AES-GCM + Lista de Contactos

const ChatE2E = (() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let socket = null;
  let username = "";
  let keyPair = null;
  let sharedKeys = new Map(); // Map<username, {aesKey, fingerprint}>
  let currentPeer = null; // Usuario seleccionado actualmente
  let onlineUsers = new Set(); // Usuarios conectados
  let favoriteContacts = new Set(); // Contactos favoritos

  const el = {};

  // ============ UTILIDADES ============
  function log(...args) {
    console.log("[E2E]", ...args);
  }

  async function generateECDHKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
  }

  async function exportPublicKeyRaw(pubKey) {
    const raw = await crypto.subtle.exportKey("raw", pubKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
  }

  async function importPublicKeyRaw(b64) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
      "raw", bytes,
      { name: "ECDH", namedCurve: "P-256" },
      true, []
    );
  }

  async function exportPrivateKeyJwk(privKey) {
    return await crypto.subtle.exportKey("jwk", privKey);
  }

  async function importPrivateKeyJwk(jwk) {
    return crypto.subtle.importKey(
      "jwk", jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true, ["deriveBits"]
    );
  }

  async function loadOrGenerateECDHKeyPair() {
    const storeKey = `chat_e2e_ecdh_${username}`;
    try {
      const stored = localStorage.getItem(storeKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        const privateKey = await importPrivateKeyJwk(parsed.privJwk);
        const publicKey = await importPublicKeyRaw(parsed.pubRawB64);
        return { publicKey, privateKey };
      }
    } catch (e) {
      console.error("Error cargando ECDH persistente:", e);
    }

    const fresh = await generateECDHKeyPair();
    const privJwk = await exportPrivateKeyJwk(fresh.privateKey);
    const pubRawB64 = await exportPublicKeyRaw(fresh.publicKey);
    try {
      localStorage.setItem(storeKey, JSON.stringify({ privJwk, pubRawB64 }));
    } catch (e) {
      console.error("No se pudo guardar clave ECDH persistente:", e);
    }
    return fresh;
  }

  async function deriveSharedKey(theirPubKey) {
    const bits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: theirPubKey },
      keyPair.privateKey,
      256
    );

    const hash = await crypto.subtle.digest("SHA-256", bits);
    const aesKey = await crypto.subtle.importKey(
      "raw", hash,
      { name: "AES-GCM" },
      false, ["encrypt", "decrypt"]
    );

    const fpBytes = new Uint8Array(hash).slice(0, 8);
    const fingerprint = Array.from(fpBytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join(":");

    return { aesKey, fingerprint };
  }

  async function encryptMessage(plaintext, peerName) {
    const keyData = sharedKeys.get(peerName);
    if (!keyData) throw new Error("No hay clave compartida con " + peerName);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      keyData.aesKey,
      encoder.encode(plaintext)
    );

    return {
      iv: btoa(String.fromCharCode(...iv)),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    };
  }

  async function decryptMessage(ivB64, ctB64, peerName) {
    const keyData = sharedKeys.get(peerName);
    if (!keyData) throw new Error("No hay clave compartida con " + peerName);

    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));

    const plaintextBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      keyData.aesKey,
      ciphertext
    );

    return decoder.decode(plaintextBuf);
  }

  // ============ GESTIÓN DE CONTACTOS ============
  function loadFavorites() {
    const key = `chat_favorites_${username}`;
    try {
      const stored = localStorage.getItem(key);
      return stored ? new Set(JSON.parse(stored)) : new Set();
    } catch (e) {
      return new Set();
    }
  }

  function saveFavorites() {
    const key = `chat_favorites_${username}`;
    try {
      localStorage.setItem(key, JSON.stringify([...favoriteContacts]));
    } catch (e) {
      console.error("Error guardando favoritos:", e);
    }
  }

  function toggleFavorite(contactName) {
    if (favoriteContacts.has(contactName)) {
      favoriteContacts.delete(contactName);
    } else {
      favoriteContacts.add(contactName);
    }
    saveFavorites();
    updateContactsList();
  }

  function updateContactsList() {
    const container = el.contactsList;
    if (!container) {
      log("❌ Elemento contactsList no encontrado");
      return;
    }

    log("📋 Actualizando lista. Usuarios online:", onlineUsers.size, [...onlineUsers]);

    if (onlineUsers.size === 0) {
      container.innerHTML = `
        <div class="text-center text-muted small">
          <i class="bi bi-inbox"></i>
          <p class="mb-0">Esperando otros usuarios...</p>
          <p class="mb-0 mt-1"><small>Abre otra pestaña para probar</small></p>
        </div>
      `;
      if (el.onlineCount) el.onlineCount.textContent = "0";
      return;
    }

    if (el.onlineCount) el.onlineCount.textContent = onlineUsers.size;

    const contacts = [...onlineUsers].sort((a, b) => {
      const aFav = favoriteContacts.has(a);
      const bFav = favoriteContacts.has(b);
      if (aFav && !bFav) return -1;
      if (!aFav && bFav) return 1;
      return a.localeCompare(b);
    });

    container.innerHTML = contacts.map(contactName => {
      const keyData = sharedKeys.get(contactName);
      const isActive = currentPeer === contactName;
      const isFav = favoriteContacts.has(contactName);
      const fp = keyData ? keyData.fingerprint : "Sin clave";

      return `
        <div class="contact-item ${isActive ? 'active' : ''}" data-contact="${contactName}">
          <div class="d-flex justify-content-between align-items-start">
            <div class="flex-grow-1">
              <div class="contact-name">
                <span class="status-dot status-online"></span>
                ${contactName}
                ${isFav ? '<i class="bi bi-star-fill text-warning ms-1"></i>' : ''}
              </div>
              <div class="contact-fingerprint">${fp}</div>
            </div>
            <button class="btn btn-favorite btn-outline-warning" data-favorite="${contactName}">
              <i class="bi ${isFav ? 'bi-star-fill' : 'bi-star'}"></i>
            </button>
          </div>
        </div>
      `;
    }).join('');

    // Event listeners para contactos
    container.querySelectorAll('.contact-item').forEach(item => {
      item.addEventListener('click', (e) => {
        if (e.target.closest('.btn-favorite')) return;
        const contactName = item.dataset.contact;
        selectPeer(contactName);
      });
    });

    container.querySelectorAll('.btn-favorite').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const contactName = btn.dataset.favorite;
        toggleFavorite(contactName);
      });
    });

    log("✅ Lista actualizada con", contacts.length, "contactos");
  }

  function selectPeer(peerName) {
    currentPeer = peerName;
    updateContactsList();
    
    const badge = document.getElementById('currentPeer');
    if (badge) {
      badge.textContent = `Chateando con: ${peerName}`;
      badge.style.display = 'inline-block';
    }

    const keyData = sharedKeys.get(peerName);
    if (keyData) {
      el.fingerprint.textContent = keyData.fingerprint;
      if (el.sharedInfo) {
        el.sharedInfo.value = `Chateando con: ${peerName}\nFingerprint: ${keyData.fingerprint}`;
      }
    }

    appendMessage({
      from: "Sistema",
      text: `Ahora chateando con ${peerName}`,
      isOwn: false,
      info: ""
    });

    setControlsEnabled(true);
  }

  // ============ MENSAJES UI ============
  function appendMessage({ from, text, isOwn, info }) {
    const wrapper = document.createElement("div");
    wrapper.className = `message-row ${isOwn ? "text-end" : "text-start"}`;

    const sender = document.createElement("div");
    sender.className = "meta";
    sender.textContent = from;

    const bubble = document.createElement("div");
    bubble.className = `message-bubble ${isOwn ? "message-own" : "message-other"}`;
    bubble.textContent = text;

    const cipherInfo = document.createElement("div");
    cipherInfo.className = "cipher-info";
    cipherInfo.textContent = info || "";

    wrapper.appendChild(sender);
    wrapper.appendChild(bubble);
    wrapper.appendChild(cipherInfo);

    el.messages.appendChild(wrapper);
    el.messages.scrollTop = el.messages.scrollHeight;
  }

  function setStatus(connected) {
    if (connected) {
      el.statusBadge.className = "badge bg-success";
      el.statusBadge.innerHTML = '<i class="bi bi-shield-check"></i> Conectado';
    } else {
      el.statusBadge.className = "badge bg-danger";
      el.statusBadge.innerHTML = '<i class="bi bi-plug"></i> Desconectado';
    }
  }

  function setControlsEnabled(connected) {
    el.connectBtn.disabled = connected;
    el.disconnectBtn.disabled = !connected;
    el.messageInput.disabled = !connected || !currentPeer;
    el.sendBtn.disabled = !connected || !currentPeer;
  }

  // ============ CONEXIÓN WEBSOCKET ============
  async function connect() {
    username = el.username.value.trim();
    if (!username) {
      alert("Ingresa un nombre de usuario");
      return;
    }

    favoriteContacts = loadFavorites();
    keyPair = await loadOrGenerateECDHKeyPair();
    const myPubB64 = await exportPublicKeyRaw(keyPair.publicKey);

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsURL = `${protocol}//${window.location.host}/ws`;

    log("🔌 Conectando a", wsURL);
    socket = new WebSocket(wsURL);

    socket.onopen = () => {
      log("✅ WebSocket abierto");
      setStatus(true);
      setControlsEnabled(true);

      const msg = {
        type: "key",
        from: username,
        publicKey: myPubB64,
        ts: Date.now(),
      };
      socket.send(JSON.stringify(msg));
      log("📤 Clave pública enviada");

      appendMessage({
        from: "Sistema",
        text: "Conectado. Esperando otros usuarios...",
        isOwn: false,
        info: ""
      });
    };

    socket.onmessage = async event => {
      try {
        const data = JSON.parse(event.data);
        log("📨 Mensaje recibido:", data.type, "from:", data.from);

        if (data.type === "key") {
          if (data.from === username) {
            log("⏭️ Ignorando mi propia clave");
            return;
          }

          log("📥 Clave recibida de:", data.from);
          onlineUsers.add(data.from);

          if (!sharedKeys.has(data.from)) {
            log("🔐 Estableciendo clave compartida con", data.from);
            const theirPub = await importPublicKeyRaw(data.publicKey);
            const keyData = await deriveSharedKey(theirPub);
            sharedKeys.set(data.from, keyData);

            appendMessage({
              from: "Sistema",
              text: `✅ ${data.from} se conectó (clave establecida)`,
              isOwn: false,
              info: `Fingerprint: ${keyData.fingerprint}`
            });
          }

          log("👥 Usuarios online actuales:", [...onlineUsers]);
          updateContactsList();
          return;
        }

        if (data.type === "msg") {
          const keyData = sharedKeys.get(data.from);
          if (!keyData) {
            log("⚠️ Mensaje de usuario sin clave:", data.from);
            return;
          }

          const plaintext = await decryptMessage(data.iv, data.ciphertext, data.from).catch(err => {
            console.error("❌ Error descifrando:", err);
            return null;
          });

          if (plaintext == null) return;

          appendMessage({
            from: data.from,
            text: plaintext,
            isOwn: false,
            info: "Cifrado E2E (AES-GCM 256)"
          });
        }
      } catch (e) {
        console.error("❌ Error procesando mensaje:", e);
      }
    };

    socket.onclose = () => {
      log("🔌 WebSocket cerrado");
      setStatus(false);
      setControlsEnabled(false);
      onlineUsers.clear();
      currentPeer = null;
      updateContactsList();
    };

    socket.onerror = err => {
      console.error("❌ Error WebSocket:", err);
      alert("Error en la conexión");
    };
  }

  function disconnect() {
    if (socket) {
      socket.close();
      socket = null;
    }
    el.messages.innerHTML = "";
    sharedKeys.clear();
    onlineUsers.clear();
    currentPeer = null;
    updateContactsList();
  }

  async function sendMessage() {
    const text = el.messageInput.value.trim();
    if (!text || !socket || socket.readyState !== WebSocket.OPEN) return;

    if (!currentPeer) {
      alert("Selecciona un contacto de la lista primero");
      return;
    }

    if (!sharedKeys.has(currentPeer)) {
      alert("No hay clave compartida con " + currentPeer);
      return;
    }

    try {
      const { iv, ciphertext } = await encryptMessage(text, currentPeer);
      const msg = {
        type: "msg",
        from: username,
        to: currentPeer,
        iv,
        ciphertext,
        ts: Date.now(),
      };

      socket.send(JSON.stringify(msg));
      log("📤 Mensaje enviado a", currentPeer);
      
      appendMessage({
        from: "Tú",
        text: text,
        isOwn: true,
        info: `Enviado a ${currentPeer}`
      });

      el.messageInput.value = "";
    } catch (e) {
      console.error("❌ Error enviando mensaje:", e);
      alert("Error al enviar el mensaje");
    }
  }

  function init() {
    log("🚀 Inicializando Chat E2E...");

    el.username = document.getElementById("username");
    el.connectBtn = document.getElementById("connectBtn");
    el.disconnectBtn = document.getElementById("disconnectBtn");
    el.messageInput = document.getElementById("messageInput");
    el.sendBtn = document.getElementById("sendBtn");
    el.messages = document.getElementById("messages");
    el.statusBadge = document.getElementById("statusBadge");
    el.fingerprint = document.getElementById("fingerprint");
    el.sharedInfo = document.getElementById("sharedInfo");
    el.contactsList = document.getElementById("contactsList");
    el.onlineCount = document.getElementById("onlineCount");

    if (!el.contactsList) {
      console.error("❌ ERROR: No se encontró el elemento #contactsList");
    } else {
      log("✅ Elemento #contactsList encontrado");
    }

    setStatus(false);
    setControlsEnabled(false);

    el.connectBtn.addEventListener("click", connect);
    el.disconnectBtn.addEventListener("click", disconnect);
    el.sendBtn.addEventListener("click", sendMessage);
    el.messageInput.addEventListener("keypress", e => {
      if (e.key === "Enter") sendMessage();
    });

    updateContactsList();
    log("✅ Chat E2E inicializado correctamente");
  }

  return { init };
})();

// =============== INICIALIZACIÓN ===============
document.addEventListener("DOMContentLoaded", () => {
  console.log("🎬 DOM cargado, iniciando aplicación...");
  ChatE2E.init();

  // Botón guardar chat cifrado
  const saveBtn = document.getElementById("saveChatBtn");
  if (saveBtn) {
    saveBtn.addEventListener("click", () => {
      const messages = [...document.querySelectorAll(".message-bubble")];
      if (messages.length === 0) {
        alert("No hay mensajes para guardar");
        return;
      }

      const text = messages.map(m => m.innerText).join("\n");
      const blob = new Blob([text], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "chat_uss.txt";
      a.click();
      URL.revokeObjectURL(url);
      console.log("💾 Chat guardado");
    });
  }

  // Botón limpiar historial
  const clearBtn = document.getElementById("clearHistoryBtn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (confirm("¿Eliminar todo el historial?")) {
        document.getElementById("messages").innerHTML = "";
        alert("Historial eliminado");
        console.log("🗑️ Historial limpiado");
      }
    });
  }

  // Botón descifrar archivo
  const decryptBtn = document.getElementById("decryptBtn");
  if (decryptBtn) {
    decryptBtn.addEventListener("click", () => {
      alert("Funcionalidad de descifrado: pendiente de implementar");
    });
  }

  console.log("✅ Todos los event listeners configurados");
});