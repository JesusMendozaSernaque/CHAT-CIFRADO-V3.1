// Chat E2E con ECDH (P-256) + KDF-SHA256 + AES-GCM

const ChatE2E = (() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  let socket = null;
  let username = "";
  let keyPair = null;          // { publicKey, privateKey } ECDH
  let sharedKey = null;        // CryptoKey AES-GCM derivado
  let sharedFingerprint = "";  // String hexadecimal corto
  let establishedPeers = new Set(); // Rastrear peers con clave ya establecida

  // Elementos de la UI
  const el = {};

  // ------------ Expuestos para uso externo ------------
  function getSharedKey() {
    return sharedKey;
  }
  function getFingerprint() {
    return sharedFingerprint;
  }
  // ----------------------------------------------------

  // Utilidades -------------------------------------------------------
  function log(...args) {
    console.log("[E2E]", ...args);
  }

  async function generateECDHKeyPair() {
    return crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
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
      "raw",
      bytes,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  }

  // Persistencia de peers establecidos (permanente, nunca se borra)
  function hasEverEstablishedWith(peerName) {
    const storeKey = `chat_e2e_ever_established_${username}_${peerName}`;
    return localStorage.getItem(storeKey) === "true";
  }

  function markEstablishedWith(peerName) {
    const storeKey = `chat_e2e_ever_established_${username}_${peerName}`;
    localStorage.setItem(storeKey, "true");
  }

  function loadEstablishedPeers() {
    const storeKey = `chat_e2e_peers_${username}`;
    try {
      const stored = localStorage.getItem(storeKey);
      if (stored) {
        return new Set(JSON.parse(stored));
      }
    } catch (e) {
      console.error("Error cargando peers establecidos:", e);
    }
    return new Set();
  }

  function saveEstablishedPeers() {
    const storeKey = `chat_e2e_peers_${username}`;
    try {
      localStorage.setItem(storeKey, JSON.stringify([...establishedPeers]));
    } catch (e) {
      console.error("Error guardando peers establecidos:", e);
    }
  }

  // Persistencia de claves ECDH (para fingerprint estable y descifrar historial)
  async function exportPrivateKeyJwk(privKey) {
    return await crypto.subtle.exportKey("jwk", privKey);
  }

  async function importPrivateKeyJwk(jwk) {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
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
    // 1) ECDH: derivar bits crudos
    const bits = await crypto.subtle.deriveBits(
      {
        name: "ECDH",
        public: theirPubKey,
      },
      keyPair.privateKey,
      256
    );

    // 2) KDF-SHA256: hash de los bits -> key material
    const hash = await crypto.subtle.digest("SHA-256", bits);

    // 3) Importar como clave AES-GCM (256 bits)
    const aesKey = await crypto.subtle.importKey(
      "raw",
      hash,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    // 4) Fingerprint: primeros 8 bytes del hash en hex
    const fpBytes = new Uint8Array(hash).slice(0, 8);
    const fingerprint = Array.from(fpBytes)
      .map(b => b.toString(16).padStart(2, "0"))
      .join(":");

    return { aesKey, fingerprint };
  }

  async function encryptMessage(plaintext) {
    if (!sharedKey) throw new Error("No hay clave compartida aún");

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      sharedKey,
      encoder.encode(plaintext)
    );

    return {
      iv: btoa(String.fromCharCode(...iv)),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    };
  }

  async function decryptMessage(ivB64, ctB64) {
    if (!sharedKey) throw new Error("No hay clave compartida para descifrar");

    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));

    const plaintextBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      sharedKey,
      ciphertext
    );

    return decoder.decode(plaintextBuf);
  }

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
    el.messageInput.disabled = !connected;
    el.sendBtn.disabled = !connected;
  }

  function showSharedInfo() {
    if (!sharedKey || !sharedFingerprint) {
      el.fingerprint.textContent = "---";
      el.sharedInfo.value =
        "Aún no se ha establecido una clave compartida.\n" +
        "Cuando exista al menos otro usuario conectado, se intercambiarán claves públicas ECDH.";
      if (el.loadHistoryBtn) el.loadHistoryBtn.disabled = true;
      return;
    }

    el.fingerprint.textContent = sharedFingerprint;
    el.sharedInfo.value =
      "Clave compartida establecida (no se muestra la clave real).\n" +
      "Fingerprint (SHA-256, 8 bytes): " +
      sharedFingerprint +
      "\n\n" +
      "Verifica este fingerprint con tu contacto por otro canal.\n" +
      "Si coincide, tienes autenticación ligera del canal E2E.";
    if (el.loadHistoryBtn) el.loadHistoryBtn.disabled = false;
  }

  // Historial local cifrado ---------------------------------------------

  function getHistoryKey() {
    return `chat_e2e_history_${username}`;
  }

  async function saveMessageToHistory(from, iv, ciphertext, timestamp) {
    if (!sharedKey) return; // Solo guardar si hay clave compartida

    try {
      const historyKey = getHistoryKey();
      const history = JSON.parse(localStorage.getItem(historyKey) || "[]");

      // Guardar el mensaje cifrado (no descifrado)
      history.push({
        from,
        iv,
        ciphertext,
        timestamp: timestamp || Date.now(),
        fingerprint: sharedFingerprint,
      });

      // Limitar a últimos 100 mensajes
      if (history.length > 100) {
        history.shift();
      }

      localStorage.setItem(historyKey, JSON.stringify(history));
      log("Mensaje guardado en historial local (cifrado)");
    } catch (e) {
      console.error("Error guardando en historial:", e);
    }
  }

  async function loadHistory() {
    if (!sharedKey) {
      alert("Primero debes establecer una clave compartida");
      return;
    }

    try {
      const historyKey = getHistoryKey();
      const history = JSON.parse(localStorage.getItem(historyKey) || "[]");

      if (history.length === 0) {
        alert("No hay historial guardado");
        return;
      }

      const candidates = history.filter(h => h.fingerprint === sharedFingerprint);
      if (candidates.length === 0) {
        alert("No hay historial para la clave actual. La clave pudo haber cambiado.");
        return;
      }
      log(`Cargando ${candidates.length} mensajes del historial...`);

      let loaded = 0;
      for (const item of candidates) {
        try {
          const plaintext = await decryptMessage(item.iv, item.ciphertext);
          const date = new Date(item.timestamp);

          appendMessage({
            from: item.from,
            text: plaintext,
            isOwn: item.from === username,
            info: `Historial local (${date.toLocaleString()})`,
          });
          loaded++;
        } catch (e) {
          console.error("Error descifrando mensaje del historial:", e);
        }
      }

      if (loaded > 0) {
        appendMessage({
          from: "Sistema",
          text: `Cargados ${loaded} mensajes del historial local`,
          isOwn: false,
          info: "",
        });
      } else {
        alert("No se pudieron descifrar mensajes del historial con esta clave.");
      }
    } catch (e) {
      console.error("Error cargando historial:", e);
      alert("Error al cargar el historial");
    }
  }

  function clearHistory() {
    if (!confirm("¿Estás seguro de eliminar todo el historial local?")) {
      return;
    }

    try {
      const historyKey = getHistoryKey();
      localStorage.removeItem(historyKey);
      log("Historial local eliminado");
      alert("Historial local eliminado");
    } catch (e) {
      console.error("Error eliminando historial:", e);
    }
  }

  // Lógica de conexión -----------------------------------------------

  async function connect() {
    username = el.username.value.trim();
    if (!username) {
      alert("Ingresa un nombre de usuario");
      return;
    }

    if (!window.isSecureContext) {
      alert(
        "Para que WebCrypto funcione completamente se recomienda usar HTTPS o localhost."
      );
    }

    // 1) Cargar peers ya establecidos
    establishedPeers = loadEstablishedPeers();

    // 2) Generar par de claves ECDH
    keyPair = await loadOrGenerateECDHKeyPair();
    const myPubB64 = await exportPublicKeyRaw(keyPair.publicKey);

    // 3) Abrir WebSocket
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsURL = `${protocol}//${window.location.host}/ws`;

    log("Conectando a", wsURL);
    socket = new WebSocket(wsURL);

    socket.onopen = () => {
      log("WebSocket abierto");
      setStatus(true);
      setControlsEnabled(true);

      // Enviar mi clave pública al resto
      const msg = {
        type: "key",
        from: username,
        publicKey: myPubB64,
        ts: Date.now(),
      };
      socket.send(JSON.stringify(msg));

      appendMessage({
        from: "Sistema",
        text: "Conectado. Clave pública ECDH enviada.",
        isOwn: false,
        info: "",
      });
    };

    socket.onmessage = async event => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === "key") {
          // Clave pública de otro usuario
          if (data.from === username) return; // Ignorar eco propio

          // Si ya establecimos clave con este peer alguna vez, ignorar y no mostrar mensaje
          if (hasEverEstablishedWith(data.from)) {
            log(`Clave de ${data.from} ya fue establecida anteriormente, omitiendo mensaje`);
            // Aún derivar la clave para poder descifrar
            const theirPub = await importPublicKeyRaw(data.publicKey);
            const { aesKey, fingerprint } = await deriveSharedKey(theirPub);
            sharedKey = aesKey;
            sharedFingerprint = fingerprint;
            showSharedInfo();
            return;
          }

          // Si ya establecimos clave con este peer en esta sesión, ignorar
          if (establishedPeers.has(data.from)) {
            log(`Clave de ${data.from} ya procesada, omitiendo mensaje duplicado`);
            return;
          }

          log("Clave pública recibida de", data.from);

          const theirPub = await importPublicKeyRaw(data.publicKey);
          const { aesKey, fingerprint } = await deriveSharedKey(theirPub);
          sharedKey = aesKey;
          sharedFingerprint = fingerprint;
          establishedPeers.add(data.from);
          saveEstablishedPeers();
          markEstablishedWith(data.from); // Marcar permanentemente
          showSharedInfo();

          appendMessage({
            from: "Sistema",
            text: `Clave compartida establecida con ${data.from}`,
            isOwn: false,
            info: `Fingerprint: ${fingerprint}`,
          });

          // Intentar cargar historial automáticamente al establecer clave
          setTimeout(() => {
            const historyKey = getHistoryKey();
            const history = JSON.parse(localStorage.getItem(historyKey) || "[]");
            if (history.length > 0) {
              log("Historial encontrado, puedes cargarlo con el botón");
            }
          }, 500);
          return;
        }

        if (data.type === "msg") {
          if (!sharedKey) {
            appendMessage({
              from: "Sistema",
              text:
                "Mensaje cifrado recibido pero aún no hay clave compartida. " +
                "Espera el intercambio de claves.",
              isOwn: false,
              info: "",
            });
            return;
          }

          const plaintext = await decryptMessage(
            data.iv,
            data.ciphertext
          ).catch(err => {
            console.error("Error al descifrar:", err);
            return null;
          });
          if (plaintext == null) return;

          appendMessage({
            from: data.from,
            text: plaintext,
            isOwn: data.from === username,
            info: "Recibido cifrado (AES-GCM, 256 bits)",
          });

          // Guardar en historial local (cifrado)
          await saveMessageToHistory(data.from, data.iv, data.ciphertext, data.ts);
          return;
        }
      } catch (e) {
        console.error("Error procesando mensaje:", e);
      }
    };

    socket.onclose = () => {
      log("WebSocket cerrado");
      setStatus(false);
      setControlsEnabled(false);
      sharedKey = null;
      sharedFingerprint = "";
      // NO limpiar establishedPeers para evitar duplicados en reconexión
      showSharedInfo();
    };

    socket.onerror = err => {
      console.error("Error WebSocket:", err);
      alert("Error en la conexión WebSocket");
    };
  }

  function disconnect() {
  if (socket) {
    socket.close();
    socket = null;
  }

  // 🔥 Limpiar el área del chat al desconectar
  if (el.messages) {
    el.messages.innerHTML = "";
  }

  // Opcional: También limpiar fingerprint
  sharedKey = null;
  sharedFingerprint = "";
  showSharedInfo();
}


  async function sendMessage() {
    const text = el.messageInput.value.trim();
    if (!text || !socket || socket.readyState !== WebSocket.OPEN) return;

    if (!sharedKey) {
      alert(
        "Aún no se ha establecido una clave compartida con otro usuario.\n" +
        "Espera a que se intercambien las claves públicas."
      );
      return;
    }

    const { iv, ciphertext } = await encryptMessage(text);
    const msg = {
      type: "msg",
      from: username,
      iv,
      ciphertext,
      ts: Date.now(),
    };

    socket.send(JSON.stringify(msg));
    el.messageInput.value = "";
  }

  function init() {
    el.username = document.getElementById("username");
    el.connectBtn = document.getElementById("connectBtn");
    el.disconnectBtn = document.getElementById("disconnectBtn");
    el.messageInput = document.getElementById("messageInput");
    el.sendBtn = document.getElementById("sendBtn");
    el.messages = document.getElementById("messages");
    el.statusBadge = document.getElementById("statusBadge");
    el.fingerprint = document.getElementById("fingerprint");
    el.sharedInfo = document.getElementById("sharedInfo");
    el.loadHistoryBtn = document.getElementById("loadHistoryBtn");
    el.clearHistoryBtn = document.getElementById("clearHistoryBtn");

    setStatus(false);
    setControlsEnabled(false);
    showSharedInfo();

    el.connectBtn.addEventListener("click", connect);
    el.disconnectBtn.addEventListener("click", disconnect);
    el.sendBtn.addEventListener("click", sendMessage);
    el.messageInput.addEventListener("keypress", e => {
      if (e.key === "Enter") sendMessage();
    });

    if (el.loadHistoryBtn) {
      el.loadHistoryBtn.addEventListener("click", loadHistory);
    }
    if (el.clearHistoryBtn) {
      el.clearHistoryBtn.addEventListener("click", clearHistory);
    }
  }

  return { init, getSharedKey, getFingerprint };
})();

// ------------------- Inicializar y conectar botones -------------------
window._chat_export = ChatE2E; // exponer para depuración si quieres

document.addEventListener("DOMContentLoaded", () => {
  // Inicializar el módulo
  ChatE2E.init();

  // Guardar chat cifrado - usa la sharedKey y fingerprint expuestos
  const exportBtn = document.getElementById("saveChatBtn");
  const statusEl = document.getElementById("saveStatus");
  if (exportBtn) {
    exportBtn.addEventListener("click", async () => {
      try {
        const sharedKey = ChatE2E.getSharedKey();
        const fingerprint = ChatE2E.getFingerprint();

        if (!sharedKey) {
          alert("No hay clave compartida todavía uwu");
          return;
        }

        const messages = [...document.querySelectorAll(".message-bubble")];
        if (messages.length === 0) {
          alert("No hay mensajes para guardar uwu");
          return;
        }

        let textToEncrypt = messages.map(m => m.innerText).join("\n");

        // Cifrar
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(textToEncrypt);
        const ciphertext = await crypto.subtle.encrypt(
          { name: "AES-GCM", iv },
          sharedKey,
          encoded
        );

        const ivB64 = btoa(String.fromCharCode(...iv));
        const ctB64 = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));

        const finalText =
`----- CHAT CIFRADO AES-GCM -----
FINGERPRINT: ${fingerprint}
IV: ${ivB64}

${ctB64}`;

        const blob = new Blob([finalText], { type: "text/plain" });
        const url = URL.createObjectURL(blob);

        const a = document.createElement("a");
        a.href = url;
        a.download = "chat_cifrado.txt";
        a.click();

        URL.revokeObjectURL(url);

        if (statusEl) {
          statusEl.style.display = "block";
          statusEl.textContent = "🔐 Archivo cifrado generado correctamente.";
        }
      } catch (e) {
        console.error("Error cifrando/guardando chat:", e);
        alert("Error cifrando el archivo uwu");
      }
    });
  }

  // Mantener compatibilidad con botón limpiar historial si existe
  const clearBtn = document.getElementById("clearHistoryBtn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (confirm("¿Eliminar historial local?")) {
        const historyKey = `chat_e2e_history_${(document.getElementById("username")?.value||"")}`;
        localStorage.removeItem(historyKey);
        alert("Historial local eliminado");
      }
    });
  }

  // ------------------ DESCIFRAR ARCHIVO ------------------
  const decryptBtn = document.getElementById("decryptBtn");
  const fileInput = document.getElementById("fileDecrypt");
  const outputEl = document.getElementById("decryptOutput");

  if (decryptBtn && fileInput && outputEl) {
    decryptBtn.addEventListener("click", async () => {
      if (!fileInput.files.length) {
        alert("Selecciona un archivo primero");
        return;
      }

      const sharedKey = ChatE2E.getSharedKey();
      if (!sharedKey) {
        alert("Primero debes tener una clave compartida establecida.");
        return;
      }

      try {
        const file = fileInput.files[0];
        const text = await file.text();

        // Extraer IV y ciphertext (admite archivos con saltos/espacios)
        const ivMatch = text.match(/IV:\s*([A-Za-z0-9+/=]+)/);
        const ctMatch = text.match(/^[A-Za-z0-9+/=]+\s*$/m); // última línea base64 (ciphertext)

        if (!ivMatch || !ctMatch) {
          alert("Formato inválido del archivo. Asegúrate de que sea un chat_cifrado.txt generado por la app.");
          return;
        }

        const ivB64 = ivMatch[1].trim();
        // Buscar el bloque de ciphertext (última porción que no es header)
        // Tomamos la última línea base64 larga del archivo
        const lines = text.split("\n").map(l => l.trim()).filter(l => l.length > 0);
        // Encontrar la línea que es el ciphertext (la que viene después del IV y no es header)
        let ctLine = null;
        let seenIV = false;
        for (const l of lines) {
          if (l.startsWith("IV:")) { seenIV = true; continue; }
          if (!seenIV) continue;
          if (l.startsWith("FINGERPRINT:") || l.startsWith("-----")) continue;
          // la primera línea no-header después del IV la tomamos como ciphertext
          ctLine = l;
          break;
        }
        if (!ctLine) {
          alert("No se encontró el ciphertext en el archivo.");
          return;
        }

        const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
        const ciphertext = Uint8Array.from(atob(ctLine), c => c.charCodeAt(0));

        const decrypted = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv },
          sharedKey,
          ciphertext
        );

        const plaintext = new TextDecoder().decode(decrypted);
        outputEl.value = plaintext;
      } catch (e) {
        console.error("Error descifrando archivo:", e);
        alert("No se pudo descifrar. Quizá la clave no coincide o el archivo está corrupto.");
      }
    });
  }
});

