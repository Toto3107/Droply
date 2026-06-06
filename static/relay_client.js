/**
 * droply relay client  —  relay_client.js
 * ==========================================
 * Runs in the browser. Handles all communication with the relay server.
 *
 * WHAT THIS DOES
 * ──────────────
 * Sender side:
 *   1. createSession()     → gets session_id, PIN, mgmt_token from relay
 *   2. uploadFile(file)    → slices file into 2MB chunks, encrypts each,
 *                            uploads with progress callback
 *
 * Receiver side:
 *   1. joinSession()       → verifies PIN, gets file list
 *   2. downloadFile()      → fetches each chunk, decrypts, reassembles,
 *                            triggers browser save-file dialog
 *   3. connectWS()         → opens WebSocket for live push notifications
 *
 * CRYPTO (Web Crypto API — no external deps)
 * ──────────────────────────────────────────
 * Key derivation:  HKDF-SHA-256(PIN, session_id) → 256-bit AES key
 * Encryption:      AES-256-GCM per chunk
 * Wire format:     IV(12 bytes) | ciphertext+tag
 *
 * WHY Web Crypto:
 *   - Built into every modern browser — no library download needed
 *   - Hardware-accelerated on most devices
 *   - Auditable — the browser's implementation, not ours
 *   - Works completely offline after first page load
 *
 * USAGE
 * ─────
 * const relay = new DroplyRelay("https://your-relay.fly.dev");
 *
 * // Sender:
 * const { sessionId, pin, mgmtToken } = await relay.createSession();
 * await relay.uploadFile(file, sessionId, mgmtToken, pin,
 *   (progress) => console.log(`${progress.percent}%`));
 *
 * // Receiver:
 * const { files } = await relay.joinSession(sessionId, pin);
 * await relay.downloadFile(sessionId, fileId, fileName, pin,
 *   (progress) => console.log(`${progress.percent}%`));
 *
 * relay.connectWS(sessionId, pin, (event) => {
 *   if (event.event === "file_complete") refreshFileList();
 * });
 */

const DROPLY_RELAY_VERSION = "1.0.0";
const CHUNK_SIZE     = 2 * 1024 * 1024;   // 2 MB
const HKDF_INFO      = new TextEncoder().encode("droply-relay-v1");
const IV_BYTES       = 12;                 // AES-GCM nonce size

// ── Crypto helpers ────────────────────────────────────────────────────────────

/**
 * Derive a 256-bit AES-GCM key from a PIN and session ID.
 * Matches the Python derive_key() in relay.py exactly.
 */
async function deriveKey(pin, sessionId) {
  const enc = new TextEncoder();
  // Import PIN bytes as raw HKDF material
  const baseKey = await crypto.subtle.importKey(
    "raw", enc.encode(pin),
    { name: "HKDF" }, false, ["deriveKey"]
  );
  // HKDF with session_id as salt
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(sessionId),
      info: HKDF_INFO,
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,               // not exportable — stays in browser key store
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt one chunk.
 * Returns ArrayBuffer: IV(12) | ciphertext+tag
 */
async function encryptChunk(key, plaintextBuffer) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintextBuffer
  );
  // Concatenate IV + ciphertext
  const out = new Uint8Array(IV_BYTES + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), IV_BYTES);
  return out.buffer;
}

/**
 * Decrypt one chunk.
 * Input: ArrayBuffer IV(12) | ciphertext+tag
 * Returns: ArrayBuffer plaintext
 */
async function decryptChunk(key, wireBuffer) {
  const iv         = wireBuffer.slice(0, IV_BYTES);
  const ciphertext = wireBuffer.slice(IV_BYTES);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    key,
    ciphertext
  );
}

/**
 * SHA-256 a full ArrayBuffer (for integrity verification).
 * Returns hex string.
 */
async function sha256(buffer) {
  const hashBuf = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Main relay client class ───────────────────────────────────────────────────

class DroplyRelay {
  /**
   * @param {string} relayUrl  Base URL of the relay server.
   *                           e.g. "https://droply-relay.fly.dev"
   *                           Defaults to same origin (useful for self-hosting).
   */
  constructor(relayUrl = "") {
    this.relayUrl = relayUrl.replace(/\/$/, "");
    this._ws = null;
  }

  // ── Session ──────────────────────────────────────────────────────────────

  /**
   * Create a new relay session.
   * Called by the sender before uploading any files.
   *
   * @returns {{ sessionId, pin, mgmtToken, expiresAt }}
   */
  async createSession() {
    const r = await fetch(`${this.relayUrl}/relay/session`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.error || `Create session failed: ${r.status}`);
    }
    const d = await r.json();
    return {
      sessionId:  d.session_id,
      pin:        d.pin,
      mgmtToken:  d.mgmt_token,
      expiresAt:  d.expires_at,
    };
  }

  /**
   * Join a session as a receiver.
   * Verifies the PIN server-side.
   *
   * @param {string} sessionId
   * @param {string} pin
   * @returns {{ files, expiresAt }}
   */
  async joinSession(sessionId, pin) {
    const r = await fetch(`${this.relayUrl}/relay/join`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId, pin }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.error || `Join failed: ${r.status}`);
    }
    return r.json();
  }

  /**
   * List files in a session (receiver).
   */
  async listFiles(sessionId, pin) {
    const r = await fetch(`${this.relayUrl}/relay/session/${sessionId}/files`, {
      headers: { "X-PIN": pin },
    });
    if (!r.ok) throw new Error(`List files failed: ${r.status}`);
    return r.json();
  }

  /**
   * Delete a session (sender).
   */
  async deleteSession(sessionId, mgmtToken) {
    await fetch(`${this.relayUrl}/relay/session/${sessionId}`, {
      method: "DELETE",
      headers: { "X-Mgmt-Token": mgmtToken },
    });
  }

  // ── Upload ────────────────────────────────────────────────────────────────

  /**
   * Upload a File to the relay in encrypted chunks.
   *
   * @param {File}     file         Browser File object
   * @param {string}   sessionId
   * @param {string}   mgmtToken    Sender's management token
   * @param {string}   pin          Used for key derivation
   * @param {Function} onProgress   Called with { chunk, total, percent, bytesUploaded, speed }
   * @returns {{ fileId, sha256 }}
   */
  async uploadFile(file, sessionId, mgmtToken, pin, onProgress = null) {
    const key      = await deriveKey(pin, sessionId);
    const fileId   = crypto.randomUUID();
    const fileData = await file.arrayBuffer();
    const fileSHA  = await sha256(fileData);

    const chunks = Math.ceil(fileData.byteLength / CHUNK_SIZE);
    let bytesUploaded = 0;
    const startTime   = Date.now();

    for (let i = 0; i < chunks; i++) {
      const start     = i * CHUNK_SIZE;
      const end       = Math.min(start + CHUNK_SIZE, fileData.byteLength);
      const plaintext = fileData.slice(start, end);
      const wire      = await encryptChunk(key, plaintext);

      const r = await fetch(`${this.relayUrl}/relay/upload`, {
        method: "POST",
        headers: {
          "Content-Type":   "application/octet-stream",
          "X-Session-ID":   sessionId,
          "X-File-ID":      fileId,
          "X-File-Name":    file.name,
          "X-File-Size":    String(file.size),
          "X-File-SHA256":  fileSHA,
          "X-Chunk-Index":  String(i),
          "X-Total-Chunks": String(chunks),
          "X-Mgmt-Token":   mgmtToken,
        },
        body: wire,
      });

      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.error || `Chunk ${i} upload failed: ${r.status}`);
      }

      bytesUploaded += (end - start);
      if (onProgress) {
        const elapsed = (Date.now() - startTime) / 1000;
        const speed   = elapsed > 0 ? bytesUploaded / elapsed : 0;
        onProgress({
          chunk:         i + 1,
          total:         chunks,
          percent:       Math.round(((i + 1) / chunks) * 100),
          bytesUploaded,
          totalBytes:    file.size,
          speed,         // bytes/sec
          eta:           speed > 0 ? Math.round((file.size - bytesUploaded) / speed) : null,
        });
      }
    }

    return { fileId, sha256: fileSHA, name: file.name, size: file.size };
  }

  // ── Download ──────────────────────────────────────────────────────────────

  /**
   * Download and decrypt a file from the relay.
   * Triggers the browser's "Save file" dialog on completion.
   *
   * @param {string}   sessionId
   * @param {string}   fileId
   * @param {string}   fileName
   * @param {string}   pin
   * @param {number}   totalChunks
   * @param {string}   expectedSHA256   Full-file SHA-256 for integrity check
   * @param {Function} onProgress       Called with { chunk, total, percent, speed }
   * @returns {{ verified: bool }}  verified = true if SHA-256 matched
   */
  async downloadFile(sessionId, fileId, fileName, pin,
                     totalChunks, expectedSHA256,
                     onProgress = null) {
    const key        = await deriveKey(pin, sessionId);
    const parts      = [];
    const startTime  = Date.now();
    let   bytesDown  = 0;

    for (let i = 0; i < totalChunks; i++) {
      const r = await fetch(
        `${this.relayUrl}/relay/download/${sessionId}/${fileId}/chunk/${i}`,
        { headers: { "X-PIN": pin } }
      );

      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        throw new Error(err.error || `Chunk ${i} download failed: ${r.status}`);
      }

      const wire      = await r.arrayBuffer();
      const plaintext = await decryptChunk(key, wire);
      parts.push(plaintext);
      bytesDown += plaintext.byteLength;

      if (onProgress) {
        const elapsed = (Date.now() - startTime) / 1000;
        const speed   = elapsed > 0 ? bytesDown / elapsed : 0;
        onProgress({
          chunk:   i + 1,
          total:   totalChunks,
          percent: Math.round(((i + 1) / totalChunks) * 100),
          speed,
          eta:     null,   // size unknown until last chunk
        });
      }
    }

    // Reassemble
    const totalBytes = parts.reduce((s, p) => s + p.byteLength, 0);
    const assembled  = new Uint8Array(totalBytes);
    let   offset     = 0;
    for (const p of parts) {
      assembled.set(new Uint8Array(p), offset);
      offset += p.byteLength;
    }

    // Integrity check
    const actualSHA  = await sha256(assembled.buffer);
    const verified   = actualSHA === expectedSHA256;
    if (!verified) {
      console.error(`Integrity FAIL: expected ${expectedSHA256}, got ${actualSHA}`);
    }

    // Trigger browser save dialog
    const blob = new Blob([assembled]);
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);

    return { verified, actualSHA };
  }

  // ── WebSocket ──────────────────────────────────────────────────────────────

  /**
   * Connect to relay WebSocket for live file-ready notifications.
   *
   * @param {string}   sessionId
   * @param {string}   pin
   * @param {Function} onEvent    Called with each push event object
   * @param {Function} onStatus   Called with "connected" | "reconnecting" | "closed"
   */
  connectWS(sessionId, pin, onEvent, onStatus = null) {
    const proto = this.relayUrl.startsWith("https") ? "wss" : "ws";
    const host  = this.relayUrl.replace(/^https?:\/\//, "");
    const url   = `${proto}://${host}/relay/ws/${sessionId}`;

    let retryDelay = 1000;
    let retryTimer = null;

    const connect = () => {
      if (onStatus) onStatus("reconnecting");

      let ws;
      try {
        ws = new WebSocket(url);
      } catch (e) {
        if (onStatus) onStatus("closed");
        return;
      }
      this._ws = ws;

      ws.onopen = () => {
        // First message: auth with PIN
        ws.send(JSON.stringify({ pin }));
        retryDelay = 1000;
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.event === "connected") {
            if (onStatus) onStatus("connected");
          } else if (msg.event === "error") {
            console.error("Relay WS error:", msg.message);
            ws.close();
          } else {
            onEvent(msg);
          }
        } catch (_) {}
      };

      ws.onerror = () => {};

      ws.onclose = () => {
        if (onStatus) onStatus("reconnecting");
        retryTimer = setTimeout(() => {
          retryDelay = Math.min(retryDelay * 2, 30000);
          connect();
        }, retryDelay);
      };
    };

    connect();

    return {
      close: () => {
        clearTimeout(retryTimer);
        if (this._ws) this._ws.close();
        if (onStatus) onStatus("closed");
      }
    };
  }

  // ── Utilities ─────────────────────────────────────────────────────────────

  static formatBytes(bytes) {
    if (!bytes) return "0 B";
    const k = 1024, s = ["B","KB","MB","GB","TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / k**i).toFixed(1) + " " + s[i];
  }

  static formatSpeed(bps) {
    return DroplyRelay.formatBytes(bps) + "/s";
  }
}

// Export for use as ES module or CommonJS
if (typeof module !== "undefined") {
  module.exports = { DroplyRelay, deriveKey, encryptChunk, decryptChunk, sha256 };
}