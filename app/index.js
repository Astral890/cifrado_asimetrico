// index.js (reemplaza tu server actual por completo)
import express from "express";
import crypto from "crypto";
import elliptic from "elliptic";
import path from "path";
import { fileURLToPath } from "url";

const EC = elliptic.ec;
const ec = new EC("secp256k1");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* ---------------- helpers AES ---------------- */
function aesEncryptRaw(keyBuffer, plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", keyBuffer, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  // devolver base64 con iv prefijado
  return Buffer.concat([iv, enc]).toString("base64");
}
function aesDecryptRaw(keyBuffer, base64Data) {
  const data = Buffer.from(base64Data, "base64");
  const iv = data.slice(0, 16);
  const ct = data.slice(16);
  const decipher = crypto.createDecipheriv("aes-256-cbc", keyBuffer, iv);
  const dec = Buffer.concat([decipher.update(ct), decipher.final()]);
  return dec.toString("utf8");
}
function deriveKeyFromSecretPoint(point) {
  // punto: elliptic point -> derive key from X coordinate
  // Normalizamos tamaño a 32 bytes (big-endian) para evitar variaciones en longitudes.
  const xbuf = point.getX().toArrayLike(Buffer, "be", 32);
  return crypto.createHash("sha256").update(xbuf).digest(); // 32 bytes
}

/* ---------------- RSA ---------------- */
app.post("/generate/rsa", (req, res) => {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    res.json({
      ok: true,
      publicKey: publicKey.export({ type: "spki", format: "pem" }),
      privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/rsa/encrypt", (req, res) => {
  const { publicKey, message } = req.body;
  try {
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(message, "utf8"));
    res.json({ ok: true, cipher: encrypted.toString("base64") });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/rsa/decrypt", (req, res) => {
  const { privateKey, cipher } = req.body;
  try {
    const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(cipher, "base64"));
    res.json({ ok: true, message: decrypted.toString("utf8") });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

/* ---------------- Diffie-Hellman ----------------
   Endpoints:
   - /generate/dh -> devuelve p,g y pares A & B (priv/pub hex)
   - /dh/encrypt -> body: { p,g, privateKeyHex, myPublicHex, peerPublicHex, message } -> devuelve cipher(base64)
   - /dh/decrypt -> same fields -> devuelve message
*/
app.post("/generate/dh", (req, res) => {
  try {
    const dhA = crypto.createDiffieHellman(2048);
    dhA.generateKeys();
    const p = dhA.getPrime("hex");
    const g = dhA.getGenerator("hex");

    // crear B a partir de p,g
    const dhB = crypto.createDiffieHellman(Buffer.from(p, "hex"), Buffer.from(g, "hex"));
    dhB.generateKeys();

    res.json({
      ok: true,
      p,
      g,
      A: { private: dhA.getPrivateKey("hex"), public: dhA.getPublicKey("hex") },
      B: { private: dhB.getPrivateKey("hex"), public: dhB.getPublicKey("hex") },
    });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/dh/encrypt", (req, res) => {
  try {
    const { p, g, privateKeyHex, myPublicHex, peerPublicHex, message } = req.body;

    if (!p || !g || !privateKeyHex || !myPublicHex || !peerPublicHex) {
      return res.json({ ok: false, error: "Faltan parámetros p/g/private/myPublic/peerPublic" });
    }

    const dh = crypto.createDiffieHellman(Buffer.from(p, "hex"), Buffer.from(g, "hex"));
    // reconstruct context using both private and public (no generateKeys)
    dh.setPrivateKey(Buffer.from(privateKeyHex, "hex"));
    dh.setPublicKey(Buffer.from(myPublicHex, "hex"));

    // compute secret against peer public
    const secret = dh.computeSecret(Buffer.from(peerPublicHex, "hex"));
    const key = crypto.createHash("sha256").update(secret).digest(); // 32 bytes
    const cipher = aesEncryptRaw(key, message);
    res.json({ ok: true, cipher });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/dh/decrypt", (req, res) => {
  try {
    const { p, g, privateKeyHex, myPublicHex, peerPublicHex, cipher } = req.body;

    if (!p || !g || !privateKeyHex || !myPublicHex || !peerPublicHex || !cipher) {
      return res.json({ ok: false, error: "Faltan parámetros p/g/private/myPublic/peerPublic/cipher" });
    }

    const dh = crypto.createDiffieHellman(Buffer.from(p, "hex"), Buffer.from(g, "hex"));
    dh.setPrivateKey(Buffer.from(privateKeyHex, "hex"));
    dh.setPublicKey(Buffer.from(myPublicHex, "hex"));

    const secret = dh.computeSecret(Buffer.from(peerPublicHex, "hex"));
    const key = crypto.createHash("sha256").update(secret).digest();
    const message = aesDecryptRaw(key, cipher);
    res.json({ ok: true, message });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

/* ---------------- ECC (ECDH -> AES) ----------------
   - /generate/ecc -> devuelve pub (hex, uncompressed) y priv (hex)
   - /ecc/encrypt -> { recipientPublicHex, message } -> { R, cipher }
   - /ecc/decrypt -> { recipientPrivateHex, R, cipher } -> message
*/
app.post("/generate/ecc", (req, res) => {
  try {
    const key = ec.genKeyPair();
    // getPublic(false,'hex') => descomprimido (uncompressed)
    res.json({
      ok: true,
      publicKey: key.getPublic(false, "hex"),
      privateKey: key.getPrivate("hex"),
    });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/ecc/encrypt", (req, res) => {
  try {
    const { recipientPublicHex, message } = req.body;
    const eph = ec.genKeyPair();
    // ephemeral public point - uncompressed
    const Rhex = eph.getPublic(false, "hex");
    const recipientPoint = ec.keyFromPublic(recipientPublicHex, "hex").getPublic();
    const S = recipientPoint.mul(eph.getPrivate()); // secret point
    const key = deriveKeyFromSecretPoint(S);
    const cipher = aesEncryptRaw(key, message);
    res.json({ ok: true, R: Rhex, cipher });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/ecc/decrypt", (req, res) => {
  try {
    const { recipientPrivateHex, R, cipher } = req.body;
    const Rpoint = ec.keyFromPublic(R, "hex").getPublic();
    const priv = ec.keyFromPrivate(recipientPrivateHex, "hex");
    const S = Rpoint.mul(priv.getPrivate());
    const key = deriveKeyFromSecretPoint(S);
    const message = aesDecryptRaw(key, cipher);
    res.json({ ok: true, message });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

/* ---------------- DSA (firma/verify) ----------------
   - /generate/dsa -> returns PEMs
   - /dsa/sign -> { privateKeyPem, message } -> signature (base64)
   - /dsa/verify -> { publicKeyPem, message, signature } -> valid boolean
*/
app.post("/generate/dsa", (req, res) => {
  try {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("dsa", {
      modulusLength: 1024,
    });
    res.json({
      ok: true,
      publicKey: publicKey.export({ type: "spki", format: "pem" }),
      privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/dsa/sign", (req, res) => {
  try {
    const { privateKeyPem, message } = req.body;
    const signer = crypto.createSign("SHA256");
    signer.update(message);
    const sig = signer.sign(privateKeyPem, "base64");
    res.json({ ok: true, signature: sig });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/dsa/verify", (req, res) => {
  try {
    const { publicKeyPem, message, signature } = req.body;
    const verifier = crypto.createVerify("SHA256");
    verifier.update(message);
    const valid = verifier.verify(publicKeyPem, signature, "base64");
    res.json({ ok: true, valid });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

/* ---------------- ElGamal (EC-based) ----------------
   - /elgamal/generate -> { publicKeyHex (uncompressed), privateKeyHex }
   - /elgamal/encrypt -> { publicKey, message } -> { R (uncompressed), cipher }
   - /elgamal/decrypt -> { privateKey, R, cipher } -> message
   Implementation: ephemeral k, R = kG, S = k*P, use S.x hashed -> AES-256
*/
function elgamalEncrypt(message, recipientPubHex) {
  const k = ec.genKeyPair();
  const R = k.getPublic(); // point
  const P = ec.keyFromPublic(recipientPubHex, "hex").getPublic();
  const S = P.mul(k.getPrivate()); // shared secret point
  const key = deriveKeyFromSecretPoint(S); // 32 bytes
  const cipher = aesEncryptRaw(key, message);
  // R encoded uncompressed (false) to ensure consistent decoding on client
  return { R: R.encode("hex", false), cipher };
}
function elgamalDecrypt(privateHex, Rhex, cipher) {
  const priv = ec.keyFromPrivate(privateHex, "hex");
  const Rpoint = ec.keyFromPublic(Rhex, "hex").getPublic();
  const S = Rpoint.mul(priv.getPrivate());
  const key = deriveKeyFromSecretPoint(S);
  return aesDecryptRaw(key, cipher);
}

app.post("/elgamal/generate", (req, res) => {
  try {
    const key = ec.genKeyPair();
    res.json({
      ok: true,
      publicKey: key.getPublic(false, "hex"), // uncompressed
      privateKey: key.getPrivate("hex"),
    });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/elgamal/encrypt", (req, res) => {
  try {
    const { publicKey, message } = req.body;
    const out = elgamalEncrypt(message, publicKey);
    res.json({ ok: true, R: out.R, cipher: out.cipher });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.post("/elgamal/decrypt", (req, res) => {
  try {
    const { privateKey, R, cipher } = req.body;
    const message = elgamalDecrypt(privateKey, R, cipher);
    res.json({ ok: true, message });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

/* ---------------- default server ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor escuchando en http://localhost:${PORT}`));
