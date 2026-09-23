/**
 * Ende-zu-Ende-Verschluesselung, ausschliesslich mit WebCrypto. Keine Bibliothek.
 *
 * Aufbau:
 *   - Identitaet:  ein ECDH-P-256-Schluesselpaar je Konto. Der oeffentliche Teil
 *                  steht im Profil, der private liegt nur lokal und ist mit dem
 *                  Sperrcode verschluesselt.
 *   - Unterhaltung: je Epoche ein zufaelliger AES-256-GCM-Schluessel.
 *   - Verteilung:  statisches ECDH (mein privater x dein oeffentlicher Schluessel)
 *                  -> HKDF-SHA-256 -> AES-GCM. Statisch, nicht ephemer: der
 *                  Empfaenger kann damit pruefen, von wem die Verpackung stammt.
 *                  Ein untergeschobener Schluessel faellt auf.
 *   - Bindung:     jeder Ciphertext traegt Unterhaltung und Epoche als
 *                  zusaetzliches authentifiziertes Datum. Ciphertext laesst sich
 *                  deshalb nicht in eine andere Unterhaltung umhaengen.
 *   - Sperrcode:   PBKDF2-SHA-256 mit 600 000 Runden.
 */

const te = new TextEncoder()
const td = new TextDecoder()

export const PBKDF2_ROUNDS = 600_000

/* ------------------------------------------------------------------ Base64 */

export function toB64(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

export function fromB64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

export const randomBytes = (length: number) => crypto.getRandomValues(new Uint8Array(length))

/* ----------------------------------------------------------------- AES-GCM */

export type Sealed = { iv: string; ct: string }

export async function seal(key: CryptoKey, plain: Uint8Array, aad?: string): Promise<Sealed> {
  const iv = randomBytes(12)
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource }
  if (aad) params.additionalData = te.encode(aad) as BufferSource
  const ct = await crypto.subtle.encrypt(params, key, plain as BufferSource)
  return { iv: toB64(iv), ct: toB64(ct) }
}

export async function unseal(key: CryptoKey, sealed: Sealed, aad?: string): Promise<Uint8Array> {
  const params: AesGcmParams = { name: 'AES-GCM', iv: fromB64(sealed.iv) as BufferSource }
  if (aad) params.additionalData = te.encode(aad) as BufferSource
  const plain = await crypto.subtle.decrypt(params, key, fromB64(sealed.ct) as BufferSource)
  return new Uint8Array(plain)
}

export const sealText = (key: CryptoKey, text: string, aad?: string) =>
  seal(key, te.encode(text), aad)

export const unsealText = async (key: CryptoKey, sealed: Sealed, aad?: string) =>
  td.decode(await unseal(key, sealed, aad))

/* -------------------------------------------------- Sperrcode -> Schluessel */

/** Aus einem Sperrcode oder einem Code-Fragment einen AES-Schluessel ableiten. */
export async function keyFromSecret(secret: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    'raw',
    te.encode(secret.normalize('NFKC')) as BufferSource,
    'PBKDF2',
    false,
    ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: PBKDF2_ROUNDS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

/* --------------------------------------------------------------- Identitaet */

export function generateIdentity(): Promise<CryptoKeyPair> {
  // extractable, weil der private Schluessel fuer ein zweites Geraet exportiert
  // werden koennen muss. Er liegt ausserhalb des Arbeitsspeichers nur
  // verschluesselt vor.
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveKey',
    'deriveBits',
  ]) as Promise<CryptoKeyPair>
}

export const exportJwk = (key: CryptoKey) => crypto.subtle.exportKey('jwk', key)

export const importPublicJwk = (jwk: JsonWebKey) =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [])

export const importPrivateJwk = (jwk: JsonWebKey) =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveKey',
    'deriveBits',
  ])

export const sameKey = (a?: JsonWebKey | null, b?: JsonWebKey | null) =>
  !!a && !!b && a.crv === b.crv && a.kty === b.kty && a.x === b.x && a.y === b.y

/**
 * Kurzer Fingerabdruck eines oeffentlichen Schluessels. Zwei Leute koennen ihn
 * ueber einen anderen Kanal vergleichen. Stimmt er ueberein, hat unterwegs
 * niemand Schluessel ausgetauscht.
 */
export async function fingerprint(jwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })
  const digest = await crypto.subtle.digest('SHA-256', te.encode(canonical) as BufferSource)
  return [...new Uint8Array(digest)]
    .slice(0, 10)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
    .match(/.{1,4}/g)!
    .join(' ')
}

/* ------------------------------------------------ Schluessel je Unterhaltung */

export function generateConversationKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]) as Promise<CryptoKey>
}

async function agree(mine: CryptoKey, theirs: CryptoKey, context: string): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirs }, mine, 256)
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: te.encode(context) as BufferSource,
      info: te.encode('invite-chat/conversation-key/v1') as BufferSource,
    },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export type KeyRow = {
  wrapped_key: string
  sender_public_key: JsonWebKey
  iv: string
}

/** Der Kontext bindet eine Verpackung an Unterhaltung und Epoche. */
export const keyContext = (conversationId: string, epoch: number) =>
  `invite-chat/key/${conversationId}/${epoch}`

/** Der AAD bindet eine Nachricht an Unterhaltung und Epoche. */
export const messageContext = (conversationId: string, epoch: number) =>
  `invite-chat/msg/${conversationId}/${epoch}`

/** Gruppenschluessel fuer genau eine Person verpacken. */
export async function wrapFor(
  conversationKey: CryptoKey,
  myPrivate: CryptoKey,
  myPublicJwk: JsonWebKey,
  recipientPublicJwk: JsonWebKey,
  context: string
): Promise<KeyRow> {
  const recipient = await importPublicJwk(recipientPublicJwk)
  const wrapper = await agree(myPrivate, recipient, context)
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', conversationKey))
  const sealed = await seal(wrapper, raw, context)
  return { wrapped_key: sealed.ct, sender_public_key: myPublicJwk, iv: sealed.iv }
}

/**
 * Gruppenschluessel auspacken. Gelingt nur, wenn die Verpackung wirklich von
 * dem oeffentlichen Schluessel in der Zeile stammt. Ob dieser Schluessel zu der
 * Person gehoert, die sich als Absender ausgibt, prueft der Aufrufer.
 */
export async function unwrapFrom(
  myPrivate: CryptoKey,
  row: KeyRow,
  context: string
): Promise<CryptoKey> {
  const sender = await importPublicJwk(row.sender_public_key)
  const wrapper = await agree(myPrivate, sender, context)
  const raw = await unseal(wrapper, { iv: row.iv, ct: row.wrapped_key }, context)
  return crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ])
}

/* -------------------------------------------------------------------- JSON */

export const sealJson = (key: CryptoKey, value: unknown, aad?: string) =>
  sealText(key, JSON.stringify(value), aad)

export async function unsealJson<T>(key: CryptoKey, sealed: Sealed, aad?: string): Promise<T> {
  return JSON.parse(await unsealText(key, sealed, aad)) as T
}
