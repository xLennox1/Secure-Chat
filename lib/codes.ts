/**
 * Zwei Sorten Code:
 *
 *   Einladung (16 Zeichen)  neues Konto. Der ganze Code geht an den Server.
 *   Geraet    (20 Zeichen)  weiteres Geraet fuer ein bestehendes Konto.
 *                           Nur die ersten 10 Zeichen gehen an den Server.
 *                           Die letzten 10 bleiben im Browser und
 *                           entschluesseln den mitgereisten Identitaetsschluessel.
 *
 * Weil der Server die zweite Haelfte nie sieht, kann er den transportierten
 * Schluessel nicht lesen, obwohl der verschluesselte Transport ueber ihn laeuft.
 */

export const ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ'
export const INVITE_LEN = 16
export const DEVICE_LEN = 20
export const DEVICE_AUTH_LEN = 10

export type CodeKind = 'invite' | 'device'

export function kindOf(normalized: string): CodeKind | null {
  if (normalized.length === INVITE_LEN) return 'invite'
  if (normalized.length === DEVICE_LEN) return 'device'
  return null
}

/** Was der Server zu sehen bekommt. Bei Geraete-Codes nur die erste Haelfte. */
export const authPart = (normalized: string) =>
  normalized.length === DEVICE_LEN ? normalized.slice(0, DEVICE_AUTH_LEN) : normalized

/** Was den Browser nie verlaesst. Nur bei Geraete-Codes belegt. */
export const secretPart = (normalized: string) =>
  normalized.length === DEVICE_LEN ? normalized.slice(DEVICE_AUTH_LEN) : ''

/** Gross schreiben und alles wegwerfen, was nicht zum Alphabet gehoert. */
export function normalizeCode(raw: string, max = DEVICE_LEN): string {
  const allowed = new Set(ALPHABET)
  return [...raw.toUpperCase()].filter((c) => allowed.has(c)).join('').slice(0, max)
}

export const formatCode = (normalized: string) =>
  normalized.match(/.{1,4}/g)?.join('-') ?? ''

export const isCompleteCode = (normalized: string) => kindOf(normalized) !== null

/** Zufaelliger Code. Laeuft sowohl im Browser als auch in Node. */
export function generateCode(length: number): string {
  const out: string[] = []
  const limit = 256 - (256 % ALPHABET.length)
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length * 2))
    for (const b of bytes) {
      if (b < limit && out.length < length) out.push(ALPHABET[b % ALPHABET.length])
    }
  }
  return out.join('')
}
