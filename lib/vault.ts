'use client'

/**
 * Der Tresor liegt in IndexedDB. Er enthaelt den privaten Identitaetsschluessel
 * und die Sitzung, beides mit dem Sperrcode verschluesselt. Ohne Sperrcode ist
 * der Inhalt fuer niemanden zu gebrauchen, auch nicht fuer jemanden mit
 * Vollzugriff auf das Browserprofil.
 */

import { fromB64, keyFromSecret, randomBytes, seal, toB64, unseal, type Sealed } from './crypto'

const DB_NAME = 'invite-chat'
const STORE = 'vault'
const RECORD = 'self'

export const MAX_UNLOCK_FAILURES = 5
export const PIN_MIN = 8

export type Vault = {
  userId: string
  username: string
  publicJwk: JsonWebKey
  salt: string
  identity: Sealed
  session: Sealed | null
  failures: number
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1)
    request.onupgradeneeded = () => request.result.createObjectStore(STORE)
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

async function transact<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest): Promise<T> {
  const db = await open()
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = run(db.transaction(STORE, mode).objectStore(STORE))
      request.onsuccess = () => resolve(request.result as T)
      request.onerror = () => reject(request.error)
    })
  } finally {
    db.close()
  }
}

export const readVault = () => transact<Vault | undefined>('readonly', (s) => s.get(RECORD))
export const writeVault = (vault: Vault) => transact<unknown>('readwrite', (s) => s.put(vault, RECORD))
export const wipeVault = () => transact<unknown>('readwrite', (s) => s.delete(RECORD))

/* ------------------------------------------------------------- Einrichten */

export async function createVault(args: {
  userId: string
  username: string
  publicJwk: JsonWebKey
  privateJwk: JsonWebKey
  pin: string
}): Promise<CryptoKey> {
  const salt = randomBytes(16)
  const pinKey = await keyFromSecret(args.pin, salt)
  const identity = await seal(pinKey, new TextEncoder().encode(JSON.stringify(args.privateJwk)))

  await writeVault({
    userId: args.userId,
    username: args.username,
    publicJwk: args.publicJwk,
    salt: toB64(salt),
    identity,
    session: null,
    failures: 0,
  })

  return pinKey
}

/* --------------------------------------------------------------- Oeffnen */

export type Opened = { vault: Vault; pinKey: CryptoKey; privateJwk: JsonWebKey }

/** Wirft, wenn der Sperrcode falsch ist. Nach zu vielen Fehlern loescht sich der Tresor. */
export async function openVault(pin: string): Promise<Opened> {
  const vault = await readVault()
  if (!vault) throw new Error('kein Tresor')

  const pinKey = await keyFromSecret(pin, fromB64(vault.salt))

  try {
    const raw = await unseal(pinKey, vault.identity)
    const privateJwk = JSON.parse(new TextDecoder().decode(raw)) as JsonWebKey
    if (vault.failures !== 0) await writeVault({ ...vault, failures: 0 })
    return { vault: { ...vault, failures: 0 }, pinKey, privateJwk }
  } catch {
    const failures = vault.failures + 1
    if (failures >= MAX_UNLOCK_FAILURES) {
      await wipeVault()
      throw new Error('zu viele Fehlversuche')
    }
    await writeVault({ ...vault, failures })
    throw new Error(`falscher Sperrcode (${MAX_UNLOCK_FAILURES - failures} Versuche uebrig)`)
  }
}

/* --------------------------------------------------------------- Sitzung */

export type StoredSession = { access_token: string; refresh_token: string }

/** Sitzung verschluesselt ablegen, damit die Sperre sie wieder herstellen kann. */
export async function stashSession(pinKey: CryptoKey, session: StoredSession) {
  const vault = await readVault()
  if (!vault) return
  const sealed = await seal(pinKey, new TextEncoder().encode(JSON.stringify(session)))
  await writeVault({ ...vault, session: sealed })
}

export async function takeSession(pinKey: CryptoKey, vault: Vault): Promise<StoredSession | null> {
  if (!vault.session) return null
  try {
    return JSON.parse(new TextDecoder().decode(await unseal(pinKey, vault.session))) as StoredSession
  } catch {
    return null
  }
}

export function pinProblem(pin: string): string | null {
  const value = pin.normalize('NFKC')
  if (value.length < PIN_MIN) return `Der Sperrcode braucht mindestens ${PIN_MIN} Zeichen.`
  if (value.length > 128) return 'Der Sperrcode ist zu lang.'
  if (/^(\d)\1*$/.test(value)) return 'Bitte keine Folge aus einer einzigen Ziffer.'
  return null
}
