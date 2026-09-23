'use client'

/**
 * Entschluesselte Schluessel leben nur hier: in einer Modulvariablen, also im
 * Arbeitsspeicher dieses einen Tabs. Sie ueberstehen einen Seitenwechsel
 * innerhalb der App, aber kein Neuladen und keine Sperre.
 */

import type { Vault } from './vault'

type Ring = {
  vault: Vault
  pinKey: CryptoKey
  identityPrivate: CryptoKey
}

let ring: Ring | null = null

export const setRing = (value: Ring) => {
  ring = value
}

export const getRing = () => ring

export const isUnlocked = () => ring !== null

export function wipeRing() {
  ring = null
}
