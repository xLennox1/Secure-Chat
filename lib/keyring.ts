'use client'

import type { Vault } from './vault'

type Ring = { vault: Vault; pinKey: CryptoKey; identityPrivate: CryptoKey }
let ring: Ring | null = null

export const setRing = (value: Ring) => { ring = value }
export const getRing = () => ring
export const isUnlocked = () => ring !== null
export function wipeRing() { ring = null }
