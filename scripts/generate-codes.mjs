#!/usr/bin/env node
/**
 * Erzeugt Einmal-Codes und legt ihre Hashes in Supabase ab.
 *
 *   npm run codes -- 5                       fuenf Codes, unbegrenzt gueltig
 *   npm run codes -- 3 "Familie" --days 14   drei Codes mit Notiz, 14 Tage gueltig
 *
 * Die Klartext-Codes erscheinen nur hier im Terminal. Sie werden nirgends
 * gespeichert und lassen sich danach nicht wiederherstellen.
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { createClient } from '@supabase/supabase-js'

const ALPHABET = '23456789ABCDEFGHJKMNPQRSTVWXYZ'
const CODE_LEN = 16

// --- .env.local einlesen -----------------------------------------------------
const envPath = path.resolve(process.cwd(), '.env.local')
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/)
    if (match && !process.env[match[1]]) {
      process.env[match[1]] = match[2].replace(/^["']|["']$/g, '')
    }
  }
}

const url = process.env.NEXT_PUBLIC_SUPABASE_URL
const key = process.env.SUPABASE_SECRET_KEY
const pepper = process.env.INVITE_CODE_PEPPER
// Rein lokale Bequemlichkeit fuers Skript, kein Next.js-Variablenname und
// nicht in Vercel noetig: die Adresse, unter der die App online steht.
const appUrl = process.env.APP_URL?.replace(/\/+$/, '') ?? null

if (!url || !key || !pepper) {
  console.error('NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SECRET_KEY und INVITE_CODE_PEPPER muessen gesetzt sein.')
  process.exit(1)
}

// --- Argumente ---------------------------------------------------------------
const args = process.argv.slice(2)
const daysIndex = args.indexOf('--days')
const days = daysIndex >= 0 ? Number(args[daysIndex + 1]) : null
const positional = args.filter((a, i) => a !== '--days' && i !== daysIndex + 1)

const count = Math.min(Math.max(Number(positional[0]) || 5, 1), 200)
const label = positional[1] ?? null
const expiresAt = days ? new Date(Date.now() + days * 86_400_000).toISOString() : null

// --- Codes erzeugen ----------------------------------------------------------
function generateCode() {
  const out = []
  const limit = 256 - (256 % ALPHABET.length)
  while (out.length < CODE_LEN) {
    for (const b of crypto.randomBytes(CODE_LEN)) {
      if (b < limit && out.length < CODE_LEN) out.push(ALPHABET[b % ALPHABET.length])
    }
  }
  return out.join('').match(/.{1,4}/g).join('-')
}

const hashCode = (normalized) =>
  crypto.createHmac('sha256', pepper).update(normalized).digest('hex')

const codes = Array.from({ length: count }, generateCode)

const supabase = createClient(url, key, { auth: { persistSession: false } })

const { error } = await supabase.from('invite_codes').insert(
  codes.map((code) => ({
    kind: 'invite',
    code_hash: hashCode(code.replaceAll('-', '')),
    label,
    expires_at: expiresAt,
  }))
)

if (error) {
  console.error('Einspielen fehlgeschlagen:', error.message)
  process.exit(1)
}

console.log(`\n${count} Code${count === 1 ? '' : 's'} angelegt${label ? ` (${label})` : ''}${
  expiresAt ? `, gueltig bis ${new Date(expiresAt).toLocaleDateString('de-DE')}` : ''
}:\n`)
for (const code of codes) console.log('  ' + code)
console.log('\nJeder Code funktioniert genau einmal. Einzeln weitergeben, nicht als Liste.\n')
