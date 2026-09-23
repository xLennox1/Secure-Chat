import { NextResponse, type NextRequest } from 'next/server'
import { createClient } from '@/lib/supabase/server'
import { createAdminClient } from '@/lib/supabase/admin'
import { hashCode } from '@/lib/hash'
import { normalizeCode, DEVICE_AUTH_LEN } from '@/lib/codes'
import { requirePepper } from '@/lib/auth-helpers'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const B64 = /^[A-Za-z0-9+/=]{8,4000}$/
const MINUTES = 10

/**
 * Legt einen Geraete-Code an. Der Browser hat ihn erzeugt und schickt nur die
 * erste Haelfte. Mit der zweiten Haelfte, die hier nie ankommt, hat er den
 * eigenen Identitaetsschluessel verschluesselt; dieses Paket reist als payload
 * mit. Der Server transportiert es, kann es aber nicht oeffnen.
 */
export async function POST(request: NextRequest) {
  let pepper: string
  try {
    pepper = requirePepper()
  } catch {
    return NextResponse.json({ error: 'Server ist nicht fertig eingerichtet.' }, { status: 500 })
  }

  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Nicht angemeldet.' }, { status: 401 })

  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Ungueltige Anfrage.' }, { status: 400 })
  }

  const auth = normalizeCode(String(body.authPart ?? ''), DEVICE_AUTH_LEN)
  const payload = String(body.payload ?? '')
  const payloadIv = String(body.payloadIv ?? '')
  const payloadSalt = String(body.payloadSalt ?? '')

  if (
    auth.length !== DEVICE_AUTH_LEN ||
    !B64.test(payload) ||
    !B64.test(payloadIv) ||
    !B64.test(payloadSalt)
  ) {
    return NextResponse.json({ error: 'Ungueltige Anfrage.' }, { status: 400 })
  }

  const admin = createAdminClient()

  // Nur ein offener Geraete-Code je Konto. Ein neuer ersetzt den alten.
  await admin
    .from('invite_codes')
    .delete()
    .eq('kind', 'device')
    .eq('for_user', user.id)
    .is('used_at', null)

  const { error } = await admin.from('invite_codes').insert({
    kind: 'device',
    for_user: user.id,
    code_hash: hashCode(auth, pepper),
    expires_at: new Date(Date.now() + MINUTES * 60_000).toISOString(),
    payload,
    payload_iv: payloadIv,
    payload_salt: payloadSalt,
  })

  if (error) {
    return NextResponse.json({ error: 'Code konnte nicht angelegt werden.' }, { status: 500 })
  }

  return NextResponse.json({ minutes: MINUTES })
}
