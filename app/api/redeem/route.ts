import { NextResponse, type NextRequest } from 'next/server'
import { createAdminClient } from '@/lib/supabase/admin'
import { hashCode } from '@/lib/hash'
import { normalizeCode, INVITE_LEN, DEVICE_AUTH_LEN } from '@/lib/codes'
import { CODE_ERROR, clientIpHash, issueSession, requirePepper } from '@/lib/auth-helpers'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

function randomBytes(length: number) {
  const bytes = new Uint8Array(length)
  crypto.getRandomValues(bytes)
  return bytes
}

function toBase64Url(bytes: Uint8Array) {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export async function POST(request: NextRequest) {
  let pepper: string
  try {
    pepper = requirePepper()
  } catch {
    return NextResponse.json({ error: 'Server ist nicht fertig eingerichtet.' }, { status: 500 })
  }

  const body = await request.json().catch(() => null) as any
  if (!body) return NextResponse.json({ error: 'Ungueltige Anfrage.' }, { status: 400 })

  const auth = normalizeCode(String(body.authPart ?? ''))
  const username = String(body.username ?? '').trim()

  if (auth.length !== INVITE_LEN && auth.length !== DEVICE_AUTH_LEN) {
    return NextResponse.json({ error: CODE_ERROR }, { status: 400 })
  }

  const admin = createAdminClient()
  const codeHash = await hashCode(auth, pepper)

  const now = new Date().toISOString()
  const { data: claimed, error: claimError } = await admin
    .from('invite_codes')
    .update({ used_at: now })
    .eq('code_hash', codeHash)
    .is('used_at', null)
    .or(`expires_at.is.null,expires_at.gt.${now}`)
    .select('id,kind')
    .maybeSingle()

  if (claimError || !claimed) {
    return NextResponse.json({ error: CODE_ERROR }, { status: 400 })
  }

  if (claimed.kind !== 'invite') {
    await admin.from('invite_codes').update({ used_at: null }).eq('id', claimed.id)
    return NextResponse.json({ error: CODE_ERROR }, { status: 400 })
  }

  if (!/^[A-Za-z0-9_.-]{3,24}$/.test(username)) {
    await admin.from('invite_codes').update({ used_at: null }).eq('id', claimed.id)
    return NextResponse.json({ error: 'Der Benutzername ist ungueltig.' }, { status: 400 })
  }

  const email = `${crypto.randomUUID()}@${process.env.INVITE_EMAIL_DOMAIN || 'invite.local'}`
  const { data: created, error: createError } = await admin.auth.admin.createUser({
    email,
    email_confirm: true,
    password: toBase64Url(randomBytes(48)),
  })

  if (createError || !created?.user) {
    await admin.from('invite_codes').update({ used_at: null }).eq('id', claimed.id)
    return NextResponse.json({ error: 'Konto konnte nicht angelegt werden.' }, { status: 500 })
  }

  const { error: profileError } = await admin.from('profiles').insert({
    id: created.user.id,
    username,
  })

  if (profileError) {
    await admin.auth.admin.deleteUser(created.user.id)
    await admin.from('invite_codes').update({ used_at: null }).eq('id', claimed.id)
    return NextResponse.json({ error: 'Benutzername ist bereits vergeben.' }, { status: 409 })
  }

  const tokenHash = await issueSession(admin, email)
  if (!tokenHash) {
    await admin.auth.admin.deleteUser(created.user.id)
    await admin.from('invite_codes').update({ used_at: null }).eq('id', claimed.id)
    return NextResponse.json({ error: 'Anmeldung fehlgeschlagen.' }, { status: 500 })
  }

  await admin.from('invite_codes').update({ claimed_by: created.user.id }).eq('id', claimed.id)

  return NextResponse.json({
    kind: 'invite',
    tokenHash,
    userId: created.user.id,
    username,
  })
}
