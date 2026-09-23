import crypto from 'node:crypto'
import { NextResponse, type NextRequest } from 'next/server'
import { createAdminClient } from '@/lib/supabase/admin'
import { hashCode } from '@/lib/hash'
import { normalizeCode, DEVICE_AUTH_LEN, INVITE_LEN } from '@/lib/codes'
import {
  CODE_ERROR,
  clientIpHash,
  issueSession,
  noteAttempt,
  requirePepper,
  throttled,
  WINDOW_MINUTES,
} from '@/lib/auth-helpers'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

const USERNAME_RE = /^[A-Za-z0-9_.-]{3,24}$/

export async function POST(request: NextRequest) {
  let pepper: string
  try {
    pepper = requirePepper()
  } catch {
    return NextResponse.json({ error: 'Server ist nicht fertig eingerichtet.' }, { status: 500 })
  }

  let payload: { authPart?: unknown; username?: unknown }
  try {
    payload = await request.json()
  } catch {
    return NextResponse.json({ error: 'Ungueltige Anfrage.' }, { status: 400 })
  }

  const auth = normalizeCode(String(payload.authPart ?? ''))
  const username = String(payload.username ?? '').trim()

  if (auth.length !== INVITE_LEN && auth.length !== DEVICE_AUTH_LEN) {
    return NextResponse.json({ error: CODE_ERROR }, { status: 400 })
  }

  const admin = createAdminClient()
  const ipHash = clientIpHash(request, pepper)

  if (await throttled(admin, ipHash)) {
    return NextResponse.json(
      { error: `Zu viele Versuche. Bitte in ${WINDOW_MINUTES} Minuten noch einmal.` },
      { status: 429 }
    )
  }

  // --- Code atomar entwerten ---------------------------------------------------
  // Der Filter used_at IS NULL steckt im UPDATE selbst. Zwei gleichzeitige
  // Anfragen mit demselben Code koennen also nicht beide gewinnen.
  const nowIso = new Date().toISOString()
  const { data: claimed } = await admin
    .from('invite_codes')
    .update({ used_at: nowIso })
    .eq('code_hash', hashCode(auth, pepper))
    .is('used_at', null)
    .or(`expires_at.is.null,expires_at.gt.${nowIso}`)
    .select('id, kind, for_user, payload, payload_iv, payload_salt')
    .maybeSingle()

  if (!claimed) {
    await noteAttempt(admin, ipHash, false)
    return NextResponse.json({ error: CODE_ERROR }, { status: 400 })
  }

  const release = () =>
    admin.from('invite_codes').update({ used_at: null, used_by: null }).eq('id', claimed.id)

  /* ======================================================= zweites Geraet === */

  if (claimed.kind === 'device') {
    const { data: owner } = await admin.auth.admin.getUserById(claimed.for_user as string)
    const { data: profile } = await admin
      .from('profiles')
      .select('username')
      .eq('id', claimed.for_user as string)
      .maybeSingle()

    if (!owner?.user?.email || !profile) {
      await release()
      await noteAttempt(admin, ipHash, false)
      return NextResponse.json({ error: CODE_ERROR }, { status: 400 })
    }

    const session = await issueSession(admin, owner.user.email)
    if ('error' in session) {
      console.error('issueSession (device):', session.error)
      await release()
      await noteAttempt(admin, ipHash, false)
      return NextResponse.json(
        { error: `Anmeldung fehlgeschlagen: ${session.error}` },
        { status: 500 }
      )
    }

    // Der verschluesselte Schluessel wird genau einmal ausgeliefert und
    // danach sofort aus der Datenbank entfernt.
    await admin
      .from('invite_codes')
      .update({ used_by: claimed.for_user, payload: null, payload_iv: null, payload_salt: null })
      .eq('id', claimed.id)

    await noteAttempt(admin, ipHash, true)
    return NextResponse.json({
      kind: 'device',
      tokenHash: session.tokenHash,
      userId: claimed.for_user,
      username: profile.username,
      payload: claimed.payload,
      payloadIv: claimed.payload_iv,
      payloadSalt: claimed.payload_salt,
    })
  }

  /* ============================================================ neues Konto === */

  if (!USERNAME_RE.test(username)) {
    await release()
    await noteAttempt(admin, ipHash, false)
    return NextResponse.json(
      { error: 'Der Benutzername braucht 3 bis 24 Zeichen: Buchstaben, Ziffern, . _ -' },
      { status: 400 }
    )
  }

  const domain = process.env.INVITE_EMAIL_DOMAIN || 'invite.local'
  const email = `${crypto.randomUUID()}@${domain}`

  const { data: created, error: userError } = await admin.auth.admin.createUser({
    email,
    email_confirm: true,
    password: crypto.randomBytes(48).toString('base64url'),
  })

  if (userError || !created?.user) {
    await release()
    await noteAttempt(admin, ipHash, false)
    return NextResponse.json({ error: 'Konto konnte nicht angelegt werden.' }, { status: 500 })
  }

  const userId = created.user.id
  const { error: profileError } = await admin.from('profiles').insert({ id: userId, username })

  if (profileError) {
    await admin.auth.admin.deleteUser(userId)
    await release()
    await noteAttempt(admin, ipHash, false)
    const conflict = profileError.code === '23505'
    return NextResponse.json(
      {
        error: conflict
          ? 'Dieser Benutzername ist schon vergeben.'
          : 'Profil konnte nicht angelegt werden.',
      },
      { status: conflict ? 409 : 500 }
    )
  }

  const session = await issueSession(admin, email)
  if ('error' in session) {
    console.error('issueSession (invite):', session.error)
    await noteAttempt(admin, ipHash, false)
    return NextResponse.json(
      { error: `Anmeldung fehlgeschlagen: ${session.error}` },
      { status: 500 }
    )
  }

  await admin.from('invite_codes').update({ used_by: userId }).eq('id', claimed.id)
  await noteAttempt(admin, ipHash, true)

  return NextResponse.json({ kind: 'invite', tokenHash: session.tokenHash, userId, username })
}
