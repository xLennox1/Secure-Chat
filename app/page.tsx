'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { createClient } from '@/lib/supabase/client'
import { setRing } from '@/lib/keyring'
import {
  createVault,
  openVault,
  pinProblem,
  readVault,
  stashSession,
  takeSession,
  wipeVault,
  PIN_MIN,
} from '@/lib/vault'
import {
  exportJwk,
  fingerprint,
  fromB64,
  generateIdentity,
  importPrivateJwk,
  keyFromSecret,
  unsealJson,
} from '@/lib/crypto'
import {
  DEVICE_LEN,
  authPart,
  formatCode,
  isCompleteCode,
  kindOf,
  normalizeCode,
  secretPart,
} from '@/lib/codes'

type Pending = {
  kind: 'invite' | 'device'
  tokenHash: string
  userId: string
  username: string
  secret: string
  payload?: string
  payloadIv?: string
  payloadSalt?: string
}

type Stage = 'checking' | 'unlock' | 'code' | 'pin'

export default function Gate() {
  const router = useRouter()
  const [stage, setStage] = useState<Stage>('checking')
  const [code, setCode] = useState('')
  const [username, setUsername] = useState('')
  const [pin, setPin] = useState('')
  const [pin2, setPin2] = useState('')
  const [pending, setPending] = useState<Pending | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    void (async () => {
      const vault = await readVault()
      if (vault) return setStage('unlock')

      // Kommt jemand über einen Einladungslink (?code=...), den Code nur
      // vorausfuellen, nie automatisch absenden — sonst koennte etwa eine
      // Link-Vorschau in einer Messenger-App den Einmal-Code verbrauchen,
      // bevor die eigentliche Person ihn sieht.
      const fromLink = normalizeCode(
        new URLSearchParams(window.location.search).get('code') ?? '',
        DEVICE_LEN
      )
      if (fromLink) {
        setCode(fromLink)
        window.history.replaceState({}, '', window.location.pathname)
      }

      // Sitzung ohne Tresor: ohne Schluessel nuetzt sie nichts, also weg damit.
      const supabase = createClient()
      const { data } = await supabase.auth.getSession()
      if (data.session) await supabase.auth.signOut()
      setStage('code')
    })()
  }, [])

  const kind = kindOf(code)

  /* ------------------------------------------------------------- entsperren */

  async function unlock(event: React.FormEvent) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError(null)

    try {
      const { vault, pinKey, privateJwk } = await openVault(pin)
      const supabase = createClient()

      const stored = await takeSession(pinKey, vault)
      if (stored) {
        const { error: sessionError } = await supabase.auth.setSession(stored)
        if (sessionError) throw new Error('Die Sitzung ist abgelaufen. Du brauchst einen neuen Code.')
      } else {
        const { data } = await supabase.auth.getSession()
        if (!data.session) throw new Error('Die Sitzung ist abgelaufen. Du brauchst einen neuen Code.')
      }

      setRing({ vault, pinKey, identityPrivate: await importPrivateJwk(privateJwk) })
      setPin('')
      router.replace('/chat')
    } catch (problem) {
      setError(problem instanceof Error ? problem.message : 'Das hat nicht geklappt.')
      setPin('')
      if (!(await readVault())) setStage('code')
      setBusy(false)
    }
  }

  /* ----------------------------------------------------------- Code einlösen */

  async function redeem(event: React.FormEvent) {
    event.preventDefault()
    if (busy || !isCompleteCode(code)) return
    setBusy(true)
    setError(null)

    try {
      const response = await fetch('/api/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authPart: authPart(code), username: username.trim() }),
      })
      const result = await response.json()

      if (!response.ok) {
        setError(result.error ?? 'Das hat nicht geklappt.')
        setBusy(false)
        return
      }

      setPending({ ...result, secret: secretPart(code) })
      setCode('')
      setStage('pin')
    } catch {
      setError('Keine Verbindung zum Server.')
    }
    setBusy(false)
  }

  /* -------------------------------------------------- Sperrcode einrichten */

  async function setupPin(event: React.FormEvent) {
    event.preventDefault()
    if (busy || !pending) return

    const problem = pinProblem(pin)
    if (problem) return setError(problem)
    if (pin !== pin2) return setError('Die beiden Eingaben stimmen nicht überein.')

    setBusy(true)
    setError(null)

    try {
      let privateJwk: JsonWebKey
      let publicJwk: JsonWebKey

      // Erst die Schluessel, dann die Sitzung, dann der Tresor. Schlaegt etwas
      // davor fehl, bleibt kein halber Tresor zurueck.
      if (pending.kind === 'device') {
        // Die zweite Hälfte des Codes hat den Server nie gesehen. Nur mit ihr
        // lässt sich der mitgereiste Identitätsschlüssel öffnen.
        const unwrapKey = await keyFromSecret(pending.secret, fromB64(pending.payloadSalt!))
        const moved = await unsealJson<{ privateJwk: JsonWebKey; publicJwk: JsonWebKey }>(
          unwrapKey,
          { iv: pending.payloadIv!, ct: pending.payload! }
        )
        privateJwk = moved.privateJwk
        publicJwk = moved.publicJwk
      } else {
        const pair = await generateIdentity()
        privateJwk = await exportJwk(pair.privateKey)
        publicJwk = await exportJwk(pair.publicKey)
      }

      const supabase = createClient()
      const { error: sessionError } = await supabase.auth.verifyOtp({
        type: 'magiclink',
        token_hash: pending.tokenHash,
      })
      if (sessionError) {
        throw new Error(`Die Anmeldung schlug fehl: ${sessionError.message}`)
      }

      const pinKey = await createVault({
        userId: pending.userId,
        username: pending.username,
        publicJwk,
        privateJwk,
        pin,
      })

      if (pending.kind === 'invite') {
        await supabase
          .from('profiles')
          .update({ identity_public_key: publicJwk, key_fingerprint: await fingerprint(publicJwk) })
          .eq('id', pending.userId)
      }

      const { data } = await supabase.auth.getSession()
      if (data.session) {
        await stashSession(pinKey, {
          access_token: data.session.access_token,
          refresh_token: data.session.refresh_token,
        })
      }

      const vault = await readVault()
      setRing({ vault: vault!, pinKey, identityPrivate: await importPrivateJwk(privateJwk) })
      setPin('')
      setPin2('')
      router.replace('/chat')
    } catch (problem) {
      await wipeVault()
      await createClient().auth.signOut()
      setPending(null)
      setStage('code')
      setError(problem instanceof Error ? problem.message : 'Das hat nicht geklappt.')
      setBusy(false)
    }
  }

  /* ------------------------------------------------------------------- View */

  if (stage === 'checking') {
    return <main className="gate" />
  }

  return (
    <main className="gate">
      {stage === 'unlock' && (
        <form className="slip" onSubmit={unlock}>
          <div className="perf" aria-hidden="true" />
          <h1>Entsperren</h1>
          <p className="lede">
            Der Chat hat sich gesperrt. Dein Sperrcode gibt die Schlüssel wieder frei.
          </p>

          <div className="row">
            <label htmlFor="pin">Sperrcode</label>
            <input
              id="pin"
              className="field"
              type="password"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              autoFocus
              autoComplete="current-password"
              required
            />
          </div>

          {error && <p className="note" role="alert">{error}</p>}

          <button className="btn" type="submit" disabled={busy || !pin}>
            {busy ? 'Einen Moment' : 'Entsperren'}
          </button>

          <p className="fine">
            Nach fünf falschen Eingaben löscht sich der Tresor auf diesem Gerät. Du brauchst dann
            einen neuen Code.{' '}
            <button
              type="button"
              className="linkish"
              onClick={async () => {
                if (!window.confirm('Schlüssel auf diesem Gerät löschen?')) return
                await wipeVault()
                await createClient().auth.signOut()
                setStage('code')
                setError(null)
              }}
            >
              Von vorn anfangen
            </button>
          </p>
        </form>
      )}

      {stage === 'code' && (
        <form className="slip" onSubmit={redeem}>
          <div className="perf" aria-hidden="true" />
          <h1>Du wurdest eingeladen</h1>
          <p className="lede">
            Gib den Code ein, den du bekommen hast. Ein Einladungscode hat 16 Zeichen, ein Code für
            ein weiteres Gerät 20.
          </p>

          <div className="row">
            <label htmlFor="code">Code</label>
            <input
              id="code"
              className="code-input"
              value={formatCode(code)}
              onChange={(e) => setCode(normalizeCode(e.target.value, DEVICE_LEN))}
              placeholder="XXXX-XXXX-XXXX-XXXX"
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              autoFocus
              required
            />
          </div>

          {kind === 'invite' && (
            <div className="row">
              <label htmlFor="username">Dein Name im Chat</label>
              <input
                id="username"
                className="field"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="z. B. anna_m"
                maxLength={24}
                autoComplete="off"
                spellCheck={false}
                required
              />
            </div>
          )}

          {kind === 'device' && (
            <p className="fine" style={{ marginTop: 0 }}>
              Dieses Gerät wird mit deinem bestehenden Konto verbunden. Der Name bleibt.
            </p>
          )}

          {error && <p className="note" role="alert">{error}</p>}

          <button
            className="btn"
            type="submit"
            disabled={busy || !kind || (kind === 'invite' && username.trim().length < 3)}
          >
            {busy ? 'Einen Moment' : 'Weiter'}
          </button>

          <p className="fine">
            Der Code funktioniert genau einmal und verfällt in dem Moment, in dem du ihn benutzt.
          </p>
        </form>
      )}

      {stage === 'pin' && (
        <form className="slip" onSubmit={setupPin}>
          <div className="perf" aria-hidden="true" />
          <h1>Sperrcode festlegen</h1>
          <p className="lede">
            Damit wird dein Schlüssel auf diesem Gerät verschlüsselt. Ohne ihn kommt niemand an
            deine Nachrichten, auch nicht mit dem Gerät in der Hand.
          </p>

          <div className="row">
            <label htmlFor="newpin">Sperrcode, mindestens {PIN_MIN} Zeichen</label>
            <input
              id="newpin"
              className="field"
              type="password"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              autoComplete="new-password"
              autoFocus
              required
            />
          </div>

          <div className="row">
            <label htmlFor="newpin2">Noch einmal</label>
            <input
              id="newpin2"
              className="field"
              type="password"
              value={pin2}
              onChange={(e) => setPin2(e.target.value)}
              autoComplete="new-password"
              required
            />
          </div>

          {error && <p className="note" role="alert">{error}</p>}

          <button className="btn" type="submit" disabled={busy || !pin || !pin2}>
            {busy ? 'Schlüssel werden erzeugt' : 'Fertig'}
          </button>

          <p className="fine">
            Es gibt keine Wiederherstellung. Vergisst du den Sperrcode, brauchst du einen neuen
            Einladungscode und fängst mit leerem Verlauf an.
          </p>
        </form>
      )}
    </main>
  )
}
