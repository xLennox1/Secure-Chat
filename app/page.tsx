'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { createClient } from '@/lib/supabase/client'

export default function Home() {
  const [code, setCode] = useState('')
  const [username, setUsername] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const router = useRouter()

  async function redeem(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const res = await fetch('/api/redeem', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ authPart: code, username }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Fehler')

      const supabase = createClient()
      const { error: authError } = await supabase.auth.verifyOtp({
        token_hash: data.tokenHash,
        type: 'magiclink',
      })
      if (authError) throw new Error('Anmeldung konnte nicht abgeschlossen werden.')

      sessionStorage.setItem('invite-chat-user', JSON.stringify({
        userId: data.userId,
        username: data.username,
      }))
      router.push('/chat')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fehler')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="gate">
      <form className="card" onSubmit={redeem}>
        <h1>Invite-Chat</h1>
        <p>Privater Chat, nur mit Einladung.</p>
        <label>Einladungscode</label>
        <input className="field" value={code} onChange={e => setCode(e.target.value)} autoComplete="one-time-code" required />
        <label>Benutzername</label>
        <input className="field" value={username} onChange={e => setUsername(e.target.value)} minLength={3} maxLength={24} required />
        {error && <p className="note">{error}</p>}
        <button className="btn" disabled={busy}>{busy ? 'Prüfe…' : 'Einlösen'}</button>
      </form>
    </main>
  )
}
