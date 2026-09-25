'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import { createClient } from '@/lib/supabase/client'
import { useIdleLock } from '@/lib/idle'
import { getRing, wipeRing } from '@/lib/keyring'
import { stashSession } from '@/lib/vault'
import {
  DEVICE_LEN,
  authPart,
  formatCode,
  generateCode,
  secretPart,
} from '@/lib/codes'
import {
  exportJwk,
  fingerprint,
  generateConversationKey,
  keyContext,
  keyFromSecret,
  messageContext,
  randomBytes,
  sameKey,
  sealJson,
  sealText,
  toB64,
  unsealText,
  unwrapFrom,
  wrapFor,
  type KeyRow,
} from '@/lib/crypto'

const IDLE_MINUTES = Number(process.env.NEXT_PUBLIC_IDLE_MINUTES ?? 5)

type Profile = { id: string; username: string; identity_public_key: JsonWebKey | null; avatar_url: string | null }
type Member = { user_id: string; role: string; profiles: { id: string; username: string } | null }
type Conversation = {
  id: string
  type: 'dm' | 'group'
  title: string | null
  key_epoch: number
  last_message_at: string
  conversation_members: Member[]
}
type Row = {
  id: string
  conversation_id: string
  sender_id: string | null
  ciphertext: string
  iv: string
  key_epoch: number
  created_at: string
}
type Shown = { id: string; sender_id: string | null; text: string; created_at: string; ok: boolean }

const CONVERSATION_SELECT =
  'id, type, title, key_epoch, last_message_at, conversation_members(user_id, role, profiles(id, username))'
const MESSAGE_SELECT = 'id, conversation_id, sender_id, ciphertext, iv, key_epoch, created_at'

const clock = (iso: string) =>
  new Date(iso).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })

const AVATAR_COLORS = ['#1f4a38', '#8e3e1e', '#6b5228', '#54406e', '#2e5c66']

function initials(name: string): string {
  const letters = name.replace(/[^\p{L}\p{N}]/gu, '')
  return (letters.slice(0, 2) || name.slice(0, 2) || '?').toUpperCase()
}

function avatarColor(id: string): string {
  let hash = 0
  for (let i = 0; i < id.length; i++) hash = (hash * 31 + id.charCodeAt(i)) >>> 0
  return AVATAR_COLORS[hash % AVATAR_COLORS.length]
}

const AVATAR_SIDE = 320
const AVATAR_MAX_CHARS = 380_000
async function processImageFile(file: File): Promise<string> {
  if (!file.type.startsWith('image/')) throw new Error('Das ist kein Bild.')
  const objectUrl = URL.createObjectURL(file)
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image()
      el.onload = () => resolve(el)
      el.onerror = () => reject(new Error('Das Bild ließ sich nicht lesen.'))
      el.src = objectUrl
    })
    const side = Math.min(img.naturalWidth, img.naturalHeight)
    if (!side) throw new Error('Das Bild ließ sich nicht lesen.')
    const canvas = document.createElement('canvas')
    canvas.width = AVATAR_SIDE
    canvas.height = AVATAR_SIDE
    const ctx = canvas.getContext('2d')
    if (!ctx) throw new Error('Bildbearbeitung wird hier nicht unterstützt.')
    ctx.drawImage(img, (img.naturalWidth-side)/2, (img.naturalHeight-side)/2, side, side, 0, 0, AVATAR_SIDE, AVATAR_SIDE)
    for (const quality of [0.85, 0.7, 0.55, 0.4]) {
      const dataUrl = canvas.toDataURL('image/jpeg', quality)
      if (dataUrl.length <= AVATAR_MAX_CHARS) return dataUrl
    }
    throw new Error('Das Bild ist auch verkleinert noch zu groß.')
  } finally { URL.revokeObjectURL(objectUrl) }
}

export default function ChatClient({ me }: { me: { id: string; username: string } }) {
  const supabase = useMemo(() => createClient(), [])
  const router = useRouter()
  const ring = getRing()

  const [people, setPeople] = useState<Profile[]>([])
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [messages, setMessages] = useState<Shown[]>([])
  const [unread, setUnread] = useState<Set<string>>(new Set())
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [noKey, setNoKey] = useState(false)
  const [dialog, setDialog] = useState<null | 'group' | 'invite' | 'device' | 'keys' | 'avatar'>(null)
  const [deviceCode, setDeviceCode] = useState<string | null>(null)
  const [view, setView] = useState<'roster' | 'thread'>('roster')

  const keys = useRef(new Map<string, CryptoKey>())
  const activeRef = useRef<string | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  activeRef.current = activeId

  const active = conversations.find((c) => c.id === activeId) ?? null

  const lock = useCallback(async () => {
    keys.current.clear()
    wipeRing()
    setMessages([])
    setDraft('')
    await supabase.auth.signOut({ scope: 'local' })
    router.replace('/')
  }, [supabase, router])

  const secondsLeft = useIdleLock(IDLE_MINUTES, lock)

  useEffect(() => {
    if (!ring) router.replace('/')
  }, [ring, router])

  useEffect(() => {
    if (!ring) return
    const { data } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) {
        void stashSession(ring.pinKey, {
          access_token: session.access_token,
          refresh_token: session.refresh_token,
        })
      }
    })
    return () => data.subscription.unsubscribe()
  }, [supabase, ring])

  const publicKeyOf = useCallback(
    (userId: string) => people.find((p) => p.id === userId)?.identity_public_key ?? null,
    [people]
  )

  const loadMyKeys = useCallback(
    async (roster: Profile[]) => {
      if (!ring) return
      const { data } = await supabase
        .from('conversation_keys')
        .select('conversation_id, epoch, wrapped_key, sender_public_key, iv, created_by')
        .eq('user_id', me.id)

      for (const row of data ?? []) {
        const claimed = roster.find((p) => p.id === row.created_by)?.identity_public_key
        if (!sameKey(claimed, row.sender_public_key as JsonWebKey)) continue
        try {
          const key = await unwrapFrom(
            ring.identityPrivate,
            row as unknown as KeyRow,
            keyContext(row.conversation_id, row.epoch)
          )
          keys.current.set(`${row.conversation_id}:${row.epoch}`, key)
        } catch {}
      }
    },
    [supabase, me.id, ring]
  )

  const ensureKey = useCallback(
    async (conv: Conversation): Promise<CryptoKey | null> => {
      if (!ring) return null
      const epoch = conv.key_epoch
      const slot = `${conv.id}:${epoch}`
      const context = keyContext(conv.id, epoch)

      const { data: rows } = await supabase
        .from('conversation_keys')
        .select('user_id')
        .eq('conversation_id', conv.id)
        .eq('epoch', epoch)

      const have = new Set((rows ?? []).map((r) => r.user_id))
      let key = keys.current.get(slot) ?? null

      if (!key && have.size > 0) return null
      if (!key) key = await generateConversationKey()

      const myPublic = ring.vault.publicJwk
      for (const member of conv.conversation_members) {
        if (have.has(member.user_id)) continue
        const recipient = publicKeyOf(member.user_id)
        if (!recipient) continue
        const wrapped = await wrapFor(key, ring.identityPrivate, myPublic, recipient, context)
        await supabase.from('conversation_keys').insert({
          conversation_id: conv.id,
          user_id: member.user_id,
          epoch,
          created_by: me.id,
          ...wrapped,
        })
      }

      const { data: mine } = await supabase
        .from('conversation_keys')
        .select('wrapped_key, sender_public_key, iv, created_by')
        .eq('conversation_id', conv.id)
        .eq('epoch', epoch)
        .eq('user_id', me.id)
        .maybeSingle()

      if (!mine) return null
      const claimed = publicKeyOf(mine.created_by as string)
      if (!sameKey(claimed, mine.sender_public_key as JsonWebKey)) return null

      const settled = await unwrapFrom(ring.identityPrivate, mine as unknown as KeyRow, context)
      keys.current.set(slot, settled)
      return settled
    },
    [supabase, me.id, ring, publicKeyOf]
  )

  const decrypt = useCallback(async (row: Row): Promise<Shown> => {
    const key = keys.current.get(`${row.conversation_id}:${row.key_epoch}`)
    const base = { id: row.id, sender_id: row.sender_id, created_at: row.created_at }
    if (!key) return { ...base, text: 'Für dieses Gerät nicht lesbar.', ok: false }
    try {
      const text = await unsealText(
        key,
        { iv: row.iv, ct: row.ciphertext },
        messageContext(row.conversation_id, row.key_epoch)
      )
      return { ...base, text, ok: true }
    } catch {
      return { ...base, text: 'Nicht entschlüsselbar.', ok: false }
    }
  }, [])

  const loadConversations = useCallback(async () => {
    const { data } = await supabase
      .from('conversations')
      .select(CONVERSATION_SELECT)
      .order('last_message_at', { ascending: false })
    const list = (data ?? []) as unknown as Conversation[]
    setConversations(list)
    return list
  }, [supabase])

  useEffect(() => {
    if (!ring) return
    let cancelled = false

    ;(async () => {
      const { data: self } = await supabase
        .from('profiles')
        .select('identity_public_key')
        .eq('id', me.id)
        .maybeSingle()

      if (self && !self.identity_public_key) {
        await supabase
          .from('profiles')
          .update({
            identity_public_key: ring.vault.publicJwk,
            key_fingerprint: await fingerprint(ring.vault.publicJwk),
          })
          .eq('id', me.id)
      }

      const [{ data: roster }, { data: avatars }] = await Promise.all([
        supabase.from('profiles').select('id, username, identity_public_key').order('username'),
        supabase.from('avatars').select('user_id, data_url'),
      ])
      if (cancelled) return
      const avatarMap = new Map((avatars ?? []).map((a) => [a.user_id as string, a.data_url as string]))
      const list = ((roster ?? []) as Omit<Profile, 'avatar_url'>[]).map((p) => ({ ...p, avatar_url: avatarMap.get(p.id) ?? null }))
      setPeople(list)
      await loadMyKeys(list)
      await loadConversations()
    })()

    return () => { cancelled = true }
  }, [supabase, me.id, ring, loadMyKeys, loadConversations])

  useEffect(() => {
    if (!ring) return
    const channel = supabase
      .channel('live')
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'messages' }, (payload) => {
        const row = payload.new as Row
        if (row.conversation_id === activeRef.current) {
          void decrypt(row).then((shown) =>
            setMessages((prev) => (prev.some((m) => m.id === shown.id) ? prev : [...prev, shown]))
          )
        } else {
          setUnread((prev) => new Set(prev).add(row.conversation_id))
        }
        void loadConversations()
      })
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'conversation_members', filter: `user_id=eq.${me.id}` },
        () => void loadConversations()
      )
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'conversation_keys', filter: `user_id=eq.${me.id}` },
        () => {
          void (async () => {
            const { data: roster } = await supabase
              .from('profiles')
              .select('id, username, identity_public_key')
            await loadMyKeys((roster ?? []) as Profile[])
            if (activeRef.current) await openConversation(activeRef.current)
          })()
        }
      )
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'avatars' },
        (payload) => {
          if (payload.eventType === 'DELETE') {
            const old = payload.old as { user_id?: string }
            if (!old.user_id) return
            setPeople((prev) => prev.map((p) => p.id === old.user_id ? { ...p, avatar_url: null } : p))
            return
          }
          const row = payload.new as { user_id: string; data_url: string }
          setPeople((prev) => prev.map((p) => p.id === row.user_id ? { ...p, avatar_url: row.data_url } : p))
        }
      )
      .subscribe()

    return () => { void supabase.removeChannel(channel) }
  }, [supabase, ring, me.id])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: 'end' })
  }, [messages])

  async function openConversation(id: string) {
    setActiveId(id)
    setView('thread')
    setUnread((prev) => {
      const next = new Set(prev)
      next.delete(id)
      return next
    })

    const list = conversations.length ? conversations : await loadConversations()
    const conv = list.find((c) => c.id === id)
    if (conv) setNoKey((await ensureKey(conv)) === null)

    const { data } = await supabase
      .from('messages')
      .select(MESSAGE_SELECT)
      .eq('conversation_id', id)
      .order('created_at', { ascending: true })
      .limit(300)

    setMessages(await Promise.all(((data ?? []) as Row[]).map(decrypt)))
  }

  async function openDm(otherId: string) {
    setError(null)
    if (!publicKeyOf(otherId)) return setError('Diese Person hat noch keinen Schlüssel hinterlegt.')
    const { data, error: rpcError } = await supabase.rpc('start_dm', { other_user: otherId })
    if (rpcError || !data) return setError('Die Unterhaltung ließ sich nicht öffnen.')
    await loadConversations()
    await openConversation(data as string)
  }

  async function send(event: React.SyntheticEvent) {
    event.preventDefault()
    const body = draft.trim()
    if (!body || !active) return

    const key = keys.current.get(`${active.id}:${active.key_epoch}`) ?? (await ensureKey(active))
    if (!key) return setError('Noch kein Schlüssel für diese Unterhaltung.')

    setDraft('')
    const sealed = await sealText(key, body, messageContext(active.id, active.key_epoch))
    const { error: insertError } = await supabase.from('messages').insert({
      conversation_id: active.id,
      sender_id: me.id,
      ciphertext: sealed.ct,
      iv: sealed.iv,
      key_epoch: active.key_epoch,
    })

    if (insertError) {
      setDraft(body)
      setError('Die Nachricht wurde nicht gesendet.')
    } else setError(null)
  }

  async function makeDeviceCode() {
    if (!ring) return
    setError(null)
    const code = generateCode(DEVICE_LEN)
    const salt = randomBytes(16)
    const transport = await keyFromSecret(secretPart(code), salt)
    const sealed = await sealJson(transport, {
      privateJwk: await exportJwk(ring.identityPrivate),
      publicJwk: ring.vault.publicJwk,
    })

    const response = await fetch('/api/device-code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        authPart: authPart(code),
        payload: sealed.ct,
        payloadIv: sealed.iv,
        payloadSalt: toB64(salt),
      }),
    })

    if (!response.ok) return setError('Der Code ließ sich nicht anlegen.')
    setDeviceCode(formatCode(code))
    setDialog('device')
  }

  const others = people.filter((p) => p.id !== me.id)
  const isOwner = active?.conversation_members.some((m) => m.user_id === me.id && m.role === 'owner')
  const titleOf = (c: Conversation) =>
    c.type === 'group' ? c.title ?? 'Gruppe' : c.conversation_members.find((m) => m.user_id !== me.id)?.profiles?.username ?? 'Direktnachricht'
  const nameOf = (id: string | null) =>
    id === me.id ? me.username : people.find((p) => p.id === id)?.username ?? 'Unbekannt'

  const myAvatar = people.find((p) => p.id === me.id)?.avatar_url ?? null
  const avatarOf = (c: Conversation) => {
    if (c.type === 'group') return { id: c.id, name: c.title ?? 'Gruppe', imageUrl: null as string | null }
    const other = c.conversation_members.find((m) => m.user_id !== me.id)
    const name = other?.profiles?.username ?? '?'
    return { id: other?.user_id ?? name, name, imageUrl: people.find((p) => p.id === other?.user_id)?.avatar_url ?? null }
  }
  async function saveAvatar(dataUrl: string): Promise<string | null> {
    const { error } = await supabase.from('avatars').upsert({ user_id: me.id, data_url: dataUrl })
    if (error) return 'Das Profilbild ließ sich nicht speichern.'
    setPeople((prev) => prev.map((p) => p.id === me.id ? { ...p, avatar_url: dataUrl } : p))
    return null
  }
  async function removeAvatar(): Promise<string | null> {
    const { error } = await supabase.from('avatars').delete().eq('user_id', me.id)
    if (error) return 'Das Profilbild ließ sich nicht entfernen.'
    setPeople((prev) => prev.map((p) => p.id === me.id ? { ...p, avatar_url: null } : p))
    return null
  }

  if (!ring) return null

  return (
    <div className="shell" data-view={view}>
      {secondsLeft !== null && <div className="idle-warn" role="status">Sperrt in {secondsLeft} s ohne Eingabe</div>}

      <aside className="roster">
        <div className="roster-head">
          <span className="who-me">
            <button type="button" className="avatar-edit" onClick={() => setDialog('avatar')} aria-label="Profilbild ändern"><Avatar id={me.id} name={me.username} imageUrl={myAvatar} size="avatar-lg" /></button>
            <strong>{me.username}</strong>
          </span>
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button className="btn-quiet" onClick={() => setDialog('keys')}>Schlüssel</button>
            <button className="btn-quiet" onClick={lock}>Sperren</button>
          </div>
        </div>

        <div className="roster-scroll">
          <div className="section-head">
            <span>Unterhaltungen</span>
            <button className="btn-quiet" onClick={() => setDialog('group')}>Gruppe anlegen</button>
          </div>

          {conversations.length === 0 && <p className="empty">Noch nichts. Schreib jemanden aus der Liste unten an.</p>}

          {conversations.map((c) => {
            const avatar = avatarOf(c)
            return (
              <button key={c.id} className="entry" aria-current={c.id === activeId} onClick={() => openConversation(c.id)}>
                <Avatar id={avatar.id} name={avatar.name} imageUrl={avatar.imageUrl} />
                <span className="entry-text">
                  <span className="entry-title">{titleOf(c)}{unread.has(c.id) && <span className="muted"> · neu</span>}</span>
                  <span className="sub">{c.type === 'group' ? `${c.conversation_members.length} Mitglieder` : 'Direktnachricht'}</span>
                </span>
              </button>
            )
          })}

          <div className="section-head"><span>Personen</span></div>
          {others.length === 0 && <p className="empty">Du bist noch allein hier.</p>}
          {others.map((p) => (
            <button key={p.id} className="entry" onClick={() => openDm(p.id)}>
              <span className="avatar" style={{ background: avatarColor(p.id) }}>{initials(p.username)}</span>
              <span className="entry-text">
                <span className="entry-title">{p.username}</span>
                {!p.identity_public_key && <span className="sub">ohne Schlüssel</span>}
              </span>
            </button>
          ))}

          <div className="section-head"><span>Dieses Konto</span></div>
          <button className="entry" onClick={makeDeviceCode}>
            <span className="avatar avatar-action">+</span>
            <span className="entry-text">
              <span className="entry-title">Weiteres Gerät verbinden</span>
              <span className="sub">Code gilt zehn Minuten</span>
            </span>
          </button>
        </div>
      </aside>

      <section className="thread">
        {!active && <div className="blank"><p>Wähle links eine Unterhaltung oder schreib jemanden an.</p></div>}

        {active && (
          <>
            <header className="thread-head">
              <div>
                <h2>{titleOf(active)}</h2>
                {active.type === 'group' && <span className="sub">{active.conversation_members.map((m) => m.profiles?.username ?? '?').join(', ')}</span>}
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {active.type === 'group' && isOwner && <button className="btn-quiet" onClick={() => setDialog('invite')}>Einladen</button>}
                <button className="btn-quiet back" onClick={() => setView('roster')}>Zurück</button>
              </div>
            </header>

            <div className="transcript">
              {noKey && <p className="muted">Für diese Unterhaltung fehlt dir noch der Schlüssel. Er kommt, sobald ein anderes Mitglied den Chat das nächste Mal öffnet.</p>}
              {!noKey && messages.length === 0 && <p className="muted">Noch keine Nachrichten.</p>}
              {messages.map((m, i) => {
                const mine = m.sender_id === me.id
                const prev = messages[i - 1]
                const next = messages[i + 1]
                const grouped = !!prev && prev.sender_id === m.sender_id
                const lastInGroup = !next || next.sender_id !== m.sender_id
                return (
                  <article key={m.id} className={`turn${mine ? ' mine' : ''}${grouped ? ' grouped' : ''}`}>
                    <div className={`bubble${m.ok ? '' : ' sealed'}`}>
                      {!mine && !grouped && <span className="who">{nameOf(m.sender_id)}</span>}
                      <p>{m.text}</p>
                      {lastInGroup && <span className="when">{clock(m.created_at)}</span>}
                    </div>
                  </article>
                )
              })}
              <div ref={bottomRef} />
            </div>

            {error && <p className="note" role="alert" style={{ padding: '0 1.5rem' }}>{error}</p>}

            <form className="composer" onSubmit={send}>
              <textarea
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault()
                    void send(e)
                  }
                }}
                placeholder="Nachricht schreiben"
                maxLength={4000}
                rows={1}
              />
              <button className="btn" type="submit" disabled={!draft.trim()}>Senden</button>
            </form>
          </>
        )}
      </section>

      {dialog === 'device' && deviceCode && (
        <Sheet title="Weiteres Gerät verbinden" onClose={() => setDialog(null)}>
          <p className="muted">Tipp diesen Code auf dem anderen Gerät ein. Er gilt zehn Minuten und genau einmal.</p>
          <p className="code-show">{deviceCode}</p>
          <p className="fine">Die zweite Hälfte des Codes erreicht den Server nie. Nur sie öffnet den Schlüssel, der verschlüsselt mitreist. Gib den Code über einen Weg weiter, den sonst niemand mitliest.</p>
        </Sheet>
      )}

      {dialog === 'avatar' && (
        <Sheet title="Profilbild" onClose={() => setDialog(null)}>
          <AvatarPicker id={me.id} name={me.username} current={myAvatar} onSave={saveAvatar} onRemove={removeAvatar} />
        </Sheet>
      )}

      {dialog === 'keys' && (
        <Sheet title="Fingerabdrücke" onClose={() => setDialog(null)}>
          <p className="muted">Vergleicht die Zeilen über einen anderen Kanal, etwa persönlich. Stimmen sie überein, hat unterwegs niemand Schlüssel ausgetauscht.</p>
          <Fingerprints people={people} meId={me.id} />
        </Sheet>
      )}

      {dialog === 'group' && (
        <GroupDialog
          people={others.filter((p) => p.identity_public_key)}
          onClose={() => setDialog(null)}
          onCreate={async (title, ids) => {
            const { data, error: rpcError } = await supabase.rpc('create_group', { p_title: title, p_members: ids })
            if (rpcError || !data) return setError('Die Gruppe ließ sich nicht anlegen.')
            setDialog(null)
            await loadConversations()
            await openConversation(data as string)
          }}
        />
      )}

      {dialog === 'invite' && active && (
        <GroupDialog
          title="Zur Gruppe einladen"
          people={others.filter((p) => p.identity_public_key && !active.conversation_members.some((m) => m.user_id === p.id))}
          onClose={() => setDialog(null)}
          onCreate={async (_ignored, ids) => {
            for (const id of ids) await supabase.rpc('invite_to_group', { p_conversation: active.id, p_user: id })
            await supabase.rpc('rotate_conversation_key', { p_conversation: active.id })
            setDialog(null)
            const list = await loadConversations()
            const fresh = list.find((c) => c.id === active.id)
            if (fresh) await ensureKey(fresh)
            await openConversation(active.id)
          }}
        />
      )}
    </div>
  )
}

function Sheet({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="scrim" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        {children}
        <div className="actions" style={{ marginTop: '1.25rem' }}>
          <button className="btn-quiet" onClick={onClose}>Schließen</button>
        </div>
      </div>
    </div>
  )
}

function Avatar({ id, name, imageUrl, size = '' }: { id: string; name: string; imageUrl?: string | null; size?: 'avatar-lg' | 'avatar-sm' | '' }) {
  const className = ['avatar', size].filter(Boolean).join(' ')
  return imageUrl ? <span className={className}><img src={imageUrl} alt="" /></span> : <span className={className} style={{ background: avatarColor(id) }}>{initials(name)}</span>
}

function AvatarPicker({ id, name, current, onSave, onRemove }: {
  id: string; name: string; current: string | null
  onSave: (dataUrl: string) => Promise<string | null>; onRemove: () => Promise<string | null>
}) {
  const [preview, setPreview] = useState<string | null>(current)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const cameraRef = useRef<HTMLInputElement>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  async function handleFile(file?: File) {
    if (!file) return
    setBusy(true); setError(null)
    try { const dataUrl = await processImageFile(file); const problem = await onSave(dataUrl); if (problem) setError(problem); else setPreview(dataUrl) }
    catch (e) { setError(e instanceof Error ? e.message : 'Das hat nicht geklappt.') }
    setBusy(false)
  }
  return <div className="avatar-picker">
    <Avatar id={id} name={name} imageUrl={preview} size="avatar-lg" />
    {error && <p className="note" role="alert">{error}</p>}
    <input ref={cameraRef} type="file" accept="image/*" capture="user" hidden onChange={e => { void handleFile(e.target.files?.[0]); e.target.value = '' }} />
    <input ref={fileRef} type="file" accept="image/*" hidden onChange={e => { void handleFile(e.target.files?.[0]); e.target.value = '' }} />
    <div className="avatar-picker-actions">
      <button className="btn-quiet" type="button" disabled={busy} onClick={() => cameraRef.current?.click()}>Kamera</button>
      <button className="btn-quiet" type="button" disabled={busy} onClick={() => fileRef.current?.click()}>Bild auswählen</button>
      {current && <button className="btn-quiet" type="button" disabled={busy} onClick={async () => { setBusy(true); setError(await onRemove()); setPreview(null); setBusy(false) }}>Entfernen</button>}
    </div>
    <p className="fine">Wird zentriert zugeschnitten und verkleinert. Wie Name und Gruppennamen ist das Profilbild nicht Ende-zu-Ende-verschlüsselt, sondern für alle Mitglieder sichtbar.</p>
  </div>
}

function Fingerprints({ people, meId }: { people: Profile[]; meId: string }) {
  const [rows, setRows] = useState<{ id: string; username: string; avatarUrl: string | null; print: string }[]>([])
  useEffect(() => {
    void Promise.all(
      people.filter((p) => p.identity_public_key).map(async (p) => ({
        id: p.id,
        username: p.username,
        avatarUrl: p.avatar_url,
        print: await fingerprint(p.identity_public_key!),
      }))
    ).then(setRows)
  }, [people])

  return (
    <div className="prints">
      {rows.map((row) => (
        <div key={row.id}>
          <span className="fp-row">
            <Avatar id={row.id} name={row.username} imageUrl={row.avatarUrl} size="avatar-sm" />
            {row.username}{row.id === meId ? ' (du)' : ''}
          </span>
          <code>{row.print}</code>
        </div>
      ))}
    </div>
  )
}

function GroupDialog({
  title = 'Neue Gruppe',
  people,
  onClose,
  onCreate,
}: {
  title?: string
  people: Profile[]
  onClose: () => void
  onCreate: (title: string, ids: string[]) => Promise<unknown>
}) {
  const naming = title === 'Neue Gruppe'
  const [name, setName] = useState('')
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)

  const toggle = (id: string) =>
    setPicked((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  return (
    <div className="scrim" onClick={onClose}>
      <div className="dialog" onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        {naming && (
          <input className="field" value={name} onChange={(e) => setName(e.target.value)} placeholder="Name der Gruppe" maxLength={60} autoFocus />
        )}
        {people.length === 0 ? (
          <p className="empty">Niemand übrig, den du hinzufügen könntest.</p>
        ) : (
          <div className="picker">
            {people.map((p) => (
              <label key={p.id} className="pick">
                <input type="checkbox" checked={picked.has(p.id)} onChange={() => toggle(p.id)} />
                <Avatar id={p.id} name={p.username} imageUrl={p.avatar_url} size="avatar-sm" />
                {p.username}
              </label>
            ))}
          </div>
        )}
        <div className="actions">
          <button className="btn-quiet" onClick={onClose}>Abbrechen</button>
          <button className="btn" disabled={busy || (naming ? !name.trim() : picked.size === 0)} onClick={async () => { setBusy(true); await onCreate(name.trim(), [...picked]); setBusy(false) }}>
            {naming ? 'Gruppe anlegen' : 'Einladen'}
          </button>
        </div>
      </div>
    </div>
  )
}
