import 'server-only'
import type { NextRequest } from 'next/server'
import type { SupabaseClient } from '@supabase/supabase-js'

export const MAX_ATTEMPTS = 8
export const WINDOW_MINUTES = 15

export const CODE_ERROR = 'Dieser Code ist ungueltig, abgelaufen oder schon benutzt.'

export function requirePepper(): string {
  const pepper = process.env.INVITE_CODE_PEPPER
  if (!pepper || pepper.length < 32) throw new Error('INVITE_CODE_PEPPER fehlt oder ist zu kurz')
  return pepper
}

export async function clientIpHash(request: NextRequest, pepper: string): Promise<string> {
  const ip =
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unbekannt'

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pepper),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const digest = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(ip))
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('')
}

export async function throttled(admin: SupabaseClient, ipHash: string): Promise<boolean> {
  const since = new Date(Date.now() - WINDOW_MINUTES * 60_000).toISOString()
  const { count } = await admin
    .from('redeem_attempts')
    .select('id', { count: 'exact', head: true })
    .eq('ip_hash', ipHash)
    .eq('success', false)
    .gte('created_at', since)
  return (count ?? 0) >= MAX_ATTEMPTS
}

export async function noteAttempt(admin: SupabaseClient, ipHash: string, success: boolean) {
  await admin.from('redeem_attempts').insert({ ip_hash: ipHash, success })
}

export async function issueSession(admin: SupabaseClient, email: string): Promise<string | null> {
  const { data, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email })
  if (error) return null
  return data?.properties?.hashed_token ?? null
}
