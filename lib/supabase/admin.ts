import 'server-only'
import { createClient } from '@supabase/supabase-js'
export function createAdminClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.SUPABASE_SECRET_KEY
  if (!url) throw new Error('NEXT_PUBLIC_SUPABASE_URL fehlt')
  if (!key) throw new Error('SUPABASE_SECRET_KEY fehlt')
  if (!key.startsWith('sb_secret_') && !key.startsWith('eyJ')) throw new Error('SUPABASE_SECRET_KEY ist kein Secret Key')
  return createClient(url, key, { auth: { autoRefreshToken: false, persistSession: false } })
}
