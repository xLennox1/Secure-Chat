'use client'

import { createBrowserClient } from '@supabase/ssr'

export function createClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY

  if (!url || !key) {
    throw new Error(
      'NEXT_PUBLIC_SUPABASE_URL oder NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY fehlt. ' +
        'In Vercel unter Settings -> Environment Variables eintragen und neu deployen.'
    )
  }

  return createBrowserClient(url, key)
}
