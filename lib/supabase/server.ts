import { cookies } from 'next/headers'
import { createServerClient } from '@supabase/ssr'

/** Client fuer Server Components und Route Handler. Laeuft mit der Sitzung des Besuchers. */
export async function createClient() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY

  if (!url || !key) {
    throw new Error(
      'NEXT_PUBLIC_SUPABASE_URL oder NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY fehlt. ' +
        'In Vercel unter Settings -> Environment Variables eintragen und neu deployen.'
    )
  }

  const cookieStore = await cookies()

  return createServerClient(url, key, {
    cookies: {
      getAll: () => cookieStore.getAll(),
      setAll: (list) => {
        try {
          list.forEach(({ name, value, options }) => cookieStore.set(name, value, options))
        } catch {
          // In Server Components darf nicht geschrieben werden; die Middleware macht das.
        }
      },
    },
  })
}
