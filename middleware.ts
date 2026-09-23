import { NextResponse, type NextRequest } from 'next/server'
import { createServerClient } from '@supabase/ssr'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL ?? ''
const supabaseWs = supabaseUrl.replace(/^https:/, 'wss:')
const isDev = process.env.NODE_ENV === 'development'

/**
 * Die CSP entsteht hier statt in next.config.mjs, weil sie pro Anfrage eine
 * frische Nonce braucht. Next.js liest den Header vom Request und haengt die
 * Nonce automatisch an seine eigenen Skript-Tags.
 *
 * 'strict-dynamic' bedeutet: nur Skripte mit gueltiger Nonce laufen, und nur
 * die duerfen weitere Skripte nachladen. Eine eingeschleuste <script>-Zeile
 * hat keine Nonce und wird vom Browser verworfen.
 */
function buildCsp(nonce: string) {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' ${isDev ? "'unsafe-eval'" : ''}`,
    // Schriften kommen aus dem eigenen Build (next/font), nicht von Google.
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",
    "img-src 'self' data: blob:",
    `connect-src 'self' ${supabaseUrl} ${supabaseWs}`,
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "object-src 'none'",
    'upgrade-insecure-requests',
  ]
    .map((line) => line.trim().replace(/\s+/g, ' '))
    .join('; ')
}

export async function middleware(request: NextRequest) {
  const nonce = btoa(crypto.randomUUID())
  const csp = buildCsp(nonce)

  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('Content-Security-Policy', csp)

  let response = NextResponse.next({ request: { headers: requestHeaders } })

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
    {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (list) => {
          list.forEach(({ name, value }) => request.cookies.set(name, value))
          response = NextResponse.next({ request: { headers: requestHeaders } })
          list.forEach(({ name, value, options }) => response.cookies.set(name, value, options))
        },
      },
    }
  )

  // getUser() prueft das Token beim Auth-Server. getSession() wuerde nur dem Cookie glauben.
  const { data: { user } } = await supabase.auth.getUser()
  const path = request.nextUrl.pathname

  if (!user && path.startsWith('/chat')) {
    return NextResponse.redirect(new URL('/', request.url))
  }
  // Kein Umleiten von '/' nach '/chat': die Startseite ist auch der
  // Entsperrbildschirm. Ob jemand schon entsperrt ist, weiss nur der Browser.

  response.headers.set('Content-Security-Policy', csp)
  return response
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)'],
}
