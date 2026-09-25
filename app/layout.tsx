import type { Metadata, Viewport } from 'next'
import { IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google'
import './globals.css'

// Wichtig fuer die CSP: middleware.ts erzeugt pro Anfrage eine neue Nonce.
// Ohne 'force-dynamic' haette Next.js die Startseite (rein clientseitig,
// keine dynamic APIs) beim Build einmal statisch vorgerendert — mit genau
// einer, fest eingebackenen Nonce im HTML. Die CSP-Antwort traegt aber bei
// jedem Aufruf eine ANDERE, frische Nonce. Nonce im Script-Tag != Nonce im
// CSP-Header, der Browser blockt daraufhin schlicht jedes Script — und die
// Seite bleibt leer, weil React nie hydriert. 'force-dynamic' hier auf dem
// Root-Layout sorgt dafuer, dass jede Route (auch neue) live gerendert wird,
// mit einer zur Antwort passenden Nonce. 'use client'-Seiten wie app/page.tsx
// koennten dasselbe Export selbst nicht setzen, es wird dort ignoriert — es
// muss von einer Server-Komponente wie diesem Layout kommen.
export const dynamic = 'force-dynamic'

// next/font laedt die Schriften beim Build herunter und liefert sie aus der
// eigenen Domain aus. Kein Aufruf zu Google, kein IP-Abfluss beim Besucher.
const sans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-sans',
  display: 'swap',
})

const mono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['500'],
  variable: '--font-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'Chat',
  description: 'Privater Chat, nur mit Einladung.',
  robots: { index: false, follow: false },
}

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  viewportFit: 'cover',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="de" className={`${sans.variable} ${mono.variable}`}>
      <body>{children}</body>
    </html>
  )
}