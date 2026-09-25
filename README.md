# Invite-Chat

Privater Invite-Chat im Browser mit Ende-zu-Ende-Verschlüsselung.

- Next.js App Router auf Vercel
- Supabase für Auth, Datenbank und Realtime
- AES-256-GCM für Nachrichten
- ECDH P-256 + HKDF-SHA-256 für Schlüsselverteilung
- IndexedDB-Tresor für den lokalen Identitätsschlüssel
- Einladungscodes (16 Zeichen) und Geräte-Codes (20 Zeichen)

## Einrichtung

1. Supabase-SQL aus `supabase/01-schema.sql` ausführen.
2. `supabase/02-retention.sql` danach ausführen.
3. In Vercel setzen:
   - `NEXT_PUBLIC_SUPABASE_URL`
   - `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`
   - `SUPABASE_SECRET_KEY`
   - `INVITE_CODE_PEPPER`
   - `INVITE_EMAIL_DOMAIN`
   - `NEXT_PUBLIC_IDLE_MINUTES`
4. Vercel neu deployen.

Die Nachrichtentexte werden vor dem Schreiben in die Datenbank verschlüsselt. In `messages` liegen nur Ciphertext, IV und Epoche. Metadaten wie Benutzername, Zeit und Gesprächszugehörigkeit bleiben sichtbar.

Vergisst jemand den lokalen Sperrcode, kann der verschlüsselte private Identitätsschlüssel auf diesem Gerät nicht wiederhergestellt werden.
