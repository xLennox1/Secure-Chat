-- ============================================================================
--  04  Fotos im Chat
--
--  Im SQL Editor ausführen, nach 01-schema.sql. Die Reihenfolge zu
--  02-retention.sql und 03-avatars.sql spielt für dieses Skript keine Rolle.
--
--  Ein Foto ist keine eigene Nachrichtenart in der Datenbank: es steckt,
--  genau wie Text, verschlüsselt in messages.ciphertext. Der Client verpackt
--  vor dem Verschlüsseln entweder {"kind":"text","text":"…"} oder
--  {"kind":"image","dataUrl":"…"} — der Server sieht in beiden Fällen nur
--  Chiffrat und kann die beiden Fälle nicht unterscheiden, nur an der Größe
--  grob erahnen. Das bisherige Limit von 8000 Zeichen war nur für Text
--  bemessen und für ein Bild viel zu knapp.
--
--  Das neue Limit ist großzügiger bemessen als das, was der Client
--  tatsächlich verschickt (siehe MESSAGE_IMAGE_MAX_CHARS in
--  chat-client.tsx) — genau wie schon beim Profilbild ist dieses Limit hier
--  nur das Netz gegen einen Client, der die eigene Begrenzung umgeht, nicht
--  die eigentliche Steuerung der Größe. Die eigentliche Grenze zieht der
--  Client beim Verkleinern, unter anderem damit eine einzelne Nachricht
--  unter dem 1-MB-Limit bleibt, das Supabase Realtime einer einzelnen
--  Zeilenänderung setzt (sonst kommt das Foto zwar in der Datenbank an,
--  aber nicht mehr live bei den anderen Mitgliedern an, sondern erst, wenn
--  sie die Unterhaltung neu öffnen).
-- ============================================================================

alter table public.messages drop constraint if exists messages_ciphertext_check;
alter table public.messages
  add constraint messages_ciphertext_check check (char_length(ciphertext) between 1 and 1000000);
