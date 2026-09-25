-- ============================================================================
--  03  Profilbilder
--
--  Im SQL Editor ausfuehren, nach 01-schema.sql und 02-retention.sql.
--
--  Bewusst eine EIGENE Tabelle statt einer neuen Spalte auf profiles: die
--  Policy "profiles_set_key_once" macht die profiles-Zeile nach dem Setzen
--  des Identitaetsschluessels absichtlich unveraenderlich (siehe README,
--  "Wie ein Schluessel zu dir kommt"). Eine zweite, generellere UPDATE-Policy
--  auf profiles wuerde diese Sperre aufweichen, weil Postgres die USING- und
--  WITH-CHECK-Ausdruecke mehrerer permissiver Policies fuer dieselbe Aktion
--  ueber OR verknuepft — nicht paarweise pro Policy. Eine eigene Tabelle mit
--  eigenen, unabhaengigen Policies umgeht dieses Risiko vollstaendig.
--
--  Das Bild selbst liegt als Data-URL (Base64) direkt in der Zeile, nicht in
--  Supabase Storage. Zwei Gruende: kein zusaetzlicher Bucket mit eigenen
--  Storage-Policies noetig, und die Content-Security-Policy in middleware.ts
--  erlaubt img-src ohnehin schon 'data:' — es muss also nichts gelockert
--  werden, um Bilder von einer fremden Domain zu laden.
--
--  Wie Benutzername und Gruppennamen ist das Profilbild NICHT
--  Ende-zu-Ende-verschluesselt: es ist Profil-Metadatum, kein Nachrichten-
--  inhalt, und muss fuer jedes Mitglied sichtbar sein, ohne dass eine
--  Unterhaltung mit ihm bestehen muss. Der Server (und wer an den Server
--  koennte) sieht es also im Klartext.
-- ============================================================================

create table public.avatars (
  user_id     uuid primary key references public.profiles(id) on delete cascade,
  data_url    text not null check (char_length(data_url) <= 400000)
                   check (data_url ~ '^data:image/(jpeg|png|webp);base64,'),
  updated_at  timestamptz not null default now()
);

alter table public.avatars enable row level security;

create policy "avatars_read" on public.avatars
  for select to authenticated using (true);

create policy "avatars_write_own" on public.avatars
  for insert to authenticated
  with check (user_id = (select auth.uid()));

create policy "avatars_update_own" on public.avatars
  for update to authenticated
  using      (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "avatars_delete_own" on public.avatars
  for delete to authenticated using (user_id = (select auth.uid()));

create or replace function public.touch_avatar()
returns trigger language plpgsql security definer
set search_path = public, pg_temp as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger avatars_touch_updated_at
before insert or update on public.avatars
for each row execute function public.touch_avatar();

alter table public.avatars replica identity full;
alter publication supabase_realtime add table public.avatars;
