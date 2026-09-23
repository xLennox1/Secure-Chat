-- ============================================================================
--  Invite-Chat — vollstaendiges Schema, Ende-zu-Ende verschluesselt
--  Im SQL Editor komplett ausfuehren, danach 02-retention.sql.
--
--  Kommt von der unverschluesselten Fassung? Erst abraeumen. Es gibt keine
--  Migration, die Klartext nachtraeglich in Ciphertext verwandeln koennte:
--
--    drop table if exists public.messages, public.conversation_members,
--      public.conversations, public.invite_codes, public.redeem_attempts,
--      public.profiles cascade;
--    drop type if exists public.conversation_type;
--
--  Und in Authentication -> Users die alten Konten loeschen.
-- ============================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- Tabellen --

-- identity_public_key ist der oeffentliche Teil eines ECDH-P-256-Paares.
-- Der private Teil liegt nur im Browser, mit dem Sperrcode verschluesselt.
create table public.profiles (
  id                   uuid primary key references auth.users(id) on delete cascade,
  username             text not null unique
                       check (username ~ '^[A-Za-z0-9_.-]{3,24}$'),
  identity_public_key  jsonb,
  key_fingerprint      text,
  created_at           timestamptz not null default now()
);

-- "Anna" und "anna" duerfen nicht nebeneinander existieren.
create unique index profiles_username_ci_idx on public.profiles (lower(username));

-- kind = 'invite'  16 Zeichen, neues Konto. Der ganze Code geht an den Server.
-- kind = 'device'  20 Zeichen, weiteres Geraet. Nur die ersten 10 Zeichen gehen
--                  an den Server; mit den letzten 10 hat der Browser den
--                  eigenen Identitaetsschluessel verschluesselt und als payload
--                  hinterlegt. Der Server transportiert ihn, kann ihn aber
--                  nicht oeffnen.
create table public.invite_codes (
  id            uuid primary key default gen_random_uuid(),
  kind          text not null default 'invite' check (kind in ('invite', 'device')),
  code_hash     text not null unique,
  for_user      uuid references public.profiles(id) on delete cascade,
  label         text,
  payload       text,
  payload_iv    text,
  payload_salt  text,
  created_at    timestamptz not null default now(),
  expires_at    timestamptz,
  used_at       timestamptz,
  used_by       uuid references auth.users(id) on delete set null,
  constraint device_needs_user check (kind <> 'device' or for_user is not null)
);
create index invite_codes_unused_idx on public.invite_codes (used_at) where used_at is null;

create table public.redeem_attempts (
  id          bigserial primary key,
  ip_hash     text not null,
  success     boolean not null default false,
  created_at  timestamptz not null default now()
);
create index redeem_attempts_lookup_idx on public.redeem_attempts (ip_hash, created_at desc);

create type public.conversation_type as enum ('dm', 'group');

-- key_epoch steigt, sobald jemand neu dazukommt. Fuer die neue Epoche wird ein
-- neuer Gruppenschluessel verteilt, und zwar nur an die dann Anwesenden. Alte
-- Nachrichten bleiben fuer Hinzugekommene unlesbar.
create table public.conversations (
  id               uuid primary key default gen_random_uuid(),
  type             public.conversation_type not null,
  title            text check (title is null or char_length(title) between 1 and 60),
  dm_key           text unique,
  key_epoch        int not null default 0,
  created_by       uuid references public.profiles(id) on delete set null,
  created_at       timestamptz not null default now(),
  last_message_at  timestamptz not null default now()
);

create table public.conversation_members (
  conversation_id  uuid not null references public.conversations(id) on delete cascade,
  user_id          uuid not null references public.profiles(id) on delete cascade,
  role             text not null default 'member' check (role in ('owner', 'member')),
  joined_at        timestamptz not null default now(),
  primary key (conversation_id, user_id)
);
create index conversation_members_user_idx on public.conversation_members (user_id);

-- Der Gruppenschluessel, einzeln fuer jedes Mitglied verpackt.
-- sender_public_key ist der oeffentliche Schluessel dessen, der verpackt hat.
-- Der Empfaenger prueft, ob er zum Profil von created_by passt.
create table public.conversation_keys (
  conversation_id    uuid not null references public.conversations(id) on delete cascade,
  user_id            uuid not null references public.profiles(id) on delete cascade,
  epoch              int not null,
  wrapped_key        text not null,
  sender_public_key  jsonb not null,
  iv                 text not null,
  created_by         uuid references public.profiles(id) on delete set null,
  created_at         timestamptz not null default now(),
  primary key (conversation_id, user_id, epoch)
);

-- Es gibt keine Klartextspalte. Was hier landet, ist bereits AES-256-GCM.
create table public.messages (
  id               uuid primary key default gen_random_uuid(),
  conversation_id  uuid not null references public.conversations(id) on delete cascade,
  sender_id        uuid references public.profiles(id) on delete set null,
  ciphertext       text not null check (char_length(ciphertext) between 1 and 8000),
  iv               text not null,
  key_epoch        int not null default 0,
  created_at       timestamptz not null default now()
);
create index messages_thread_idx on public.messages (conversation_id, created_at desc);

-- ------------------------------------------------- Hilfsfunktionen fuer RLS --

create or replace function public.is_member(conv uuid)
returns boolean language sql security definer stable
set search_path = public, pg_temp as $$
  select exists (
    select 1 from public.conversation_members
    where conversation_id = conv and user_id = (select auth.uid())
  );
$$;

create or replace function public.is_owner(conv uuid)
returns boolean language sql security definer stable
set search_path = public, pg_temp as $$
  select exists (
    select 1 from public.conversation_members
    where conversation_id = conv and user_id = (select auth.uid()) and role = 'owner'
  );
$$;

revoke execute on function public.is_member(uuid) from public, anon;
revoke execute on function public.is_owner(uuid)  from public, anon;
grant  execute on function public.is_member(uuid) to authenticated;
grant  execute on function public.is_owner(uuid)  to authenticated;

-- ------------------------------------------------------------------ Trigger --

create or replace function public.touch_conversation()
returns trigger language plpgsql security definer
set search_path = public, pg_temp as $$
begin
  update public.conversations
     set last_message_at = new.created_at
   where id = new.conversation_id;
  return new;
end;
$$;

create trigger messages_touch_conversation
after insert on public.messages
for each row execute function public.touch_conversation();

-- ---------------------------------------------------------------------- RLS --

alter table public.profiles             enable row level security;
alter table public.invite_codes         enable row level security;
alter table public.redeem_attempts      enable row level security;
alter table public.conversations        enable row level security;
alter table public.conversation_members enable row level security;
alter table public.conversation_keys    enable row level security;
alter table public.messages             enable row level security;

revoke all on public.invite_codes    from anon, authenticated;
revoke all on public.redeem_attempts from anon, authenticated;

create policy "profiles_read" on public.profiles
  for select to authenticated using (true);

create policy "profiles_set_key_once" on public.profiles
  for update to authenticated
  using      (id = (select auth.uid()) and identity_public_key is null)
  with check (id = (select auth.uid()) and identity_public_key is not null);

create policy "conversations_read" on public.conversations
  for select to authenticated using (public.is_member(id));

create policy "conversations_rename_by_owner" on public.conversations
  for update to authenticated
  using (type = 'group' and public.is_owner(id))
  with check (type = 'group' and public.is_owner(id));

create policy "members_read" on public.conversation_members
  for select to authenticated using (public.is_member(conversation_id));

create policy "members_leave" on public.conversation_members
  for delete to authenticated using (user_id = (select auth.uid()));

create policy "conv_keys_read" on public.conversation_keys
  for select to authenticated using (public.is_member(conversation_id));

create policy "conv_keys_write" on public.conversation_keys
  for insert to authenticated
  with check (public.is_member(conversation_id) and created_by = (select auth.uid()));

create policy "messages_read" on public.messages
  for select to authenticated using (public.is_member(conversation_id));

create policy "messages_write" on public.messages
  for insert to authenticated
  with check (
    sender_id = (select auth.uid())
    and public.is_member(conversation_id)
    and ciphertext is not null
    and iv is not null
  );

create policy "messages_delete_own" on public.messages
  for delete to authenticated using (sender_id = (select auth.uid()));

-- ---------------------------------------------------------------------- RPC --

create or replace function public.start_dm(other_user uuid)
returns uuid language plpgsql security definer
set search_path = public, pg_temp as $$
declare
  me uuid := (select auth.uid());
  key text;
  conv uuid;
begin
  if me is null then raise exception 'Nicht angemeldet' using errcode = '42501'; end if;
  if other_user is null or other_user = me then raise exception 'Ungueltige Person'; end if;
  if not exists (select 1 from public.profiles where id = other_user) then raise exception 'Unbekannte Person'; end if;
  key := case when me < other_user then me::text || ':' || other_user::text else other_user::text || ':' || me::text end;
  select id into conv from public.conversations where dm_key = key;
  if conv is not null then return conv; end if;
  begin
    insert into public.conversations (type, dm_key, created_by) values ('dm', key, me) returning id into conv;
  exception when unique_violation then
    select id into conv from public.conversations where dm_key = key;
    return conv;
  end;
  insert into public.conversation_members (conversation_id, user_id, role)
  values (conv, me, 'owner'), (conv, other_user, 'member');
  return conv;
end;
$$;

create or replace function public.create_group(p_title text, p_members uuid[])
returns uuid language plpgsql security definer
set search_path = public, pg_temp as $$
declare
  me uuid := (select auth.uid());
  conv uuid;
  t text := nullif(btrim(coalesce(p_title, '')), '');
begin
  if me is null then raise exception 'Nicht angemeldet' using errcode = '42501'; end if;
  if t is null or char_length(t) > 60 then raise exception 'Gruppenname braucht 1 bis 60 Zeichen'; end if;
  if coalesce(array_length(p_members, 1), 0) > 49 then raise exception 'Hoechstens 49 weitere Mitglieder'; end if;
  insert into public.conversations (type, title, created_by) values ('group', t, me) returning id into conv;
  insert into public.conversation_members (conversation_id, user_id, role) values (conv, me, 'owner');
  insert into public.conversation_members (conversation_id, user_id, role)
  select conv, p.id, 'member' from public.profiles p where p.id = any(p_members) and p.id <> me on conflict do nothing;
  return conv;
end;
$$;

create or replace function public.invite_to_group(p_conversation uuid, p_user uuid)
returns void language plpgsql security definer
set search_path = public, pg_temp as $$
begin
  if not public.is_owner(p_conversation) then raise exception 'Nur die Gruppenleitung darf einladen' using errcode = '42501'; end if;
  if not exists (select 1 from public.conversations where id = p_conversation and type = 'group') then raise exception 'Das ist keine Gruppe'; end if;
  if not exists (select 1 from public.profiles where id = p_user) then raise exception 'Unbekannte Person'; end if;
  insert into public.conversation_members (conversation_id, user_id) values (p_conversation, p_user) on conflict do nothing;
end;
$$;

create or replace function public.rotate_conversation_key(p_conversation uuid)
returns int language plpgsql security definer
set search_path = public, pg_temp as $$
declare e int;
begin
  if not public.is_member(p_conversation) then raise exception 'Kein Mitglied dieser Unterhaltung' using errcode = '42501'; end if;
  update public.conversations set key_epoch = key_epoch + 1 where id = p_conversation returning key_epoch into e;
  return e;
end;
$$;

revoke execute on function public.start_dm(uuid) from public, anon;
revoke execute on function public.create_group(text, uuid[]) from public, anon;
revoke execute on function public.invite_to_group(uuid, uuid) from public, anon;
revoke execute on function public.rotate_conversation_key(uuid) from public, anon;
grant execute on function public.start_dm(uuid) to authenticated;
grant execute on function public.create_group(text, uuid[]) to authenticated;
grant execute on function public.invite_to_group(uuid, uuid) to authenticated;
grant execute on function public.rotate_conversation_key(uuid) to authenticated;

alter table public.messages replica identity full;
alter table public.conversation_keys replica identity full;
alter publication supabase_realtime add table public.messages;
alter publication supabase_realtime add table public.conversation_members;
alter publication supabase_realtime add table public.conversation_keys;
