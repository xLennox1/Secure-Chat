-- ============================================================================
--  03  Aufraeumen: alte Nachrichten, Versuche und verfallene Codes
--
--  Voraussetzung: Extension pg_cron aktivieren unter
--  Database -> Extensions -> pg_cron.
-- ============================================================================

create extension if not exists pg_cron;

-- Einstellungen als Tabelle, damit du die Fristen aendern kannst, ohne
-- die Funktion neu schreiben zu muessen.
create table if not exists public.app_config (
  key   text primary key,
  value text not null
);

alter table public.app_config enable row level security;
revoke all on public.app_config from anon, authenticated;
-- Keine Policy: nur der Secret Key auf dem Server kommt heran.

insert into public.app_config (key, value) values
  ('message_retention_days', '90'),
  ('attempt_retention_days', '7'),
  ('stale_code_retention_days', '30'),
  ('device_code_minutes', '10')
on conflict (key) do nothing;

create or replace function public.config_int(p_key text, p_default int)
returns int
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select coalesce((select value::int from public.app_config where key = p_key), p_default);
$$;

create or replace function public.purge_old_data()
returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  msg_days   int := public.config_int('message_retention_days', 90);
  att_days   int := public.config_int('attempt_retention_days', 7);
  code_days  int := public.config_int('stale_code_retention_days', 30);
  dev_min    int := public.config_int('device_code_minutes', 10);
begin
  delete from public.messages
   where created_at < now() - make_interval(days => msg_days);

  delete from public.conversation_keys ck
   where ck.created_at < now() - make_interval(days => msg_days)
     and not exists (
       select 1 from public.messages m
        where m.conversation_id = ck.conversation_id
          and m.key_epoch = ck.epoch
     );

  delete from public.redeem_attempts
   where created_at < now() - make_interval(days => att_days);

  delete from public.invite_codes
   where kind = 'device'
     and used_at is null
     and created_at < now() - make_interval(mins => dev_min);

  update public.invite_codes
     set payload = null, payload_iv = null, payload_salt = null
   where payload is not null
     and (used_at is not null or created_at < now() - make_interval(mins => dev_min));

  delete from public.invite_codes
   where kind = 'invite'
     and used_at is null
     and expires_at is not null
     and expires_at < now() - make_interval(days => code_days);

  delete from public.conversations c
   where c.last_message_at < now() - make_interval(days => msg_days)
     and not exists (select 1 from public.messages m where m.conversation_id = c.id);
end;
$$;

revoke execute on function public.purge_old_data() from public, anon, authenticated;
revoke execute on function public.config_int(text, int) from public, anon, authenticated;

select cron.unschedule('purge-old-data')
 where exists (select 1 from cron.job where jobname = 'purge-old-data');

select cron.schedule('purge-old-data', '17 3 * * *', $$select public.purge_old_data()$$);

-- Fristen spaeter aendern:
--   update public.app_config set value = '30' where key = 'message_retention_days';
-- Einmal von Hand aufraeumen:
--   select public.purge_old_data();
-- Laeuft der Job?
--   select jobname, schedule, active from cron.job;
--   select * from cron.job_run_details order by start_time desc limit 10;
