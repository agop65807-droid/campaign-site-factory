begin;

-- Remove dangerous legacy RPC entry points.
drop function if exists public.exec_sql(text);
drop function if exists public.exec_sql(text, jsonb);

-- Remove every legacy public-schema policy. This application reaches Postgres
-- only through server-side service-role clients, so anon/authenticated do not
-- require direct table access.
do $$
declare
  policy_record record;
begin
  for policy_record in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
  loop
    execute format(
      'drop policy if exists %I on %I.%I',
      policy_record.policyname,
      policy_record.schemaname,
      policy_record.tablename
    );
  end loop;
end
$$;

-- Enable and force RLS as defense in depth on every exposed public table.
do $$
declare
  table_record record;
begin
  for table_record in
    select schemaname, tablename
    from pg_tables
    where schemaname = 'public'
  loop
    execute format(
      'alter table %I.%I enable row level security',
      table_record.schemaname,
      table_record.tablename
    );
    execute format(
      'alter table %I.%I force row level security',
      table_record.schemaname,
      table_record.tablename
    );
  end loop;
end
$$;

-- Lock the exposed schema to the trusted backend role.
revoke usage on schema public from public, anon, authenticated;
revoke all privileges on all tables in schema public from public, anon, authenticated;
revoke all privileges on all sequences in schema public from public, anon, authenticated;
revoke execute on all functions in schema public from public, anon, authenticated;

grant usage on schema public to service_role;
grant all privileges on all tables in schema public to service_role;
grant all privileges on all sequences in schema public to service_role;

-- New objects remain private unless a future migration explicitly grants them.
alter default privileges for role postgres in schema public
  revoke all privileges on tables from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke all privileges on sequences from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;

-- Only backend RPCs present in the current database are executable.
do $$
begin
  if to_regprocedure('public.factory_check_rate_limit(text,integer,integer)') is not null then
    grant execute on function public.factory_check_rate_limit(text, integer, integer) to service_role;
  end if;
  if to_regprocedure('public.tenant_check_rate_limit(text,integer,integer)') is not null then
    grant execute on function public.tenant_check_rate_limit(text, integer, integer) to service_role;
  end if;
  if to_regprocedure('public.create_main_admin(text,text,boolean)') is not null then
    grant execute on function public.create_main_admin(text, text, boolean) to service_role;
  end if;
  if to_regprocedure('public.upsert_site_settings(jsonb)') is not null then
    grant execute on function public.upsert_site_settings(jsonb) to service_role;
  end if;
end
$$;

-- Pin search_path for application-owned functions, excluding extension members.
do $$
declare
  function_record record;
begin
  for function_record in
    select p.oid::regprocedure as identity
    from pg_proc p
    join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and not exists (
        select 1
        from pg_depend d
        join pg_extension e on e.oid = d.refobjid
        where d.classid = 'pg_proc'::regclass
          and d.objid = p.oid
          and d.deptype = 'e'
      )
  loop
    execute format(
      'alter function %s set search_path = pg_catalog, public',
      function_record.identity
    );
  end loop;
end
$$;

-- Public buckets do not need broad SELECT policies for public object URLs.
drop policy if exists "Anyone can view logos" on storage.objects;
drop policy if exists "Authenticated manage logos" on storage.objects;

commit;
