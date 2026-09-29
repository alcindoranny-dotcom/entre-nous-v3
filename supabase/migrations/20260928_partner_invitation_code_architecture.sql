-- ENTRE NOUS: partner-level private invitations
create table if not exists public.partner_links (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  partner_user_id uuid null references auth.users(id) on delete set null,
  partner_name text not null,
  code text not null unique,
  code_hash text not null,
  status text not null default 'pending' check (status in ('pending','active','revoked')),
  invited_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '7 days'),
  claimed_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.games add column if not exists partner_id uuid;
do $$ begin
  if not exists (select 1 from pg_constraint where conname='games_partner_id_fkey') then
    alter table public.games add constraint games_partner_id_fkey foreign key (partner_id) references public.partner_links(id) on delete set null;
  end if;
end $$;

alter table public.invitations add column if not exists partner_id uuid;
do $$ begin
  if not exists (select 1 from pg_constraint where conname='invitations_partner_id_fkey') then
    alter table public.invitations add constraint invitations_partner_id_fkey foreign key (partner_id) references public.partner_links(id) on delete set null;
  end if;
end $$;

do $$ begin
  if exists (select 1 from pg_constraint where conname='invitations_code_key') then
    alter table public.invitations drop constraint invitations_code_key;
  end if;
end $$;
create unique index if not exists invitations_partner_code_uidx on public.invitations(partner_id,code);
create index if not exists idx_partner_links_owner on public.partner_links(owner_id);
create index if not exists idx_partner_links_partner_user on public.partner_links(partner_user_id);
create index if not exists idx_games_partner on public.games(partner_id);
create index if not exists idx_invitations_partner on public.invitations(partner_id);

alter table public.partner_links enable row level security;
revoke all on public.partner_links from anon, authenticated;

create or replace function public.create_partner_invitation(p_game_id uuid,p_invitee_name text,p_token_hash text,p_expires_at timestamptz default (now()+interval '7 days'))
returns table(partner_id uuid,partner_name text,partner_code text,invitation_id uuid,expires_at timestamptz)
language plpgsql security definer set search_path='' as $$
declare v_partner_id uuid; v_code text; v_game_owner uuid; v_invitation_id uuid;
begin
 if auth.uid() is null then raise exception 'not_authenticated'; end if;
 select owner_id into v_game_owner from public.games where id=p_game_id;
 if v_game_owner is null or v_game_owner<>auth.uid() then raise exception 'not_authorized'; end if;
 if coalesce(trim(p_invitee_name),'')='' then raise exception 'missing_invitee'; end if;
 v_code:=lpad((floor(random()*1000000))::bigint::text,6,'0');
 while exists(select 1 from public.partner_links where code=v_code) loop v_code:=lpad((floor(random()*1000000))::bigint::text,6,'0'); end loop;
 insert into public.partner_links(owner_id,partner_name,code,code_hash,status,expires_at)
 values(auth.uid(),trim(p_invitee_name),v_code,encode(extensions.digest(v_code,'sha256'),'hex'),'pending',p_expires_at)
 returning id into v_partner_id;
 update public.games set partner_id=v_partner_id,updated_at=now() where id=p_game_id;
 insert into public.invitations(game_id,partner_id,invitee_name,code,status,created_at,token_hash,expires_at)
 values(p_game_id,v_partner_id,trim(p_invitee_name),v_code,'pending',now(),p_token_hash,p_expires_at)
 returning id into v_invitation_id;
 return query select v_partner_id,trim(p_invitee_name),v_code,v_invitation_id,p_expires_at;
end $$;

create or replace function public.resend_partner_invitation(p_partner_id uuid,p_token_hash text,p_expires_at timestamptz default (now()+interval '7 days'))
returns table(partner_id uuid,partner_name text,partner_code text,invitation_id uuid,expires_at timestamptz)
language plpgsql security definer set search_path='' as $$
declare p public.partner_links%rowtype; i public.invitations%rowtype;
begin
 if auth.uid() is null then raise exception 'not_authenticated'; end if;
 select * into p from public.partner_links where id=p_partner_id and owner_id=auth.uid();
 if not found then raise exception 'partner_not_found'; end if;
 if p.status='revoked' then raise exception 'partner_revoked'; end if;
 select * into i from public.invitations where partner_id=p.id order by created_at desc limit 1;
 if i.id is null then raise exception 'partner_has_no_invitation'; end if;
 update public.invitations set token_hash=p_token_hash,expires_at=p_expires_at,status='pending',used_at=null,claimed_by=null,created_at=now() where id=i.id returning * into i;
 update public.partner_links set expires_at=p_expires_at,updated_at=now() where id=p.id;
 return query select p.id,p.partner_name,p.code,i.id,p_expires_at;
end $$;

create or replace function public.get_partner_invitation(p_token_hash text)
returns table(invitation_id uuid,partner_id uuid,game_id uuid,invitee_name text,experience text,inviter_name text,partner_code text,expires_at timestamptz,status text)
language sql security definer set search_path='' as $$
 select i.id,i.partner_id,i.game_id,i.invitee_name,g.experience,coalesce(pr.name,'ENTRE NOUS'),pl.code,i.expires_at,i.status
 from public.invitations i join public.partner_links pl on pl.id=i.partner_id join public.games g on g.id=i.game_id
 left join public.profiles pr on pr.id=g.owner_id
 where i.token_hash=p_token_hash and i.expires_at>now() and i.status='pending' and pl.status in ('pending','active') limit 1
$$;

create or replace function public.claim_partner_invitation(p_token_hash text,p_partner_code text)
returns table(partner_id uuid,game_id uuid,experience text,invitee_name text,inviter_name text,partner_code text)
language plpgsql security definer set search_path='' as $$
declare i public.invitations%rowtype; p public.partner_links%rowtype; g public.games%rowtype; inviter text;
begin
 if auth.uid() is null then raise exception 'not_authenticated'; end if;
 select * into i from public.invitations where token_hash=p_token_hash and expires_at>now() and status='pending' limit 1;
 if not found then raise exception 'invalid_or_expired_invitation'; end if;
 select * into p from public.partner_links where id=i.partner_id;
 if not found then raise exception 'partner_not_found'; end if;
 if upper(trim(coalesce(p_partner_code,'')))<>upper(p.code) then raise exception 'invalid_partner_code'; end if;
 if p.status='revoked' then raise exception 'partner_revoked'; end if;
 select * into g from public.games where id=i.game_id;
 select coalesce(pr.name,'ENTRE NOUS') into inviter from public.profiles pr where pr.id=g.owner_id;
 update public.partner_links set partner_user_id=auth.uid(),status='active',claimed_at=coalesce(claimed_at,now()),updated_at=now() where id=p.id;
 update public.invitations set used_at=now(),claimed_by=auth.uid(),status='accepted' where id=i.id;
 update public.games set partner_id=p.id,updated_at=now() where id=g.id;
 insert into public.participants(game_id,user_id,name,role)
 select g.id,auth.uid(),i.invitee_name,'guest' where not exists(select 1 from public.participants pp where pp.game_id=g.id and pp.user_id=auth.uid());
 return query select p.id,g.id,g.experience,i.invitee_name,inviter,p.code;
end $$;

create or replace function public.list_partner_links()
returns table(partner_id uuid,partner_name text,partner_code text,status text,invited_at timestamptz,expires_at timestamptz,claimed_at timestamptz)
language sql security definer set search_path='' as $$
 select id,partner_name,code,status,invited_at,expires_at,claimed_at from public.partner_links where owner_id=auth.uid() order by updated_at desc
$$;

grant execute on function public.create_partner_invitation(uuid,text,text,timestamptz) to authenticated;
grant execute on function public.resend_partner_invitation(uuid,text,timestamptz) to authenticated;
grant execute on function public.get_partner_invitation(text) to anon,authenticated;
grant execute on function public.claim_partner_invitation(text,text) to authenticated;
grant execute on function public.list_partner_links() to authenticated;
