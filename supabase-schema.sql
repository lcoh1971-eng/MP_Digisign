-- ══════════════════════════════════════════
--  Hotel Signage — Supabase Schema
--  Ejecutar en: Supabase → SQL Editor → New Query
-- ══════════════════════════════════════════

-- Tabla: salones
create table if not exists salones (
  id          uuid primary key default gen_random_uuid(),
  nombre      text not null,
  slug        text not null unique,  -- usado en la URL: /salon/imperial
  activo      boolean default true,
  created_at  timestamptz default now()
);

-- Tabla: eventos
create table if not exists eventos (
  id           uuid primary key default gen_random_uuid(),
  salon_id     uuid references salones(id) on delete cascade,
  nombre       text not null,
  tipo         text not null default 'Evento',
  subtitulo    text,
  fecha        date not null,
  hora_inicio  time not null,
  hora_fin     time not null,
  imagen_url   text,
  color_acento text default '#B8962E',
  created_at   timestamptz default now()
);

-- Índice para búsquedas por salón y fecha
create index if not exists idx_eventos_salon_fecha
  on eventos(salon_id, fecha);

-- Habilitar Row Level Security
alter table salones enable row level security;
alter table eventos  enable row level security;

-- Política: lectura pública (las tabletas no necesitan auth)
create policy "Lectura pública de salones"
  on salones for select using (true);

create policy "Lectura pública de eventos"
  on eventos for select using (true);

-- Política: escritura solo con service_role (desde Netlify Functions)
create policy "Escritura autenticada de salones"
  on salones for all using (auth.role() = 'service_role');

create policy "Escritura autenticada de eventos"
  on eventos for all using (auth.role() = 'service_role');

-- ── Datos de ejemplo ──
insert into salones (nombre, slug) values
  ('Salón Imperial',     'imperial'),
  ('Salón Versalles',    'versalles'),
  ('Salón Mediterráneo', 'mediterraneo'),
  ('Sala Ejecutiva A',   'ejecutiva-a'),
  ('Sala Ejecutiva B',   'ejecutiva-b');
