// netlify/functions/upselling-medios.js
// POST   /api/upselling-medios         → agregar medio a campaña
// PUT    /api/upselling-medios?id=xxx  → actualizar orden/duración
// DELETE /api/upselling-medios?id=xxx  → eliminar medio

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'hotel2024';

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-token',
    'Access-Control-Allow-Methods': 'POST, PUT, DELETE, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  const _tok = event.headers['x-admin-token'] || event.headers['x-user-token'];
  const _user = _tok ? (() => { try {
    const p=_tok.replace(/-/g,'+').replace(/_/g,'/');
    const n=p+'='.repeat((4-p.length%4)%4);
    return JSON.parse(Buffer.from(n,'base64').toString('utf8'));
  } catch { return null; } })() : null;
  const _auth = _tok === ADMIN_PASSWORD || (_user && (_user.rol === 'admin' || _user.rol === 'operador'));
  if (!_auth) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };
  }

  const params = event.queryStringParameters || {};
  const body = JSON.parse(event.body || '{}');
  const id = params.id;

  if (event.httpMethod === 'POST') {
    // Upload image if base64
    if ((body.tipo === 'imagen' || body.tipo === 'video_archivo') && body.file_base64) {
      const buffer = Buffer.from(body.file_base64, 'base64');
      const filename = `upselling-${Date.now()}-${(body.file_name || 'media').replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      const contentType = body.file_type || (body.tipo === 'video_archivo' ? 'video/mp4' : 'image/jpeg');
      const { error: upErr } = await supabase.storage
        .from('imagenes-eventos')
        .upload(filename, buffer, { contentType, upsert: false });
      if (upErr) return { statusCode: 400, headers, body: JSON.stringify({ error: upErr.message }) };
      const { data: urlData } = supabase.storage.from('imagenes-eventos').getPublicUrl(filename);
      body.url = urlData.publicUrl;
    }

    const { data, error } = await supabase
      .from('upselling_medios')
      .insert([{ upselling_id: body.upselling_id, tipo: body.tipo, url: body.url, duracion_segundos: body.duracion_segundos || 10, orden: body.orden || 0, titulo: body.titulo||'', subtitulo: body.subtitulo||'' }])
      .select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 201, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'PUT' && id) {
    const updates = {};
    if (body.orden !== undefined) updates.orden = body.orden;
    if (body.duracion_segundos !== undefined) updates.duracion_segundos = body.duracion_segundos;
    if (body.titulo !== undefined) updates.titulo = body.titulo;
    if (body.subtitulo !== undefined) updates.subtitulo = body.subtitulo;
    const { data, error } = await supabase
      .from('upselling_medios').update(updates).eq('id', id).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'DELETE' && id) {
    const { error } = await supabase.from('upselling_medios').delete().eq('id', id);
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
};
