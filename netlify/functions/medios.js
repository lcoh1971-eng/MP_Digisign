// netlify/functions/medios.js
// GET    /api/medios?evento_id=xxx     → lista medios de un evento
// POST   /api/medios                   → agrega un medio (imagen o video_url)
// DELETE /api/medios?id=xxx            → elimina un medio
// PUT    /api/medios?id=xxx            → actualiza orden

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'hotel2024';

const crypto = require('crypto');

function parseUserToken(token) {
  try { return JSON.parse(Buffer.from(token, 'base64').toString('utf8')); }
  catch { return null; }
}

function authorized(event) {
  const token = event.headers['x-admin-token'] || event.headers['x-user-token'];
  if (!token) return false;
  if (token === ADMIN_PASSWORD) return true;
  const user = parseUserToken(token);
  return user && (user.rol === 'admin' || user.rol === 'operador');
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-token',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  const params = event.queryStringParameters || {};

  // GET — público
  if (event.httpMethod === 'GET' && params.evento_id) {
    const { data, error } = await supabase
      .from('evento_medios')
      .select('*')
      .eq('evento_id', params.evento_id)
      .order('orden');
    if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (!authorized(event)) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };
  }

  const body = JSON.parse(event.body || '{}');
  const id = params.id;

  // POST — agregar medio
  if (event.httpMethod === 'POST') {
    // Si es imagen base64, subir a storage primero
    if ((body.tipo === 'imagen' || body.tipo === 'video_archivo') && body.file_base64) {
      const buffer = Buffer.from(body.file_base64, 'base64');
      const filename = `${Date.now()}-${(body.file_name || 'archivo').replace(/[^a-zA-Z0-9._-]/g, '_')}`;
      const contentType = body.file_type || (body.tipo === 'video_archivo' ? 'video/mp4' : 'image/jpeg');
      const { error: upErr } = await supabase.storage
        .from('imagenes-eventos')
        .upload(filename, buffer, { contentType, upsert: false });
      if (upErr) return { statusCode: 400, headers, body: JSON.stringify({ error: upErr.message }) };
      const { data: urlData } = supabase.storage.from('imagenes-eventos').getPublicUrl(filename);
      body.url = urlData.publicUrl;
    }

    const { data, error } = await supabase
      .from('evento_medios')
      .insert([{ evento_id: body.evento_id, tipo: body.tipo, url: body.url, orden: body.orden || 0 }])
      .select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 201, headers, body: JSON.stringify(data) };
  }

  // PUT — actualizar orden y/o duracion
  if (event.httpMethod === 'PUT' && id) {
    const updates = {};
    if (body.orden !== undefined) updates.orden = body.orden;
    if (body.duracion_segundos !== undefined) updates.duracion_segundos = body.duracion_segundos;
    const { data, error } = await supabase
      .from('evento_medios')
      .update(updates)
      .eq('id', id).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  // DELETE
  if (event.httpMethod === 'DELETE' && id) {
    const { error } = await supabase.from('evento_medios').delete().eq('id', id);
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
};
