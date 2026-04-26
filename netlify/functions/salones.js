// netlify/functions/salones.js
// GET  /api/salones        → lista todos los salones
// POST /api/salones        → crea un salón
// PUT  /api/salones/:id    → edita un salón
// DELETE /api/salones/:id  → elimina un salón

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'hotel2024';

function authorized(event) {
  const auth = event.headers['x-admin-token'];
  return auth === ADMIN_PASSWORD;
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-token',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  // GET — público
  if (event.httpMethod === 'GET') {
    const { data, error } = await supabase
      .from('salones')
      .select('*')
      .eq('activo', true)
      .order('nombre');
    if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  // Mutaciones — requieren token
  if (!authorized(event)) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };
  }

  const body = JSON.parse(event.body || '{}');
  const id   = event.queryStringParameters?.id;

  if (event.httpMethod === 'POST') {
    const { data, error } = await supabase.from('salones').insert([body]).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 201, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'PUT' && id) {
    const { data, error } = await supabase.from('salones').update(body).eq('id', id).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'DELETE' && id) {
    const { error } = await supabase.from('salones').delete().eq('id', id);
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
};

