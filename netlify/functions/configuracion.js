// netlify/functions/configuracion.js
// GET  /api/configuracion         → obtiene toda la configuracion
// POST /api/configuracion         → guarda un valor (requiere auth)

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
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  if (event.httpMethod === 'GET') {
    const { data, error } = await supabase
      .from('configuracion')
      .select('clave, valor');
    if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    // Convert to key-value object
    const config = {};
    data.forEach(row => { config[row.clave] = row.valor; });
    return { statusCode: 200, headers, body: JSON.stringify(config) };
  }

  if (event.httpMethod === 'POST') {
    const _tok = event.headers['x-admin-token'] || event.headers['x-user-token'];
  const _user = _tok ? (() => { try { return JSON.parse(Buffer.from(_tok, 'base64').toString('utf8')); } catch { return null; } })() : null;
  const _auth = _tok === ADMIN_PASSWORD || (_user && (_user.rol === 'admin' || _user.rol === 'operador'));
  if (!_auth) {
      return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };
    }
    const updates = JSON.parse(event.body || '{}');
    const rows = Object.entries(updates).map(([clave, valor]) => ({
      clave, valor: String(valor), updated_at: new Date().toISOString()
    }));
    const { error } = await supabase
      .from('configuracion')
      .upsert(rows, { onConflict: 'clave' });
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
};
