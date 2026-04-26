// netlify/functions/auth.js
// POST /api/auth  → verifica contraseña, devuelve token (la misma contraseña como token simple)

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'hotel2024';

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
  }

  const { password } = JSON.parse(event.body || '{}');

  if (password === ADMIN_PASSWORD) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ ok: true, token: ADMIN_PASSWORD }),
    };
  }

  return { statusCode: 401, headers, body: JSON.stringify({ error: 'Contraseña incorrecta' }) };
};

