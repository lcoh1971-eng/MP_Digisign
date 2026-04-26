// netlify/functions/upload.js
// POST /api/upload  → sube imagen a Supabase Storage, devuelve URL pública

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
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.headers['x-admin-token'] !== ADMIN_PASSWORD) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
  }

  try {
    const body = JSON.parse(event.body);
    // body.file = base64 string, body.name = filename, body.type = mime type
    const { file, name, type } = body;
    const buffer = Buffer.from(file, 'base64');
    const filename = `${Date.now()}-${name.replace(/[^a-zA-Z0-9._-]/g, '_')}`;

    const { error } = await supabase.storage
      .from('imagenes-eventos')
      .upload(filename, buffer, { contentType: type, upsert: false });

    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };

    const { data: urlData } = supabase.storage
      .from('imagenes-eventos')
      .getPublicUrl(filename);

    return { statusCode: 200, headers, body: JSON.stringify({ url: urlData.publicUrl }) };
  } catch (err) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message }) };
  }
};

