// netlify/functions/eventos.js
const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'hotel2024';

function authorized(event) {
  return event.headers['x-admin-token'] === ADMIN_PASSWORD;
}

function nowPanama() {
  const utc = new Date();
  utc.setHours(utc.getHours() - 5);
  return utc;
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

  // GET: evento activo para tableta
  if (event.httpMethod === 'GET' && params.salon_slug) {
    const now = nowPanama();
    const fecha = now.toISOString().slice(0, 10);
    const hora = now.toTimeString().slice(0, 5);

    const { data: salon, error: sErr } = await supabase
      .from('salones').select('id, nombre').eq('slug', params.salon_slug).single();
    if (sErr || !salon) return { statusCode: 404, headers, body: JSON.stringify({ error: 'Salón no encontrado' }) };

    const { data: eventos, error: eErr } = await supabase
      .from('eventos').select('*')
      .eq('salon_id', salon.id).eq('fecha', fecha)
      .lte('hora_inicio', hora).gte('hora_fin', hora)
      .order('hora_inicio').limit(1);
    if (eErr) return { statusCode: 500, headers, body: JSON.stringify({ error: eErr.message }) };

    let evento = eventos?.[0] || null;
    if (evento) {
      const { data: medios } = await supabase
        .from('evento_medios').select('*').eq('evento_id', evento.id).order('orden');
      evento.medios = medios || [];
    }

    return { statusCode: 200, headers, body: JSON.stringify({ salon: salon.nombre, evento, hora_actual: hora, fecha_actual: fecha }) };
  }

  // GET: todos los eventos de un salón en una fecha
  if (event.httpMethod === 'GET' && params.salon_id) {
    const fecha = params.fecha || nowPanama().toISOString().slice(0, 10);
    const { data, error } = await supabase
      .from('eventos').select('*').eq('salon_id', params.salon_id).eq('fecha', fecha).order('hora_inicio');
    if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  // GET: todos los eventos de una fecha (agenda)
  if (event.httpMethod === 'GET' && params.fecha) {
    const { data, error } = await supabase
      .from('eventos').select('*, salones(nombre,slug)').eq('fecha', params.fecha).order('hora_inicio');
    if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  // GET: un evento específico con sus medios
  if (event.httpMethod === 'GET' && params.id) {
    const { data, error } = await supabase.from('eventos').select('*').eq('id', params.id).single();
    if (error) return { statusCode: 404, headers, body: JSON.stringify({ error: error.message }) };
    const { data: medios } = await supabase.from('evento_medios').select('*').eq('evento_id', params.id).order('orden');
    data.medios = medios || [];
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (!authorized(event)) return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };

  const body = JSON.parse(event.body || '{}');
  const id = params.id;

  if (event.httpMethod === 'POST') {
    const { data, error } = await supabase.from('eventos').insert([body]).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 201, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'PUT' && id) {
    const { data, error } = await supabase.from('eventos').update(body).eq('id', id).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'DELETE' && id) {
    const { error } = await supabase.from('eventos').delete().eq('id', id);
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
};
