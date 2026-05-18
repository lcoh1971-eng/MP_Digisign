// netlify/functions/upselling.js
// GET  /api/upselling?salon_slug=xxx  → campaña activa para una tableta
// GET  /api/upselling                 → todas las campañas (admin)
// GET  /api/upselling?id=xxx          → una campaña con sus medios
// POST /api/upselling                 → crear campaña
// PUT  /api/upselling?id=xxx          → actualizar campaña
// DELETE /api/upselling?id=xxx        → eliminar campaña

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'hotel2024';

function authorized(event) {
  const _tok = event.headers['x-admin-token'] || event.headers['x-user-token'];
  const _user = _tok ? (() => { try {
    const p=_tok.replace(/-/g,'+').replace(/_/g,'/');
    const n=p+'='.repeat((4-p.length%4)%4);
    return JSON.parse(Buffer.from(n,'base64').toString('utf8'));
  } catch { return null; } })() : null;
  return _tok === ADMIN_PASSWORD || (_user && (_user.rol === 'admin' || _user.rol === 'operador'));
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

  if (event.httpMethod === 'GET' && params.salon_slug) {
    const { data: salon } = await supabase
      .from('salones').select('id').eq('slug', params.salon_slug).single();
    if (!salon) return { statusCode: 200, headers, body: JSON.stringify(null) };

    const { data: allCamps } = await supabase
      .from('upselling')
      .select('*, upselling_medios(*)')
      .eq('activo', true)
      .eq('aplica_todos', true)
      .order('created_at', { ascending: false })
      .limit(1);

    const { data: specificCamps } = await supabase
      .from('upselling_salones')
      .select('upselling_id')
      .eq('salon_id', salon.id);

    let campaign = null;

    if (specificCamps && specificCamps.length > 0) {
      const ids = specificCamps.map(s => s.upselling_id);
      const { data: sc } = await supabase
        .from('upselling')
        .select('*, upselling_medios(*)')
        .eq('activo', true)
        .eq('aplica_todos', false)
        .in('id', ids)
        .order('created_at', { ascending: false })
        .limit(1);
      if (sc && sc.length > 0) campaign = sc[0];
    }

    if (!campaign && allCamps && allCamps.length > 0) campaign = allCamps[0];

    if (campaign) {
      campaign.upselling_medios?.sort((a, b) => a.orden - b.orden);
    }

    return { statusCode: 200, headers, body: JSON.stringify(campaign) };
  }

  if (event.httpMethod === 'GET' && params.id) {
    const { data, error } = await supabase
      .from('upselling')
      .select('*, upselling_medios(*), upselling_salones(salon_id)')
      .eq('id', params.id)
      .single();
    if (error) return { statusCode: 404, headers, body: JSON.stringify({ error: error.message }) };
    data.upselling_medios?.sort((a, b) => a.orden - b.orden);
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'GET') {
    const { data, error } = await supabase
      .from('upselling')
      .select('*, upselling_medios(id), upselling_salones(salon_id)')
      .order('created_at', { ascending: false });
    if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (!authorized(event)) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };
  }

  const body = JSON.parse(event.body || '{}');
  const id = params.id;

  if (event.httpMethod === 'POST') {
    const { salon_ids, ...campData } = body;
    const { data, error } = await supabase
      .from('upselling').insert([campData]).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };

    if (!campData.aplica_todos && salon_ids && salon_ids.length > 0) {
      await supabase.from('upselling_salones').insert(
        salon_ids.map(sid => ({ upselling_id: data.id, salon_id: sid }))
      );
    }
    return { statusCode: 201, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'PUT' && id) {
    const { salon_ids, ...campData } = body;
    const { data, error } = await supabase
      .from('upselling').update(campData).eq('id', id).select().single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };

    if (salon_ids !== undefined) {
      await supabase.from('upselling_salones').delete().eq('upselling_id', id);
      if (!campData.aplica_todos && salon_ids.length > 0) {
        await supabase.from('upselling_salones').insert(
          salon_ids.map(sid => ({ upselling_id: id, salon_id: sid }))
        );
      }
    }
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  if (event.httpMethod === 'DELETE' && id) {
    const { error } = await supabase.from('upselling').delete().eq('id', id);
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
};
