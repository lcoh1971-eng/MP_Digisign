// netlify/functions/reportes.js
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
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };
  if (event.headers['x-admin-token'] !== ADMIN_PASSWORD) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };
  }

  const params = event.queryStringParameters || {};
  const { desde, hasta } = params;

  if (!desde || !hasta) {
    return { statusCode: 400, headers, body: JSON.stringify({ error: 'Parámetros desde y hasta requeridos' }) };
  }

  // Fetch all events in range with salon info
  const { data: eventos, error } = await supabase
    .from('eventos')
    .select('*, salones(nombre, slug)')
    .gte('fecha', desde)
    .lte('fecha', hasta)
    .order('fecha')
    .order('hora_inicio');

  if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };

  // Fetch all salones
  const { data: salones } = await supabase.from('salones').select('id, nombre, slug').eq('activo', true).order('nombre');

  // ── METRICS ──

  // 1. Eventos por tipo
  const porTipo = {};
  eventos.forEach(e => { porTipo[e.tipo] = (porTipo[e.tipo] || 0) + 1; });

  // 2. Eventos por salón
  const porSalon = {};
  salones.forEach(s => { porSalon[s.nombre] = 0; });
  eventos.forEach(e => {
    const nombre = e.salones?.nombre || 'Desconocido';
    porSalon[nombre] = (porSalon[nombre] || 0) + 1;
  });

  // 3. Ocupación por hora del día (0-23)
  const porHora = Array(24).fill(0);
  eventos.forEach(e => {
    const hIni = parseInt(e.hora_inicio.slice(0, 2));
    const hFin = parseInt(e.hora_fin.slice(0, 2));
    for (let h = hIni; h <= hFin; h++) { if (h < 24) porHora[h]++; }
  });

  // 4. Ociosidad por salón (días sin eventos / total días en rango)
  const totalDias = Math.round((new Date(hasta) - new Date(desde)) / 86400000) + 1;
  const diasConEvento = {};
  salones.forEach(s => { diasConEvento[s.nombre] = new Set(); });
  eventos.forEach(e => {
    const nombre = e.salones?.nombre;
    if (nombre && diasConEvento[nombre]) diasConEvento[nombre].add(e.fecha);
  });

  const ociosidad = {};
  salones.forEach(s => {
    const activos = diasConEvento[s.nombre]?.size || 0;
    ociosidad[s.nombre] = {
      dias_con_evento: activos,
      dias_sin_evento: totalDias - activos,
      pct_ocupacion: Math.round(activos / totalDias * 100),
      pct_ociosidad: Math.round((totalDias - activos) / totalDias * 100),
    };
  });

  // 5. Eventos por día (timeline)
  const porDia = {};
  eventos.forEach(e => { porDia[e.fecha] = (porDia[e.fecha] || 0) + 1; });

  // 6. Duración promedio de eventos (horas)
  let totalMinutos = 0;
  eventos.forEach(e => {
    const [hI, mI] = e.hora_inicio.split(':').map(Number);
    const [hF, mF] = e.hora_fin.split(':').map(Number);
    totalMinutos += (hF * 60 + mF) - (hI * 60 + mI);
  });
  const duracionPromedio = eventos.length > 0 ? Math.round(totalMinutos / eventos.length) : 0;

  // 7. Top salones más activos
  const topSalones = Object.entries(porSalon)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      resumen: {
        total_eventos: eventos.length,
        total_salones: salones.length,
        dias_analizados: totalDias,
        duracion_promedio_min: duracionPromedio,
        tipo_mas_frecuente: Object.entries(porTipo).sort((a,b)=>b[1]-a[1])[0]?.[0] || '—',
        salon_mas_activo: topSalones[0]?.[0] || '—',
      },
      por_tipo: porTipo,
      por_salon: porSalon,
      por_hora: porHora,
      por_dia: porDia,
      ociosidad,
      top_salones: topSalones,
      eventos_raw: eventos,
    }),
  };
};

