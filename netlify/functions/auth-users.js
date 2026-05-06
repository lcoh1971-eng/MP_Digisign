// netlify/functions/auth-users.js
// POST /auth-users { email, password } → { ok, token, user }
// GET  /auth-users?action=list        → lista usuarios (admin only)
// POST /auth-users?action=create      → crear usuario (admin only)
// PUT  /auth-users?id=xxx             → actualizar usuario (admin only)
// DELETE /auth-users?id=xxx           → eliminar usuario (admin only)

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'hotel2024';

// Simple password hashing with SHA-256 + salt (no bcrypt dependency needed)
function hashPassword(password) {
  const salt = 'digisign_gva_2026';
  return crypto.createHmac('sha256', salt).update(password).digest('hex');
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

// Simple token: base64 of user id + role + timestamp
function makeToken(user) {
  const payload = JSON.stringify({ id: user.id, rol: user.rol, email: user.email, ts: Date.now() });
  return Buffer.from(payload).toString('base64');
}

function parseToken(token) {
  try {
    return JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
  } catch { return null; }
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-token, x-user-token',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Content-Type': 'application/json',
  };

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers, body: '' };

  const params = event.queryStringParameters || {};
  const body = event.body ? JSON.parse(event.body) : {};

  // ── LOGIN ──
  if (event.httpMethod === 'POST' && !params.action && !params.id) {
    const { email, password } = body;
    if (!email || !password) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Email y contraseña requeridos' }) };

    const { data: user, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email.toLowerCase().trim())
      .eq('activo', true)
      .single();

    if (error || !user) return { statusCode: 401, headers, body: JSON.stringify({ error: 'Usuario no encontrado o inactivo' }) };
    if (!verifyPassword(password, user.password_hash)) return { statusCode: 401, headers, body: JSON.stringify({ error: 'Contraseña incorrecta' }) };

    const token = makeToken(user);
    return { statusCode: 200, headers, body: JSON.stringify({
      ok: true, token,
      user: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol }
    })};
  }

  // ── ADMIN ACTIONS — require x-admin-token or admin user token ──
  const adminToken = event.headers['x-admin-token'];
  const userToken = event.headers['x-user-token'];

  let isAdmin = adminToken === ADMIN_PASSWORD;
  let currentUser = null;

  // Also accept user token from logged-in admin users
  const tokenToCheck = userToken || adminToken;
  if (!isAdmin && tokenToCheck) {
    currentUser = parseToken(tokenToCheck);
    if (currentUser && currentUser.rol === 'admin') isAdmin = true;
  }

  if (!isAdmin) return { statusCode: 401, headers, body: JSON.stringify({ error: 'No autorizado' }) };

  // GET list
  if (event.httpMethod === 'GET' && params.action === 'list') {
    const { data, error } = await supabase
      .from('usuarios')
      .select('id, nombre, email, rol, activo, created_at')
      .order('created_at', { ascending: false });
    if (error) return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  // POST create
  if (event.httpMethod === 'POST' && params.action === 'create') {
    const { nombre, email, password, rol } = body;
    if (!nombre || !email || !password || !rol) return { statusCode: 400, headers, body: JSON.stringify({ error: 'Todos los campos son requeridos' }) };
    const { data, error } = await supabase
      .from('usuarios')
      .insert([{ nombre, email: email.toLowerCase().trim(), password_hash: hashPassword(password), rol, activo: true }])
      .select('id, nombre, email, rol, activo').single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 201, headers, body: JSON.stringify(data) };
  }

  // PUT update
  if (event.httpMethod === 'PUT' && params.id) {
    const updates = {};
    if (body.nombre) updates.nombre = body.nombre;
    if (body.email) updates.email = body.email.toLowerCase().trim();
    if (body.rol) updates.rol = body.rol;
    if (body.activo !== undefined) updates.activo = body.activo;
    if (body.password) updates.password_hash = hashPassword(body.password);
    updates.updated_at = new Date().toISOString();
    const { data, error } = await supabase
      .from('usuarios').update(updates).eq('id', params.id).select('id, nombre, email, rol, activo').single();
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify(data) };
  }

  // DELETE
  if (event.httpMethod === 'DELETE' && params.id) {
    const { error } = await supabase.from('usuarios').delete().eq('id', params.id);
    if (error) return { statusCode: 400, headers, body: JSON.stringify({ error: error.message }) };
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  }

  return { statusCode: 405, headers, body: JSON.stringify({ error: 'Método no permitido' }) };
};
