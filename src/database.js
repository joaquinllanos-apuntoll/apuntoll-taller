const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// Limpiar la URL por si tiene espacios o saltos de línea
const rawUrl = (process.env.TURSO_URL || '').trim().replace(/\s+/g, '');
const rawToken = (process.env.TURSO_TOKEN || '').trim().replace(/\s+/g, '');

console.log('TURSO_URL recibida:', rawUrl ? rawUrl.substring(0, 40) + '...' : 'VACÍA');
console.log('TURSO_TOKEN recibido:', rawToken ? 'OK ('+rawToken.length+' chars)' : 'VACÍO');

if (!rawUrl) {
  console.error('ERROR: TURSO_URL no está configurada en las variables de entorno');
  process.exit(1);
}

const db = createClient({
  url: rawUrl,
  authToken: rawToken,
});

async function run(sql, args=[]) {
  return db.execute({ sql, args });
}

async function get(sql, args=[]) {
  const r = await db.execute({ sql, args });
  return r.rows[0] || null;
}

async function all(sql, args=[]) {
  const r = await db.execute({ sql, args });
  return r.rows;
}

async function initDB() {
  const tablas = [
    `CREATE TABLE IF NOT EXISTS talleres (
      id TEXT PRIMARY KEY, nombre TEXT NOT NULL, email TEXT NOT NULL,
      telefono TEXT DEFAULT '', direccion TEXT DEFAULT '',
      nombre_dueno TEXT DEFAULT '', dni_dueno TEXT DEFAULT '',
      activo INTEGER DEFAULT 1, pendiente INTEGER DEFAULT 0,
      suscripcion_hasta TEXT DEFAULT '', logo TEXT DEFAULT '',
      color_fondo TEXT DEFAULT '#f0f0f0', color_nav TEXT DEFAULT '#111111',
      created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, nombre TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'operario',
      taller_id TEXT, last_login TEXT, created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS clientes (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, nombre TEXT NOT NULL,
      telefono TEXT DEFAULT '', email TEXT DEFAULT '', dni TEXT DEFAULT '',
      direccion TEXT DEFAULT '', patentes TEXT DEFAULT '', created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS vehiculos (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, patente TEXT NOT NULL,
      marca TEXT DEFAULT '', modelo TEXT DEFAULT '', anio TEXT DEFAULT '',
      cliente_id TEXT DEFAULT '', ultimo_km INTEGER DEFAULT 0,
      proximo_aceite INTEGER DEFAULT 0, created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS ingresos (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, numero INTEGER DEFAULT 0,
      patente TEXT NOT NULL, fecha TEXT NOT NULL, marca TEXT DEFAULT '',
      modelo TEXT DEFAULT '', anio TEXT DEFAULT '', km INTEGER DEFAULT 0,
      cliente_id TEXT DEFAULT '', estado TEXT DEFAULT 'bueno',
      aceite TEXT DEFAULT 'ok', refrigerante TEXT DEFAULT 'ok',
      frenos TEXT DEFAULT 'ok', liq_frenos TEXT DEFAULT 'ok',
      trabajos TEXT NOT NULL, obs TEXT DEFAULT '', fotos TEXT DEFAULT '[]',
      created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS ordenes (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, numero INTEGER DEFAULT 0,
      patente TEXT NOT NULL, fecha TEXT NOT NULL, tecnico TEXT DEFAULT '',
      estado TEXT DEFAULT 'abierta', trabajos TEXT NOT NULL,
      items_mano_obra TEXT DEFAULT '[]', items_repuestos_taller TEXT DEFAULT '[]',
      items_repuestos_externos TEXT DEFAULT '[]', checklist TEXT DEFAULT '{}',
      km_egreso INTEGER DEFAULT 0, mano_obra REAL DEFAULT 0,
      costo_repuestos_taller REAL DEFAULT 0, costo_repuestos_externos REAL DEFAULT 0,
      total REAL DEFAULT 0, proximo_aceite INTEGER DEFAULT 0,
      aceite_usado TEXT DEFAULT '', obs TEXT DEFAULT '', created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS presupuestos (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, numero INTEGER DEFAULT 0,
      patente TEXT NOT NULL, fecha TEXT NOT NULL, fecha_caducidad TEXT DEFAULT '',
      cliente_id TEXT DEFAULT '', descripcion TEXT DEFAULT '',
      items TEXT DEFAULT '[]', total REAL DEFAULT 0, obs TEXT DEFAULT '',
      created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS movimientos (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, tipo TEXT NOT NULL,
      fecha TEXT NOT NULL, categoria TEXT DEFAULT 'otros', monto REAL NOT NULL,
      descripcion TEXT DEFAULT '', orden_id TEXT DEFAULT '',
      es_fijo INTEGER DEFAULT 0, created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS gastos_fijos (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, nombre TEXT NOT NULL,
      monto REAL NOT NULL, categoria TEXT DEFAULT 'otros',
      periodo_tipo TEXT DEFAULT 'mensual', periodo_valor INTEGER DEFAULT 1,
      proxima_fecha TEXT DEFAULT '', created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS movimientos_admin (
      id TEXT PRIMARY KEY, tipo TEXT NOT NULL, fecha TEXT NOT NULL,
      categoria TEXT DEFAULT 'suscripcion', monto REAL NOT NULL,
      descripcion TEXT DEFAULT '', taller_id TEXT DEFAULT '', created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS alertas (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, patente TEXT NOT NULL,
      telefono_dueno TEXT DEFAULT '', tipo TEXT DEFAULT 'fecha',
      fecha_alerta TEXT DEFAULT '', km_alerta INTEGER DEFAULT 0,
      aceite_usado TEXT DEFAULT '', filtros_cambiados TEXT DEFAULT '',
      notas TEXT DEFAULT '', resuelta INTEGER DEFAULT 0, created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS guia_km (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, tipo TEXT NOT NULL, km INTEGER NOT NULL)`,
    `CREATE TABLE IF NOT EXISTS chat_mensajes (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, remitente_id TEXT NOT NULL,
      remitente_nombre TEXT NOT NULL, remitente_role TEXT NOT NULL,
      mensaje TEXT NOT NULL, leido INTEGER DEFAULT 0, created_at TEXT)`,
    `CREATE TABLE IF NOT EXISTS contadores (
      id TEXT PRIMARY KEY, taller_id TEXT NOT NULL, tipo TEXT NOT NULL,
      valor INTEGER DEFAULT 0)`,
  ];

  for (const sql of tablas) {
    await run(sql);
  }

  const sa = await get("SELECT id FROM users WHERE role = 'superadmin'");
  if (!sa) {
    const hash = bcrypt.hashSync('admin1234', 10);
    await run(
      'INSERT INTO users (id,nombre,email,password,role,taller_id,created_at) VALUES (?,?,?,?,?,?,?)',
      [uuidv4(), 'Super Admin', 'admin@apuntoll.com', hash, 'superadmin', null, new Date().toISOString()]
    );
    console.log('Superadmin creado');
  }

  console.log('DB Turso inicializada OK');
}

async function nextNum(tallerId, tipo) {
  const c = await get('SELECT valor FROM contadores WHERE taller_id=? AND tipo=?', [tallerId, tipo]);
  if (!c) {
    await run('INSERT INTO contadores (id,taller_id,tipo,valor) VALUES (?,?,?,1)', [uuidv4(), tallerId, tipo]);
    return 1;
  }
  const next = (c.valor || 0) + 1;
  await run('UPDATE contadores SET valor=? WHERE taller_id=? AND tipo=?', [next, tallerId, tipo]);
  return next;
}

module.exports = { db, run, get, all, initDB, nextNum };
