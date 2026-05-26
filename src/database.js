const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../db/apuntoll.db');
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS talleres (
  id TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  email TEXT NOT NULL,
  telefono TEXT DEFAULT '',
  direccion TEXT DEFAULT '',
  activo INTEGER DEFAULT 1,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  nombre TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'operario',
  taller_id TEXT,
  last_login TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS clientes (
  id TEXT PRIMARY KEY,
  taller_id TEXT NOT NULL,
  nombre TEXT NOT NULL,
  telefono TEXT DEFAULT '',
  email TEXT DEFAULT '',
  dni TEXT DEFAULT '',
  direccion TEXT DEFAULT '',
  patentes TEXT DEFAULT '',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS vehiculos (
  id TEXT PRIMARY KEY,
  taller_id TEXT NOT NULL,
  patente TEXT NOT NULL,
  marca TEXT DEFAULT '',
  modelo TEXT DEFAULT '',
  anio TEXT DEFAULT '',
  cliente_id TEXT DEFAULT '',
  ultimo_km INTEGER DEFAULT 0,
  proximo_aceite INTEGER DEFAULT 0,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS ingresos (
  id TEXT PRIMARY KEY,
  taller_id TEXT NOT NULL,
  patente TEXT NOT NULL,
  fecha TEXT NOT NULL,
  marca TEXT DEFAULT '',
  modelo TEXT DEFAULT '',
  anio TEXT DEFAULT '',
  km INTEGER DEFAULT 0,
  cliente_id TEXT DEFAULT '',
  estado TEXT DEFAULT 'bueno',
  aceite TEXT DEFAULT 'ok',
  refrigerante TEXT DEFAULT 'ok',
  frenos TEXT DEFAULT 'ok',
  proximo_aceite INTEGER DEFAULT 0,
  trabajos TEXT NOT NULL,
  obs TEXT DEFAULT '',
  fotos TEXT DEFAULT '[]',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS ordenes (
  id TEXT PRIMARY KEY,
  taller_id TEXT NOT NULL,
  numero TEXT NOT NULL,
  patente TEXT NOT NULL,
  fecha TEXT NOT NULL,
  tecnico TEXT DEFAULT '',
  estado TEXT DEFAULT 'abierta',
  trabajos TEXT NOT NULL,
  repuestos TEXT DEFAULT '',
  km_egreso INTEGER DEFAULT 0,
  mano_obra REAL DEFAULT 0,
  costo_repuestos REAL DEFAULT 0,
  total REAL DEFAULT 0,
  obs TEXT DEFAULT '',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS movimientos (
  id TEXT PRIMARY KEY,
  taller_id TEXT NOT NULL,
  tipo TEXT NOT NULL,
  fecha TEXT NOT NULL,
  categoria TEXT DEFAULT 'otros',
  monto REAL NOT NULL,
  descripcion TEXT DEFAULT '',
  orden_id TEXT DEFAULT '',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS guia_km (
  id TEXT PRIMARY KEY,
  taller_id TEXT NOT NULL,
  tipo TEXT NOT NULL,
  km INTEGER NOT NULL
);
`);

// Crear superadmin si no existe
const superadmin = db.prepare("SELECT id FROM users WHERE role = 'superadmin'").get();
if (!superadmin) {
  const hash = bcrypt.hashSync('admin1234', 10);
  db.prepare("INSERT INTO users (id, nombre, email, password, role, taller_id, created_at) VALUES (?,?,?,?,?,?,?)")
    .run(uuidv4(), 'Super Admin', 'admin@apuntoll.com', hash, 'superadmin', null, new Date().toISOString());
  console.log('✓ Superadmin creado: admin@apuntoll.com / admin1234 — CAMBIÁ LA CONTRASEÑA');
}

module.exports = db;
