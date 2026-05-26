const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, '../public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'apuntoll_secret_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// ─── MIDDLEWARE AUTH ───────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'No autorizado' });
}
function requireSuperAdmin(req, res, next) {
  if (req.session && req.session.role === 'superadmin') return next();
  res.status(403).json({ error: 'Acceso denegado' });
}
function requireTaller(req, res, next) {
  if (req.session && (req.session.role === 'superadmin' || req.session.role === 'admin' || req.session.role === 'operario')) return next();
  res.status(403).json({ error: 'Acceso denegado' });
}

// ─── AUTH ROUTES ──────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ ok: false, error: 'Completá todos los campos' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user) return res.json({ ok: false, error: 'Email o contraseña incorrectos' });
  if (!bcrypt.compareSync(password, user.password)) return res.json({ ok: false, error: 'Email o contraseña incorrectos' });

  if (user.role !== 'superadmin') {
    const taller = db.prepare('SELECT * FROM talleres WHERE id = ?').get(user.taller_id);
    if (!taller || taller.activo === 0) return res.json({ ok: false, error: 'Tu cuenta está suspendida. Contactá al administrador.' });
  }

  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(new Date().toISOString(), user.id);
  req.session.userId = user.id;
  req.session.role = user.role;
  req.session.tallerId = user.taller_id;
  req.session.nombre = user.nombre;

  res.json({ ok: true, role: user.role, nombre: user.nombre });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ userId: req.session.userId, role: req.session.role, tallerId: req.session.tallerId, nombre: req.session.nombre });
});

// ─── SUPERADMIN: TALLERES ─────────────────────────────────────
app.get('/api/admin/talleres', requireSuperAdmin, (req, res) => {
  const talleres = db.prepare(`
    SELECT t.*, 
      (SELECT COUNT(*) FROM users WHERE taller_id = t.id) as usuarios,
      (SELECT COUNT(*) FROM vehiculos WHERE taller_id = t.id) as vehiculos,
      (SELECT last_login FROM users WHERE taller_id = t.id AND role = 'admin' ORDER BY last_login DESC LIMIT 1) as ultimo_acceso
    FROM talleres t ORDER BY t.created_at DESC
  `).all();
  res.json(talleres);
});

app.post('/api/admin/talleres', requireSuperAdmin, (req, res) => {
  const { nombre, email, password, telefono, direccion } = req.body;
  if (!nombre || !email || !password) return res.json({ ok: false, error: 'Faltan datos obligatorios' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.json({ ok: false, error: 'Ese email ya está registrado' });
  const tallerId = uuidv4();
  db.prepare('INSERT INTO talleres (id, nombre, email, telefono, direccion, activo, created_at) VALUES (?,?,?,?,?,1,?)').run(tallerId, nombre, email.toLowerCase(), telefono||'', direccion||'', new Date().toISOString());
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (id, nombre, email, password, role, taller_id, created_at) VALUES (?,?,?,?,?,?,?)').run(uuidv4(), nombre, email.toLowerCase(), hash, 'admin', tallerId, new Date().toISOString());
  res.json({ ok: true });
});

app.put('/api/admin/talleres/:id/toggle', requireSuperAdmin, (req, res) => {
  const taller = db.prepare('SELECT * FROM talleres WHERE id = ?').get(req.params.id);
  if (!taller) return res.json({ ok: false, error: 'No encontrado' });
  db.prepare('UPDATE talleres SET activo = ? WHERE id = ?').run(taller.activo ? 0 : 1, taller.id);
  res.json({ ok: true, activo: !taller.activo });
});

app.put('/api/admin/talleres/:id/password', requireSuperAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 4) return res.json({ ok: false, error: 'Contraseña muy corta' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password = ? WHERE taller_id = ? AND role = ?').run(hash, req.params.id, 'admin');
  res.json({ ok: true });
});

app.delete('/api/admin/talleres/:id', requireSuperAdmin, (req, res) => {
  const id = req.params.id;
  db.prepare('DELETE FROM movimientos WHERE taller_id = ?').run(id);
  db.prepare('DELETE FROM ordenes WHERE taller_id = ?').run(id);
  db.prepare('DELETE FROM ingresos WHERE taller_id = ?').run(id);
  db.prepare('DELETE FROM vehiculos WHERE taller_id = ?').run(id);
  db.prepare('DELETE FROM clientes WHERE taller_id = ?').run(id);
  db.prepare('DELETE FROM users WHERE taller_id = ?').run(id);
  db.prepare('DELETE FROM talleres WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ─── SUPERADMIN: USUARIOS DE UN TALLER ───────────────────────
app.get('/api/admin/talleres/:id/users', requireSuperAdmin, (req, res) => {
  const users = db.prepare('SELECT id, nombre, email, role, last_login, created_at FROM users WHERE taller_id = ?').all(req.params.id);
  res.json(users);
});

// ─── TALLER: USUARIOS PROPIOS ─────────────────────────────────
app.get('/api/taller/users', requireAuth, (req, res) => {
  if (req.session.role !== 'admin' && req.session.role !== 'superadmin') return res.json([]);
  const users = db.prepare('SELECT id, nombre, email, role, last_login, created_at FROM users WHERE taller_id = ?').all(req.session.tallerId);
  res.json(users);
});

app.post('/api/taller/users', requireAuth, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Solo el admin puede crear usuarios' });
  const { nombre, email, password, role } = req.body;
  if (!nombre || !email || !password) return res.json({ ok: false, error: 'Faltan datos' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.json({ ok: false, error: 'Email ya registrado' });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (id, nombre, email, password, role, taller_id, created_at) VALUES (?,?,?,?,?,?,?)').run(uuidv4(), nombre, email.toLowerCase(), hash, role||'operario', req.session.tallerId, new Date().toISOString());
  res.json({ ok: true });
});

app.delete('/api/taller/users/:id', requireAuth, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'No autorizado' });
  db.prepare('DELETE FROM users WHERE id = ? AND taller_id = ? AND role != ?').run(req.params.id, req.session.tallerId, 'admin');
  res.json({ ok: true });
});

// ─── TALLER: CLIENTES ────────────────────────────────────────
app.get('/api/clientes', requireTaller, (req, res) => {
  const rows = db.prepare('SELECT * FROM clientes WHERE taller_id = ? ORDER BY nombre').all(req.session.tallerId);
  res.json(rows);
});
app.post('/api/clientes', requireTaller, (req, res) => {
  const { nombre, telefono, email, dni, direccion, patentes } = req.body;
  if (!nombre) return res.json({ ok: false, error: 'El nombre es obligatorio' });
  const id = uuidv4();
  db.prepare('INSERT INTO clientes (id, taller_id, nombre, telefono, email, dni, direccion, patentes, created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(id, req.session.tallerId, nombre, telefono||'', email||'', dni||'', direccion||'', patentes||'', new Date().toISOString());
  if (patentes) {
    patentes.split(',').map(p=>p.trim().toUpperCase()).filter(Boolean).forEach(pat => {
      const v = db.prepare('SELECT id FROM vehiculos WHERE patente = ? AND taller_id = ?').get(pat, req.session.tallerId);
      if (!v) db.prepare('INSERT INTO vehiculos (id, taller_id, patente, cliente_id, created_at) VALUES (?,?,?,?,?)').run(uuidv4(), req.session.tallerId, pat, id, new Date().toISOString());
      else db.prepare('UPDATE vehiculos SET cliente_id = ? WHERE id = ?').run(id, v.id);
    });
  }
  res.json({ ok: true, id });
});
app.put('/api/clientes/:id', requireTaller, (req, res) => {
  const { nombre, telefono, email, dni, direccion } = req.body;
  db.prepare('UPDATE clientes SET nombre=?, telefono=?, email=?, dni=?, direccion=? WHERE id=? AND taller_id=?').run(nombre, telefono||'', email||'', dni||'', direccion||'', req.params.id, req.session.tallerId);
  res.json({ ok: true });
});
app.delete('/api/clientes/:id', requireTaller, (req, res) => {
  db.prepare('DELETE FROM clientes WHERE id = ? AND taller_id = ?').run(req.params.id, req.session.tallerId);
  res.json({ ok: true });
});

// ─── TALLER: VEHICULOS ───────────────────────────────────────
app.get('/api/vehiculos', requireTaller, (req, res) => {
  const rows = db.prepare(`
    SELECT v.*, c.nombre as cliente_nombre, c.telefono as cliente_tel
    FROM vehiculos v LEFT JOIN clientes c ON v.cliente_id = c.id
    WHERE v.taller_id = ? ORDER BY v.patente
  `).all(req.session.tallerId);
  res.json(rows);
});
app.get('/api/vehiculos/:patente', requireTaller, (req, res) => {
  const v = db.prepare(`SELECT v.*, c.nombre as cliente_nombre, c.telefono as cliente_tel, c.email as cliente_email, c.id as cliente_id_real FROM vehiculos v LEFT JOIN clientes c ON v.cliente_id = c.id WHERE v.patente = ? AND v.taller_id = ?`).get(req.params.patente.toUpperCase(), req.session.tallerId);
  if (!v) return res.json(null);
  v.ingresos = db.prepare('SELECT * FROM ingresos WHERE patente = ? AND taller_id = ? ORDER BY fecha DESC').all(req.params.patente.toUpperCase(), req.session.tallerId);
  v.ordenes = db.prepare('SELECT * FROM ordenes WHERE patente = ? AND taller_id = ? ORDER BY fecha DESC').all(req.params.patente.toUpperCase(), req.session.tallerId);
  res.json(v);
});

// ─── TALLER: INGRESOS ────────────────────────────────────────
app.get('/api/ingresos', requireTaller, (req, res) => {
  const rows = db.prepare('SELECT * FROM ingresos WHERE taller_id = ? ORDER BY fecha DESC, created_at DESC LIMIT 100').all(req.session.tallerId);
  res.json(rows);
});
app.post('/api/ingresos', requireTaller, (req, res) => {
  const { patente, fecha, marca, modelo, anio, km, cliente_id, estado, aceite, refrigerante, frenos, proximo_aceite, trabajos, obs, fotos } = req.body;
  if (!patente || !fecha || !trabajos) return res.json({ ok: false, error: 'Faltan datos obligatorios' });
  const pat = patente.toUpperCase().trim();
  const id = uuidv4();
  db.prepare('INSERT INTO ingresos (id, taller_id, patente, fecha, marca, modelo, anio, km, cliente_id, estado, aceite, refrigerante, frenos, proximo_aceite, trabajos, obs, fotos, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id, req.session.tallerId, pat, fecha, marca||'', modelo||'', anio||'', km||0, cliente_id||'', estado||'bueno', aceite||'ok', refrigerante||'ok', frenos||'ok', proximo_aceite||0, trabajos, obs||'', JSON.stringify(fotos||[]), new Date().toISOString());
  let v = db.prepare('SELECT id FROM vehiculos WHERE patente = ? AND taller_id = ?').get(pat, req.session.tallerId);
  if (!v) { db.prepare('INSERT INTO vehiculos (id, taller_id, patente, marca, modelo, anio, cliente_id, ultimo_km, proximo_aceite, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').run(uuidv4(), req.session.tallerId, pat, marca||'', modelo||'', anio||'', cliente_id||'', km||0, proximo_aceite||0, new Date().toISOString()); }
  else { db.prepare('UPDATE vehiculos SET marca=COALESCE(NULLIF(?,\'\'),marca), modelo=COALESCE(NULLIF(?,\'\'),modelo), anio=COALESCE(NULLIF(?,\'\'),anio), cliente_id=COALESCE(NULLIF(?,\'\'),cliente_id), ultimo_km=?, proximo_aceite=? WHERE patente=? AND taller_id=?').run(marca||'', modelo||'', anio||'', cliente_id||'', km||0, proximo_aceite||0, pat, req.session.tallerId); }
  res.json({ ok: true, id });
});

// ─── TALLER: ORDENES ─────────────────────────────────────────
app.get('/api/ordenes', requireTaller, (req, res) => {
  const rows = db.prepare('SELECT * FROM ordenes WHERE taller_id = ? ORDER BY fecha DESC, created_at DESC').all(req.session.tallerId);
  res.json(rows);
});
app.post('/api/ordenes', requireTaller, (req, res) => {
  const { patente, fecha, tecnico, estado, trabajos, repuestos, km_egreso, mano_obra, costo_repuestos, total, obs } = req.body;
  if (!patente || !fecha || !trabajos) return res.json({ ok: false, error: 'Faltan datos' });
  const pat = patente.toUpperCase().trim();
  const id = uuidv4();
  const num = 'OT-' + Date.now().toString().slice(-6);
  db.prepare('INSERT INTO ordenes (id, taller_id, numero, patente, fecha, tecnico, estado, trabajos, repuestos, km_egreso, mano_obra, costo_repuestos, total, obs, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id, req.session.tallerId, num, pat, fecha, tecnico||'', estado||'abierta', trabajos, repuestos||'', km_egreso||0, mano_obra||0, costo_repuestos||0, total||0, obs||'', new Date().toISOString());
  if (km_egreso) db.prepare('UPDATE vehiculos SET ultimo_km = ? WHERE patente = ? AND taller_id = ?').run(km_egreso, pat, req.session.tallerId);
  if (total > 0) db.prepare('INSERT INTO movimientos (id, taller_id, tipo, fecha, categoria, monto, descripcion, orden_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(uuidv4(), req.session.tallerId, 'ingreso', fecha, 'mano_obra', total, 'OT '+num+' — '+pat, id, new Date().toISOString());
  res.json({ ok: true, id, numero: num });
});
app.put('/api/ordenes/:id', requireTaller, (req, res) => {
  const { estado, tecnico, trabajos, repuestos, km_egreso, mano_obra, costo_repuestos, total, obs } = req.body;
  db.prepare('UPDATE ordenes SET estado=?, tecnico=?, trabajos=?, repuestos=?, km_egreso=?, mano_obra=?, costo_repuestos=?, total=?, obs=? WHERE id=? AND taller_id=?').run(estado, tecnico||'', trabajos, repuestos||'', km_egreso||0, mano_obra||0, costo_repuestos||0, total||0, obs||'', req.params.id, req.session.tallerId);
  res.json({ ok: true });
});
app.delete('/api/ordenes/:id', requireTaller, (req, res) => {
  db.prepare('DELETE FROM ordenes WHERE id = ? AND taller_id = ?').run(req.params.id, req.session.tallerId);
  res.json({ ok: true });
});

// ─── TALLER: MOVIMIENTOS ─────────────────────────────────────
app.get('/api/movimientos', requireTaller, (req, res) => {
  const rows = db.prepare('SELECT * FROM movimientos WHERE taller_id = ? ORDER BY fecha DESC, created_at DESC').all(req.session.tallerId);
  res.json(rows);
});
app.post('/api/movimientos', requireTaller, (req, res) => {
  const { tipo, fecha, categoria, monto, descripcion, orden_id } = req.body;
  if (!tipo || !fecha || !monto) return res.json({ ok: false, error: 'Faltan datos' });
  const id = uuidv4();
  db.prepare('INSERT INTO movimientos (id, taller_id, tipo, fecha, categoria, monto, descripcion, orden_id, created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(id, req.session.tallerId, tipo, fecha, categoria||'otros', parseFloat(monto), descripcion||'', orden_id||'', new Date().toISOString());
  res.json({ ok: true, id });
});
app.delete('/api/movimientos/:id', requireTaller, (req, res) => {
  db.prepare('DELETE FROM movimientos WHERE id = ? AND taller_id = ?').run(req.params.id, req.session.tallerId);
  res.json({ ok: true });
});

// ─── TALLER: GUIA KM ─────────────────────────────────────────
app.get('/api/guiakm', requireTaller, (req, res) => {
  const rows = db.prepare('SELECT * FROM guia_km WHERE taller_id = ? ORDER BY tipo').all(req.session.tallerId);
  res.json(rows);
});
app.post('/api/guiakm', requireTaller, (req, res) => {
  const { tipo, km } = req.body;
  db.prepare('INSERT INTO guia_km (id, taller_id, tipo, km) VALUES (?,?,?,?)').run(uuidv4(), req.session.tallerId, tipo, km);
  res.json({ ok: true });
});
app.delete('/api/guiakm/:id', requireTaller, (req, res) => {
  db.prepare('DELETE FROM guia_km WHERE id = ? AND taller_id = ?').run(req.params.id, req.session.tallerId);
  res.json({ ok: true });
});

// ─── TALLER INFO ─────────────────────────────────────────────
app.get('/api/taller/info', requireAuth, (req, res) => {
  if (req.session.role === 'superadmin') return res.json({ nombre: 'Apuntoll Admin', email: '' });
  const t = db.prepare('SELECT * FROM talleres WHERE id = ?').get(req.session.tallerId);
  res.json(t || {});
});

// ─── SERVE FRONTEND ──────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`Apuntoll corriendo en http://localhost:${PORT}`);
});
