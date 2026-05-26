const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, '../public')));
app.use(session({ secret: process.env.SESSION_SECRET || 'apuntoll_2024', resave: false, saveUninitialized: false, cookie: { maxAge: 24*60*60*1000 } }));

const auth = (req,res,next) => req.session?.userId ? next() : res.status(401).json({error:'No autorizado'});
const isSA = (req,res,next) => req.session?.role==='superadmin' ? next() : res.status(403).json({error:'Solo superadmin'});
const isAdm = (req,res,next) => ['superadmin','admin'].includes(req.session?.role) ? next() : res.status(403).json({error:'Solo admin'});
const isTaller = (req,res,next) => ['superadmin','admin','operario'].includes(req.session?.role) ? next() : res.status(403).json({error:'No autorizado'});

// AUTH
app.post('/api/login', (req,res) => {
  const {email,password} = req.body;
  if(!email||!password) return res.json({ok:false,error:'Completá todos los campos'});
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase().trim());
  if(!user||!bcrypt.compareSync(password,user.password)) return res.json({ok:false,error:'Email o contraseña incorrectos'});
  if(user.role!=='superadmin'){
    const t = db.prepare('SELECT * FROM talleres WHERE id=?').get(user.taller_id);
    if(!t||t.activo===0) return res.json({ok:false,error:'Cuenta suspendida. Contactá al administrador.'});
    if(t.suscripcion_hasta && t.suscripcion_hasta < new Date().toISOString().split('T')[0])
      return res.json({ok:false,error:'Suscripción vencida. Contactá al administrador.'});
  }
  db.prepare('UPDATE users SET last_login=? WHERE id=?').run(new Date().toISOString(), user.id);
  req.session.userId=user.id; req.session.role=user.role; req.session.tallerId=user.taller_id; req.session.nombre=user.nombre;
  res.json({ok:true, role:user.role, nombre:user.nombre});
});
app.post('/api/logout', (req,res) => { req.session.destroy(); res.json({ok:true}); });
app.get('/api/me', auth, (req,res) => res.json({userId:req.session.userId,role:req.session.role,tallerId:req.session.tallerId,nombre:req.session.nombre}));

// REGISTRO PÚBLICO
app.post('/api/registro', (req,res) => {
  const {nombre,email,password,telefono,direccion,nombre_dueno,dni_dueno} = req.body;
  if(!nombre||!email||!password) return res.json({ok:false,error:'Faltan datos obligatorios'});
  if(password.length<6) return res.json({ok:false,error:'Contraseña mínimo 6 caracteres'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return res.json({ok:false,error:'Email ya registrado'});
  const tid = uuidv4();
  db.prepare('INSERT INTO talleres (id,nombre,email,telefono,direccion,nombre_dueno,dni_dueno,activo,pendiente,created_at) VALUES (?,?,?,?,?,?,?,0,1,?)').run(tid,nombre,email.toLowerCase(),telefono||'',direccion||'',nombre_dueno||'',dni_dueno||'',new Date().toISOString());
  db.prepare('INSERT INTO users (id,nombre,email,password,role,taller_id,created_at) VALUES (?,?,?,?,?,?,?)').run(uuidv4(),nombre_dueno||nombre,email.toLowerCase(),bcrypt.hashSync(password,10),'admin',tid,new Date().toISOString());
  res.json({ok:true});
});

// SUPERADMIN TALLERES
app.get('/api/admin/talleres', isSA, (req,res) => {
  res.json(db.prepare(`SELECT t.*,(SELECT COUNT(*) FROM vehiculos WHERE taller_id=t.id) as vehiculos,(SELECT last_login FROM users WHERE taller_id=t.id AND role='admin' ORDER BY last_login DESC LIMIT 1) as ultimo_acceso FROM talleres t ORDER BY t.created_at DESC`).all());
});
app.post('/api/admin/talleres', isSA, (req,res) => {
  const {nombre,email,password,telefono,direccion,nombre_dueno,dni_dueno,suscripcion_hasta} = req.body;
  if(!nombre||!email||!password) return res.json({ok:false,error:'Faltan datos'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return res.json({ok:false,error:'Email ya registrado'});
  const tid = uuidv4();
  db.prepare('INSERT INTO talleres (id,nombre,email,telefono,direccion,nombre_dueno,dni_dueno,activo,pendiente,suscripcion_hasta,created_at) VALUES (?,?,?,?,?,?,?,1,0,?,?)').run(tid,nombre,email.toLowerCase(),telefono||'',direccion||'',nombre_dueno||'',dni_dueno||'',suscripcion_hasta||'',new Date().toISOString());
  db.prepare('INSERT INTO users (id,nombre,email,password,role,taller_id,created_at) VALUES (?,?,?,?,?,?,?)').run(uuidv4(),nombre_dueno||nombre,email.toLowerCase(),bcrypt.hashSync(password,10),'admin',tid,new Date().toISOString());
  res.json({ok:true});
});
app.put('/api/admin/talleres/:id', isSA, (req,res) => {
  const {nombre,email,telefono,direccion,nombre_dueno,dni_dueno,activo,pendiente,suscripcion_hasta} = req.body;
  db.prepare('UPDATE talleres SET nombre=?,email=?,telefono=?,direccion=?,nombre_dueno=?,dni_dueno=?,activo=?,pendiente=?,suscripcion_hasta=? WHERE id=?').run(nombre,email,telefono||'',direccion||'',nombre_dueno||'',dni_dueno||'',activo?1:0,pendiente?1:0,suscripcion_hasta||'',req.params.id);
  res.json({ok:true});
});
app.put('/api/admin/talleres/:id/toggle', isSA, (req,res) => {
  const t = db.prepare('SELECT * FROM talleres WHERE id=?').get(req.params.id);
  if(!t) return res.json({ok:false});
  db.prepare('UPDATE talleres SET activo=? WHERE id=?').run(t.activo?0:1,t.id);
  res.json({ok:true,activo:!t.activo});
});
app.put('/api/admin/talleres/:id/aprobar', isSA, (req,res) => {
  db.prepare('UPDATE talleres SET activo=1,pendiente=0,suscripcion_hasta=? WHERE id=?').run(req.body.suscripcion_hasta||'',req.params.id);
  res.json({ok:true});
});
app.put('/api/admin/talleres/:id/password', isSA, (req,res) => {
  const {password} = req.body;
  if(!password||password.length<4) return res.json({ok:false,error:'Contraseña muy corta'});
  db.prepare('UPDATE users SET password=? WHERE taller_id=? AND role=?').run(bcrypt.hashSync(password,10),req.params.id,'admin');
  res.json({ok:true});
});
app.delete('/api/admin/talleres/:id', isSA, (req,res) => {
  const id = req.params.id;
  ['movimientos','gastos_fijos','ordenes','presupuestos','ingresos','vehiculos','clientes','users','alertas','chat_mensajes'].forEach(t=>db.prepare(`DELETE FROM ${t} WHERE taller_id=?`).run(id));
  db.prepare('DELETE FROM talleres WHERE id=?').run(id);
  res.json({ok:true});
});
app.get('/api/admin/talleres/:id/users', isSA, (req,res) => res.json(db.prepare('SELECT id,nombre,email,role,last_login,created_at FROM users WHERE taller_id=?').all(req.params.id)));

// SUPERADMIN PERFIL Y ECONOMÍA
app.put('/api/admin/perfil', isSA, (req,res) => {
  const {nombre,email,password} = req.body;
  if(email){const ex=db.prepare('SELECT id FROM users WHERE email=? AND id!=?').get(email.toLowerCase(),req.session.userId);if(ex)return res.json({ok:false,error:'Email ya en uso'});db.prepare('UPDATE users SET nombre=?,email=? WHERE id=?').run(nombre||'Super Admin',email.toLowerCase(),req.session.userId);}
  if(password&&password.length>=4) db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(password,10),req.session.userId);
  res.json({ok:true});
});
app.get('/api/admin/movimientos', isSA, (req,res) => res.json(db.prepare('SELECT * FROM movimientos_admin ORDER BY fecha DESC').all()));
app.post('/api/admin/movimientos', isSA, (req,res) => {
  db.prepare('INSERT INTO movimientos_admin (id,tipo,fecha,categoria,monto,descripcion,taller_id,created_at) VALUES (?,?,?,?,?,?,?,?)').run(uuidv4(),req.body.tipo,req.body.fecha,req.body.categoria||'suscripcion',parseFloat(req.body.monto),req.body.descripcion||'',req.body.taller_id||'',new Date().toISOString());
  res.json({ok:true});
});
app.delete('/api/admin/movimientos/:id', isSA, (req,res) => { db.prepare('DELETE FROM movimientos_admin WHERE id=?').run(req.params.id); res.json({ok:true}); });

// TALLER USUARIOS
app.get('/api/taller/users', isAdm, (req,res) => res.json(db.prepare('SELECT id,nombre,email,role,last_login,created_at FROM users WHERE taller_id=?').all(req.session.tallerId)));
app.post('/api/taller/users', isAdm, (req,res) => {
  const {nombre,email,password,role} = req.body;
  if(!nombre||!email||!password) return res.json({ok:false,error:'Faltan datos'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) return res.json({ok:false,error:'Email ya registrado'});
  db.prepare('INSERT INTO users (id,nombre,email,password,role,taller_id,created_at) VALUES (?,?,?,?,?,?,?)').run(uuidv4(),nombre,email.toLowerCase(),bcrypt.hashSync(password,10),role||'operario',req.session.tallerId,new Date().toISOString());
  res.json({ok:true});
});
app.put('/api/taller/users/:id', isAdm, (req,res) => {
  const {nombre,email,password} = req.body;
  const u = db.prepare('SELECT * FROM users WHERE id=? AND taller_id=?').get(req.params.id,req.session.tallerId);
  if(!u) return res.json({ok:false,error:'No encontrado'});
  if(email&&email!==u.email){const ex=db.prepare('SELECT id FROM users WHERE email=? AND id!=?').get(email.toLowerCase(),req.params.id);if(ex)return res.json({ok:false,error:'Email ya en uso'});}
  db.prepare('UPDATE users SET nombre=?,email=? WHERE id=?').run(nombre||u.nombre,(email||u.email).toLowerCase(),req.params.id);
  if(password&&password.length>=4) db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(password,10),req.params.id);
  res.json({ok:true});
});
app.delete('/api/taller/users/:id', isAdm, (req,res) => { db.prepare("DELETE FROM users WHERE id=? AND taller_id=? AND role!='admin'").run(req.params.id,req.session.tallerId); res.json({ok:true}); });
app.put('/api/taller/perfil', auth, (req,res) => {
  const {nombre,email,password} = req.body;
  if(email){const ex=db.prepare('SELECT id FROM users WHERE email=? AND id!=?').get(email.toLowerCase(),req.session.userId);if(ex)return res.json({ok:false,error:'Email ya en uso'});db.prepare('UPDATE users SET nombre=?,email=? WHERE id=?').run(nombre||'',email.toLowerCase(),req.session.userId);}
  if(password&&password.length>=4) db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(password,10),req.session.userId);
  res.json({ok:true});
});

// TALLER INFO Y PERSONALIZACIÓN
app.get('/api/taller/info', auth, (req,res) => {
  if(req.session.role==='superadmin') return res.json({nombre:'Apuntoll Admin',email:'',color_fondo:'#f0f0f0',color_nav:'#111111',logo:''});
  res.json(db.prepare('SELECT * FROM talleres WHERE id=?').get(req.session.tallerId)||{});
});
app.put('/api/taller/personalizacion', isAdm, (req,res) => {
  db.prepare('UPDATE talleres SET color_fondo=?,color_nav=?,logo=? WHERE id=?').run(req.body.color_fondo||'#f0f0f0',req.body.color_nav||'#111111',req.body.logo||'',req.session.tallerId);
  res.json({ok:true});
});

// CLIENTES
app.get('/api/clientes', isTaller, (req,res) => res.json(db.prepare('SELECT * FROM clientes WHERE taller_id=? ORDER BY nombre').all(req.session.tallerId)));
app.post('/api/clientes', isTaller, (req,res) => {
  const {nombre,telefono,email,dni,direccion,patentes} = req.body;
  if(!nombre) return res.json({ok:false,error:'El nombre es obligatorio'});
  const id = uuidv4();
  db.prepare('INSERT INTO clientes (id,taller_id,nombre,telefono,email,dni,direccion,patentes,created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(id,req.session.tallerId,nombre,telefono||'',email||'',dni||'',direccion||'',patentes||'',new Date().toISOString());
  if(patentes) patentes.split(',').map(p=>p.trim().toUpperCase()).filter(Boolean).forEach(pat=>{
    const v=db.prepare('SELECT id FROM vehiculos WHERE patente=? AND taller_id=?').get(pat,req.session.tallerId);
    if(!v) db.prepare('INSERT INTO vehiculos (id,taller_id,patente,cliente_id,created_at) VALUES (?,?,?,?,?)').run(uuidv4(),req.session.tallerId,pat,id,new Date().toISOString());
    else db.prepare('UPDATE vehiculos SET cliente_id=? WHERE id=?').run(id,v.id);
  });
  res.json({ok:true,id});
});
app.put('/api/clientes/:id', isTaller, (req,res) => {
  const {nombre,telefono,email,dni,direccion} = req.body;
  db.prepare('UPDATE clientes SET nombre=?,telefono=?,email=?,dni=?,direccion=? WHERE id=? AND taller_id=?').run(nombre,telefono||'',email||'',dni||'',direccion||'',req.params.id,req.session.tallerId);
  res.json({ok:true});
});
app.delete('/api/clientes/:id', isTaller, (req,res) => { db.prepare('DELETE FROM clientes WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });

// VEHICULOS
app.get('/api/vehiculos', isTaller, (req,res) => res.json(db.prepare('SELECT v.*,c.nombre as cliente_nombre,c.telefono as cliente_tel FROM vehiculos v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.taller_id=? ORDER BY v.patente').all(req.session.tallerId)));
app.get('/api/vehiculos/:patente', isTaller, (req,res) => {
  const v = db.prepare('SELECT v.*,c.nombre as cliente_nombre,c.telefono as cliente_tel,c.email as cliente_email,c.dni as cliente_dni,c.id as cliente_id_real FROM vehiculos v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.patente=? AND v.taller_id=?').get(req.params.patente.toUpperCase(),req.session.tallerId);
  if(!v) return res.json(null);
  v.ingresos = db.prepare('SELECT * FROM ingresos WHERE patente=? AND taller_id=? ORDER BY fecha DESC').all(req.params.patente.toUpperCase(),req.session.tallerId);
  v.ordenes = db.prepare('SELECT * FROM ordenes WHERE patente=? AND taller_id=? ORDER BY fecha DESC').all(req.params.patente.toUpperCase(),req.session.tallerId);
  res.json(v);
});
app.put('/api/vehiculos/:id', isTaller, (req,res) => {
  db.prepare('UPDATE vehiculos SET marca=?,modelo=?,anio=?,cliente_id=? WHERE id=? AND taller_id=?').run(req.body.marca||'',req.body.modelo||'',req.body.anio||'',req.body.cliente_id||'',req.params.id,req.session.tallerId);
  res.json({ok:true});
});

// INGRESOS
app.get('/api/ingresos', isTaller, (req,res) => res.json(db.prepare('SELECT * FROM ingresos WHERE taller_id=? ORDER BY fecha DESC,created_at DESC LIMIT 100').all(req.session.tallerId)));
app.post('/api/ingresos', isTaller, (req,res) => {
  const {patente,fecha,marca,modelo,anio,km,cliente_id,estado,aceite,refrigerante,frenos,trabajos,obs,fotos} = req.body;
  if(!patente||!fecha||!trabajos) return res.json({ok:false,error:'Faltan datos obligatorios'});
  const pat = patente.toUpperCase().trim();
  const id = uuidv4();
  db.prepare('INSERT INTO ingresos (id,taller_id,patente,fecha,marca,modelo,anio,km,cliente_id,estado,aceite,refrigerante,frenos,trabajos,obs,fotos,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,req.session.tallerId,pat,fecha,marca||'',modelo||'',anio||'',km||0,cliente_id||'',estado||'bueno',aceite||'ok',refrigerante||'ok',frenos||'ok',trabajos,obs||'',JSON.stringify(fotos||[]),new Date().toISOString());
  const v = db.prepare('SELECT id FROM vehiculos WHERE patente=? AND taller_id=?').get(pat,req.session.tallerId);
  if(!v) db.prepare('INSERT INTO vehiculos (id,taller_id,patente,marca,modelo,anio,cliente_id,ultimo_km,created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(uuidv4(),req.session.tallerId,pat,marca||'',modelo||'',anio||'',cliente_id||'',km||0,new Date().toISOString());
  else db.prepare("UPDATE vehiculos SET marca=COALESCE(NULLIF(?,''),marca),modelo=COALESCE(NULLIF(?,''),modelo),anio=COALESCE(NULLIF(?,''),anio),cliente_id=COALESCE(NULLIF(?,''),cliente_id),ultimo_km=? WHERE patente=? AND taller_id=?").run(marca||'',modelo||'',anio||'',cliente_id||'',km||0,pat,req.session.tallerId);
  res.json({ok:true,id});
});
app.put('/api/ingresos/:id', isTaller, (req,res) => {
  const {fecha,marca,modelo,anio,km,cliente_id,estado,aceite,refrigerante,frenos,trabajos,obs} = req.body;
  db.prepare('UPDATE ingresos SET fecha=?,marca=?,modelo=?,anio=?,km=?,cliente_id=?,estado=?,aceite=?,refrigerante=?,frenos=?,trabajos=?,obs=? WHERE id=? AND taller_id=?').run(fecha,marca||'',modelo||'',anio||'',km||0,cliente_id||'',estado||'bueno',aceite||'ok',refrigerante||'ok',frenos||'ok',trabajos,obs||'',req.params.id,req.session.tallerId);
  res.json({ok:true});
});
app.delete('/api/ingresos/:id', isTaller, (req,res) => { db.prepare('DELETE FROM ingresos WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });

// ORDENES
app.get('/api/ordenes', isTaller, (req,res) => res.json(db.prepare('SELECT * FROM ordenes WHERE taller_id=? ORDER BY fecha DESC,created_at DESC').all(req.session.tallerId)));
app.post('/api/ordenes', isTaller, (req,res) => {
  const {patente,fecha,tecnico,estado,trabajos,items_mano_obra,items_repuestos_taller,items_repuestos_externos,checklist,km_egreso,mano_obra,costo_repuestos_taller,costo_repuestos_externos,total,proximo_aceite,aceite_usado,obs} = req.body;
  if(!patente||!fecha||!trabajos) return res.json({ok:false,error:'Faltan datos'});
  const pat = patente.toUpperCase().trim();
  const id = uuidv4(); const num = 'OT-'+Date.now().toString().slice(-6);
  db.prepare('INSERT INTO ordenes (id,taller_id,numero,patente,fecha,tecnico,estado,trabajos,items_mano_obra,items_repuestos_taller,items_repuestos_externos,checklist,km_egreso,mano_obra,costo_repuestos_taller,costo_repuestos_externos,total,proximo_aceite,aceite_usado,obs,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,req.session.tallerId,num,pat,fecha,tecnico||'',estado||'abierta',trabajos,JSON.stringify(items_mano_obra||[]),JSON.stringify(items_repuestos_taller||[]),JSON.stringify(items_repuestos_externos||[]),JSON.stringify(checklist||{}),km_egreso||0,mano_obra||0,costo_repuestos_taller||0,costo_repuestos_externos||0,total||0,proximo_aceite||0,aceite_usado||'',obs||'',new Date().toISOString());
  if(km_egreso) db.prepare('UPDATE vehiculos SET ultimo_km=? WHERE patente=? AND taller_id=?').run(km_egreso,pat,req.session.tallerId);
  if(proximo_aceite) db.prepare('UPDATE vehiculos SET proximo_aceite=? WHERE patente=? AND taller_id=?').run(proximo_aceite,pat,req.session.tallerId);
  if(total>0) db.prepare('INSERT INTO movimientos (id,taller_id,tipo,fecha,categoria,monto,descripcion,orden_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(uuidv4(),req.session.tallerId,'ingreso',fecha,'mano_obra',total,'OT '+num+' — '+pat,id,new Date().toISOString());
  res.json({ok:true,id,numero:num});
});
app.put('/api/ordenes/:id', isTaller, (req,res) => {
  const {estado,tecnico,trabajos,items_mano_obra,items_repuestos_taller,items_repuestos_externos,checklist,km_egreso,mano_obra,costo_repuestos_taller,costo_repuestos_externos,total,proximo_aceite,aceite_usado,obs} = req.body;
  db.prepare('UPDATE ordenes SET estado=?,tecnico=?,trabajos=?,items_mano_obra=?,items_repuestos_taller=?,items_repuestos_externos=?,checklist=?,km_egreso=?,mano_obra=?,costo_repuestos_taller=?,costo_repuestos_externos=?,total=?,proximo_aceite=?,aceite_usado=?,obs=? WHERE id=? AND taller_id=?').run(estado,tecnico||'',trabajos,JSON.stringify(items_mano_obra||[]),JSON.stringify(items_repuestos_taller||[]),JSON.stringify(items_repuestos_externos||[]),JSON.stringify(checklist||{}),km_egreso||0,mano_obra||0,costo_repuestos_taller||0,costo_repuestos_externos||0,total||0,proximo_aceite||0,aceite_usado||'',obs||'',req.params.id,req.session.tallerId);
  res.json({ok:true});
});
app.delete('/api/ordenes/:id', isTaller, (req,res) => { db.prepare('DELETE FROM ordenes WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });

// PRESUPUESTOS
app.get('/api/presupuestos', isTaller, (req,res) => res.json(db.prepare('SELECT * FROM presupuestos WHERE taller_id=? ORDER BY fecha DESC').all(req.session.tallerId)));
app.post('/api/presupuestos', isTaller, (req,res) => {
  const {patente,fecha,cliente_id,items,total,obs} = req.body;
  if(!patente||!fecha) return res.json({ok:false,error:'Faltan datos'});
  const id=uuidv4(); const num='PRES-'+Date.now().toString().slice(-6);
  db.prepare('INSERT INTO presupuestos (id,taller_id,numero,patente,fecha,cliente_id,items,total,obs,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').run(id,req.session.tallerId,num,patente.toUpperCase(),fecha,cliente_id||'',JSON.stringify(items||[]),total||0,obs||'',new Date().toISOString());
  res.json({ok:true,id,numero:num});
});
app.put('/api/presupuestos/:id', isTaller, (req,res) => {
  db.prepare('UPDATE presupuestos SET patente=?,fecha=?,cliente_id=?,items=?,total=?,obs=? WHERE id=? AND taller_id=?').run(req.body.patente||'',req.body.fecha,req.body.cliente_id||'',JSON.stringify(req.body.items||[]),req.body.total||0,req.body.obs||'',req.params.id,req.session.tallerId);
  res.json({ok:true});
});
app.delete('/api/presupuestos/:id', isTaller, (req,res) => { db.prepare('DELETE FROM presupuestos WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });

// MOVIMIENTOS Y GASTOS FIJOS
app.get('/api/movimientos', isTaller, (req,res) => res.json(db.prepare('SELECT * FROM movimientos WHERE taller_id=? ORDER BY fecha DESC,created_at DESC').all(req.session.tallerId)));
app.post('/api/movimientos', isTaller, (req,res) => {
  db.prepare('INSERT INTO movimientos (id,taller_id,tipo,fecha,categoria,monto,descripcion,orden_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)').run(uuidv4(),req.session.tallerId,req.body.tipo,req.body.fecha,req.body.categoria||'otros',parseFloat(req.body.monto),req.body.descripcion||'',req.body.orden_id||'',new Date().toISOString());
  res.json({ok:true});
});
app.delete('/api/movimientos/:id', isTaller, (req,res) => { db.prepare('DELETE FROM movimientos WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });
app.get('/api/gastos-fijos', isAdm, (req,res) => res.json(db.prepare('SELECT * FROM gastos_fijos WHERE taller_id=? ORDER BY nombre').all(req.session.tallerId)));
app.post('/api/gastos-fijos', isAdm, (req,res) => {
  db.prepare('INSERT INTO gastos_fijos (id,taller_id,nombre,monto,categoria,created_at) VALUES (?,?,?,?,?,?)').run(uuidv4(),req.session.tallerId,req.body.nombre,parseFloat(req.body.monto),req.body.categoria||'otros',new Date().toISOString());
  res.json({ok:true});
});
app.put('/api/gastos-fijos/:id', isAdm, (req,res) => {
  db.prepare('UPDATE gastos_fijos SET nombre=?,monto=?,categoria=? WHERE id=? AND taller_id=?').run(req.body.nombre,parseFloat(req.body.monto),req.body.categoria||'otros',req.params.id,req.session.tallerId);
  res.json({ok:true});
});
app.delete('/api/gastos-fijos/:id', isAdm, (req,res) => { db.prepare('DELETE FROM gastos_fijos WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });

// ALERTAS
app.get('/api/alertas', isTaller, (req,res) => res.json(db.prepare('SELECT * FROM alertas WHERE taller_id=? AND resuelta=0 ORDER BY fecha_alerta ASC').all(req.session.tallerId)));
app.post('/api/alertas', isTaller, (req,res) => {
  const {patente,tipo,fecha_alerta,km_alerta,aceite_usado,filtros_cambiados,notas} = req.body;
  db.prepare('INSERT INTO alertas (id,taller_id,patente,tipo,fecha_alerta,km_alerta,aceite_usado,filtros_cambiados,notas,resuelta,created_at) VALUES (?,?,?,?,?,?,?,?,?,0,?)').run(uuidv4(),req.session.tallerId,patente.toUpperCase(),tipo||'fecha',fecha_alerta||'',km_alerta||0,aceite_usado||'',filtros_cambiados||'',notas||'',new Date().toISOString());
  res.json({ok:true});
});
app.put('/api/alertas/:id', isTaller, (req,res) => {
  db.prepare('UPDATE alertas SET resuelta=?,aceite_usado=?,filtros_cambiados=?,notas=? WHERE id=? AND taller_id=?').run(req.body.resuelta?1:0,req.body.aceite_usado||'',req.body.filtros_cambiados||'',req.body.notas||'',req.params.id,req.session.tallerId);
  res.json({ok:true});
});
app.delete('/api/alertas/:id', isTaller, (req,res) => { db.prepare('DELETE FROM alertas WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });

// GUIA KM
app.get('/api/guiakm', isTaller, (req,res) => res.json(db.prepare('SELECT * FROM guia_km WHERE taller_id=? ORDER BY tipo').all(req.session.tallerId)));
app.post('/api/guiakm', isTaller, (req,res) => { db.prepare('INSERT INTO guia_km (id,taller_id,tipo,km) VALUES (?,?,?,?)').run(uuidv4(),req.session.tallerId,req.body.tipo,req.body.km); res.json({ok:true}); });
app.delete('/api/guiakm/:id', isTaller, (req,res) => { db.prepare('DELETE FROM guia_km WHERE id=? AND taller_id=?').run(req.params.id,req.session.tallerId); res.json({ok:true}); });

// CHAT
app.get('/api/chat/:taller_id', auth, (req,res) => {
  const tid = req.session.role==='superadmin' ? req.params.taller_id : req.session.tallerId;
  res.json(db.prepare('SELECT * FROM chat_mensajes WHERE taller_id=? ORDER BY created_at ASC').all(tid));
  if(req.session.role==='superadmin') db.prepare("UPDATE chat_mensajes SET leido=1 WHERE taller_id=? AND remitente_role!='superadmin'").run(tid);
  else db.prepare("UPDATE chat_mensajes SET leido=1 WHERE taller_id=? AND remitente_role='superadmin'").run(tid);
});
app.post('/api/chat/:taller_id', auth, (req,res) => {
  const tid = req.session.role==='superadmin' ? req.params.taller_id : req.session.tallerId;
  db.prepare('INSERT INTO chat_mensajes (id,taller_id,remitente_id,remitente_nombre,remitente_role,mensaje,leido,created_at) VALUES (?,?,?,?,?,?,0,?)').run(uuidv4(),tid,req.session.userId,req.session.nombre,req.session.role,req.body.mensaje,new Date().toISOString());
  res.json({ok:true});
});
app.get('/api/chat/unread/count', auth, (req,res) => {
  if(req.session.role==='superadmin'){
    const rows = db.prepare("SELECT taller_id,COUNT(*) as cnt FROM chat_mensajes WHERE remitente_role!='superadmin' AND leido=0 GROUP BY taller_id").all();
    res.json(rows);
  } else {
    const cnt = db.prepare("SELECT COUNT(*) as cnt FROM chat_mensajes WHERE taller_id=? AND remitente_role='superadmin' AND leido=0").get(req.session.tallerId);
    res.json({count:cnt?.cnt||0});
  }
});

app.get('*', (req,res) => res.sendFile(path.join(__dirname,'../public/index.html')));
app.listen(PORT, () => console.log(`Apuntoll en http://localhost:${PORT}`));
