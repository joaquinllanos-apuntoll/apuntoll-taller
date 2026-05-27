const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { run, get, all, initDB, nextNum } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, '../public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'apuntoll_2024',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 24*60*60*1000 }
}));

const auth   = (req,res,next) => req.session?.userId ? next() : res.status(401).json({error:'No autorizado'});
const isSA   = (req,res,next) => req.session?.role==='superadmin' ? next() : res.status(403).json({error:'Solo superadmin'});
const isAdm  = (req,res,next) => ['superadmin','admin'].includes(req.session?.role) ? next() : res.status(403).json({error:'Solo admin'});
const isTaller=(req,res,next) => ['superadmin','admin','operario'].includes(req.session?.role) ? next() : res.status(403).json({error:'No autorizado'});

// AUTH
app.post('/api/login', async (req,res) => {
  try {
    const {email,password} = req.body;
    if(!email||!password) return res.json({ok:false,error:'Completá todos los campos'});
    const user = await get('SELECT * FROM users WHERE email=?',[email.toLowerCase().trim()]);
    if(!user||!bcrypt.compareSync(password,user.password)) return res.json({ok:false,error:'Email o contraseña incorrectos'});
    if(user.role!=='superadmin'){
      const t = await get('SELECT * FROM talleres WHERE id=?',[user.taller_id]);
      if(!t||t.activo===0) return res.json({ok:false,error:'Cuenta suspendida.'});
      if(t.suscripcion_hasta && t.suscripcion_hasta < new Date().toISOString().split('T')[0])
        return res.json({ok:false,error:'Suscripción vencida.'});
    }
    await run('UPDATE users SET last_login=? WHERE id=?',[new Date().toISOString(),user.id]);
    req.session.userId=user.id; req.session.role=user.role;
    req.session.tallerId=user.taller_id; req.session.nombre=user.nombre;
    res.json({ok:true,role:user.role,nombre:user.nombre});
  } catch(e){res.json({ok:false,error:'Error interno'});}
});
app.post('/api/logout',(req,res)=>{req.session.destroy();res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({userId:req.session.userId,role:req.session.role,tallerId:req.session.tallerId,nombre:req.session.nombre}));

// REGISTRO
app.post('/api/registro', async (req,res) => {
  try {
    const {nombre,email,password,telefono,direccion,nombre_dueno,dni_dueno} = req.body;
    if(!nombre||!email||!password) return res.json({ok:false,error:'Faltan datos obligatorios'});
    if(password.length<6) return res.json({ok:false,error:'Contraseña mínimo 6 caracteres'});
    if(await get('SELECT id FROM users WHERE email=?',[email.toLowerCase()])) return res.json({ok:false,error:'Email ya registrado'});
    const tid=uuidv4();
    await run('INSERT INTO talleres (id,nombre,email,telefono,direccion,nombre_dueno,dni_dueno,activo,pendiente,created_at) VALUES (?,?,?,?,?,?,?,0,1,?)',
      [tid,nombre,email.toLowerCase(),telefono||'',direccion||'',nombre_dueno||'',dni_dueno||'',new Date().toISOString()]);
    await run('INSERT INTO users (id,nombre,email,password,role,taller_id,created_at) VALUES (?,?,?,?,?,?,?)',
      [uuidv4(),nombre_dueno||nombre,email.toLowerCase(),bcrypt.hashSync(password,10),'admin',tid,new Date().toISOString()]);
    res.json({ok:true});
  } catch(e){res.json({ok:false,error:'Error: '+e.message});}
});

// SUPERADMIN TALLERES
app.get('/api/admin/talleres', isSA, async (req,res) => {
  try {
    const ts = await all(`SELECT t.*,(SELECT COUNT(*) FROM vehiculos WHERE taller_id=t.id) as vehiculos,(SELECT last_login FROM users WHERE taller_id=t.id AND role='admin' ORDER BY last_login DESC LIMIT 1) as ultimo_acceso FROM talleres t ORDER BY t.created_at DESC`);
    res.json(ts);
  } catch(e){res.json([]);}
});
app.post('/api/admin/talleres', isSA, async (req,res) => {
  try {
    const {nombre,email,password,telefono,direccion,nombre_dueno,dni_dueno,suscripcion_hasta} = req.body;
    if(!nombre||!email||!password) return res.json({ok:false,error:'Faltan datos'});
    if(await get('SELECT id FROM users WHERE email=?',[email.toLowerCase()])) return res.json({ok:false,error:'Email ya registrado'});
    const tid=uuidv4();
    await run('INSERT INTO talleres (id,nombre,email,telefono,direccion,nombre_dueno,dni_dueno,activo,pendiente,suscripcion_hasta,created_at) VALUES (?,?,?,?,?,?,?,1,0,?,?)',
      [tid,nombre,email.toLowerCase(),telefono||'',direccion||'',nombre_dueno||'',dni_dueno||'',suscripcion_hasta||'',new Date().toISOString()]);
    await run('INSERT INTO users (id,nombre,email,password,role,taller_id,created_at) VALUES (?,?,?,?,?,?,?)',
      [uuidv4(),nombre_dueno||nombre,email.toLowerCase(),bcrypt.hashSync(password,10),'admin',tid,new Date().toISOString()]);
    res.json({ok:true});
  } catch(e){res.json({ok:false,error:e.message});}
});
app.put('/api/admin/talleres/:id', isSA, async (req,res) => {
  const {nombre,email,telefono,direccion,nombre_dueno,dni_dueno,activo,pendiente,suscripcion_hasta} = req.body;
  await run('UPDATE talleres SET nombre=?,email=?,telefono=?,direccion=?,nombre_dueno=?,dni_dueno=?,activo=?,pendiente=?,suscripcion_hasta=? WHERE id=?',
    [nombre,email,telefono||'',direccion||'',nombre_dueno||'',dni_dueno||'',activo?1:0,pendiente?1:0,suscripcion_hasta||'',req.params.id]);
  res.json({ok:true});
});
app.put('/api/admin/talleres/:id/toggle', isSA, async (req,res) => {
  const t = await get('SELECT * FROM talleres WHERE id=?',[req.params.id]);
  if(!t) return res.json({ok:false});
  await run('UPDATE talleres SET activo=? WHERE id=?',[t.activo?0:1,t.id]);
  res.json({ok:true,activo:!t.activo});
});
app.put('/api/admin/talleres/:id/aprobar', isSA, async (req,res) => {
  await run('UPDATE talleres SET activo=1,pendiente=0,suscripcion_hasta=? WHERE id=?',[req.body.suscripcion_hasta||'',req.params.id]);
  res.json({ok:true});
});
app.put('/api/admin/talleres/:id/password', isSA, async (req,res) => {
  const {password} = req.body;
  if(!password||password.length<4) return res.json({ok:false,error:'Contraseña muy corta'});
  await run('UPDATE users SET password=? WHERE taller_id=? AND role=?',[bcrypt.hashSync(password,10),req.params.id,'admin']);
  res.json({ok:true});
});
app.delete('/api/admin/talleres/:id', isSA, async (req,res) => {
  const id=req.params.id;
  for(const t of ['movimientos','gastos_fijos','ordenes','presupuestos','ingresos','vehiculos','clientes','users','alertas','chat_mensajes','contadores'])
    await run(`DELETE FROM ${t} WHERE taller_id=?`,[id]);
  await run('DELETE FROM talleres WHERE id=?',[id]);
  res.json({ok:true});
});
app.get('/api/admin/talleres/:id/users', isSA, async (req,res) => {
  res.json(await all('SELECT id,nombre,email,role,last_login,created_at FROM users WHERE taller_id=?',[req.params.id]));
});
app.put('/api/admin/perfil', isSA, async (req,res) => {
  const {nombre,email,password} = req.body;
  if(email){const ex=await get('SELECT id FROM users WHERE email=? AND id!=?',[email.toLowerCase(),req.session.userId]);if(ex)return res.json({ok:false,error:'Email ya en uso'});await run('UPDATE users SET nombre=?,email=? WHERE id=?',[nombre||'Super Admin',email.toLowerCase(),req.session.userId]);}
  if(password&&password.length>=4) await run('UPDATE users SET password=? WHERE id=?',[bcrypt.hashSync(password,10),req.session.userId]);
  res.json({ok:true});
});
app.get('/api/admin/movimientos', isSA, async (req,res) => res.json(await all('SELECT * FROM movimientos_admin ORDER BY fecha DESC')));
app.post('/api/admin/movimientos', isSA, async (req,res) => {
  await run('INSERT INTO movimientos_admin (id,tipo,fecha,categoria,monto,descripcion,taller_id,created_at) VALUES (?,?,?,?,?,?,?,?)',
    [uuidv4(),req.body.tipo,req.body.fecha,req.body.categoria||'suscripcion',parseFloat(req.body.monto),req.body.descripcion||'',req.body.taller_id||'',new Date().toISOString()]);
  res.json({ok:true});
});
app.delete('/api/admin/movimientos/:id', isSA, async (req,res) => {await run('DELETE FROM movimientos_admin WHERE id=?',[req.params.id]);res.json({ok:true});});

// TALLER USUARIOS
app.get('/api/taller/users', isAdm, async (req,res) => res.json(await all('SELECT id,nombre,email,role,last_login,created_at FROM users WHERE taller_id=?',[req.session.tallerId])));
app.post('/api/taller/users', isAdm, async (req,res) => {
  const {nombre,email,password,role} = req.body;
  if(!nombre||!email||!password) return res.json({ok:false,error:'Faltan datos'});
  if(await get('SELECT id FROM users WHERE email=?',[email.toLowerCase()])) return res.json({ok:false,error:'Email ya registrado'});
  await run('INSERT INTO users (id,nombre,email,password,role,taller_id,created_at) VALUES (?,?,?,?,?,?,?)',
    [uuidv4(),nombre,email.toLowerCase(),bcrypt.hashSync(password,10),role||'operario',req.session.tallerId,new Date().toISOString()]);
  res.json({ok:true});
});
app.put('/api/taller/users/:id', isAdm, async (req,res) => {
  const {nombre,email,password} = req.body;
  const u = await get('SELECT * FROM users WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);
  if(!u) return res.json({ok:false,error:'No encontrado'});
  await run('UPDATE users SET nombre=?,email=? WHERE id=?',[nombre||u.nombre,(email||u.email).toLowerCase(),req.params.id]);
  if(password&&password.length>=4) await run('UPDATE users SET password=? WHERE id=?',[bcrypt.hashSync(password,10),req.params.id]);
  res.json({ok:true});
});
app.delete('/api/taller/users/:id', isAdm, async (req,res) => {
  await run("DELETE FROM users WHERE id=? AND taller_id=? AND role!='admin'",[req.params.id,req.session.tallerId]);
  res.json({ok:true});
});
app.put('/api/taller/perfil', auth, async (req,res) => {
  const {nombre,email,password} = req.body;
  if(email){const ex=await get('SELECT id FROM users WHERE email=? AND id!=?',[email.toLowerCase(),req.session.userId]);if(ex)return res.json({ok:false,error:'Email ya en uso'});await run('UPDATE users SET nombre=?,email=? WHERE id=?',[nombre||'',email.toLowerCase(),req.session.userId]);}
  if(password&&password.length>=4) await run('UPDATE users SET password=? WHERE id=?',[bcrypt.hashSync(password,10),req.session.userId]);
  res.json({ok:true});
});

// TALLER INFO
app.get('/api/taller/info', auth, async (req,res) => {
  if(req.session.role==='superadmin') return res.json({nombre:'Apuntoll Admin',email:'',color_fondo:'#f0f0f0',color_nav:'#111111',logo:''});
  res.json(await get('SELECT * FROM talleres WHERE id=?',[req.session.tallerId])||{});
});
app.put('/api/taller/personalizacion', isAdm, async (req,res) => {
  await run('UPDATE talleres SET color_fondo=?,color_nav=?,logo=? WHERE id=?',
    [req.body.color_fondo||'#f0f0f0',req.body.color_nav||'#111111',req.body.logo||'',req.session.tallerId]);
  res.json({ok:true});
});

// CLIENTES
app.get('/api/clientes', isTaller, async (req,res) => res.json(await all('SELECT * FROM clientes WHERE taller_id=? ORDER BY nombre',[req.session.tallerId])));
app.post('/api/clientes', isTaller, async (req,res) => {
  const {nombre,telefono,email,dni,direccion,patentes} = req.body;
  if(!nombre) return res.json({ok:false,error:'El nombre es obligatorio'});
  const id=uuidv4();
  await run('INSERT INTO clientes (id,taller_id,nombre,telefono,email,dni,direccion,patentes,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [id,req.session.tallerId,nombre,telefono||'',email||'',dni||'',direccion||'',patentes||'',new Date().toISOString()]);
  if(patentes){
    for(const pat of patentes.split(',').map(p=>p.trim().toUpperCase()).filter(Boolean)){
      const v=await get('SELECT id FROM vehiculos WHERE patente=? AND taller_id=?',[pat,req.session.tallerId]);
      if(!v) await run('INSERT INTO vehiculos (id,taller_id,patente,cliente_id,created_at) VALUES (?,?,?,?,?)',[uuidv4(),req.session.tallerId,pat,id,new Date().toISOString()]);
      else await run('UPDATE vehiculos SET cliente_id=? WHERE id=?',[id,v.id]);
    }
  }
  res.json({ok:true,id});
});
app.put('/api/clientes/:id', isTaller, async (req,res) => {
  const {nombre,telefono,email,dni,direccion} = req.body;
  await run('UPDATE clientes SET nombre=?,telefono=?,email=?,dni=?,direccion=? WHERE id=? AND taller_id=?',
    [nombre,telefono||'',email||'',dni||'',direccion||'',req.params.id,req.session.tallerId]);
  res.json({ok:true});
});
app.delete('/api/clientes/:id', isTaller, async (req,res) => {await run('DELETE FROM clientes WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// VEHICULOS
app.get('/api/vehiculos', isTaller, async (req,res) => {
  res.json(await all('SELECT v.*,c.nombre as cliente_nombre,c.telefono as cliente_tel FROM vehiculos v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.taller_id=? ORDER BY v.patente',[req.session.tallerId]));
});
app.get('/api/vehiculos/:patente', isTaller, async (req,res) => {
  const v = await get('SELECT v.*,c.nombre as cliente_nombre,c.telefono as cliente_tel,c.email as cliente_email,c.dni as cliente_dni,c.id as cliente_id_real FROM vehiculos v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.patente=? AND v.taller_id=?',[req.params.patente.toUpperCase(),req.session.tallerId]);
  if(!v) return res.json(null);
  v.ingresos = await all('SELECT * FROM ingresos WHERE patente=? AND taller_id=? ORDER BY fecha DESC',[req.params.patente.toUpperCase(),req.session.tallerId]);
  v.ordenes  = await all('SELECT * FROM ordenes WHERE patente=? AND taller_id=? ORDER BY fecha DESC',[req.params.patente.toUpperCase(),req.session.tallerId]);
  res.json(v);
});
app.put('/api/vehiculos/:id', isTaller, async (req,res) => {
  await run('UPDATE vehiculos SET marca=?,modelo=?,anio=?,cliente_id=? WHERE id=? AND taller_id=?',
    [req.body.marca||'',req.body.modelo||'',req.body.anio||'',req.body.cliente_id||'',req.params.id,req.session.tallerId]);
  res.json({ok:true});
});

// INGRESOS
app.get('/api/ingresos', isTaller, async (req,res) => res.json(await all('SELECT * FROM ingresos WHERE taller_id=? ORDER BY fecha DESC,created_at DESC LIMIT 100',[req.session.tallerId])));
app.post('/api/ingresos', isTaller, async (req,res) => {
  try {
    const {patente,fecha,marca,modelo,anio,km,cliente_id,estado,aceite,refrigerante,frenos,liq_frenos,trabajos,obs,fotos} = req.body;
    if(!patente||!fecha||!trabajos) return res.json({ok:false,error:'Faltan datos obligatorios'});
    const pat=patente.toUpperCase().trim();const id=uuidv4();
    const num = await nextNum(req.session.tallerId,'recepcion');
    await run('INSERT INTO ingresos (id,taller_id,numero,patente,fecha,marca,modelo,anio,km,cliente_id,estado,aceite,refrigerante,frenos,liq_frenos,trabajos,obs,fotos,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [id,req.session.tallerId,num,pat,fecha,marca||'',modelo||'',anio||'',km||0,cliente_id||'',estado||'bueno',aceite||'ok',refrigerante||'ok',frenos||'ok',liq_frenos||'ok',trabajos,obs||'',JSON.stringify(fotos||[]),new Date().toISOString()]);
    const v = await get('SELECT id FROM vehiculos WHERE patente=? AND taller_id=?',[pat,req.session.tallerId]);
    if(!v) await run('INSERT INTO vehiculos (id,taller_id,patente,marca,modelo,anio,cliente_id,ultimo_km,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [uuidv4(),req.session.tallerId,pat,marca||'',modelo||'',anio||'',cliente_id||'',km||0,new Date().toISOString()]);
    else await run('UPDATE vehiculos SET marca=COALESCE(NULLIF(?,\'\'),marca),modelo=COALESCE(NULLIF(?,\'\'),modelo),anio=COALESCE(NULLIF(?,\'\'),anio),cliente_id=COALESCE(NULLIF(?,\'\'),cliente_id),ultimo_km=? WHERE patente=? AND taller_id=?',
      [marca||'',modelo||'',anio||'',cliente_id||'',km||0,pat,req.session.tallerId]);
    res.json({ok:true,id,numero:num});
  } catch(e){res.json({ok:false,error:e.message});}
});
app.put('/api/ingresos/:id', isTaller, async (req,res) => {
  const {fecha,marca,modelo,anio,km,cliente_id,estado,aceite,refrigerante,frenos,liq_frenos,trabajos,obs} = req.body;
  await run('UPDATE ingresos SET fecha=?,marca=?,modelo=?,anio=?,km=?,cliente_id=?,estado=?,aceite=?,refrigerante=?,frenos=?,liq_frenos=?,trabajos=?,obs=? WHERE id=? AND taller_id=?',
    [fecha,marca||'',modelo||'',anio||'',km||0,cliente_id||'',estado||'bueno',aceite||'ok',refrigerante||'ok',frenos||'ok',liq_frenos||'ok',trabajos,obs||'',req.params.id,req.session.tallerId]);
  res.json({ok:true});
});
app.delete('/api/ingresos/:id', isTaller, async (req,res) => {await run('DELETE FROM ingresos WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// ORDENES
app.get('/api/ordenes', isTaller, async (req,res) => res.json(await all('SELECT * FROM ordenes WHERE taller_id=? ORDER BY fecha DESC,created_at DESC',[req.session.tallerId])));
app.post('/api/ordenes', isTaller, async (req,res) => {
  try {
    const {patente,fecha,tecnico,estado,trabajos,items_mano_obra,items_repuestos_taller,items_repuestos_externos,checklist,km_egreso,mano_obra,costo_repuestos_taller,costo_repuestos_externos,total,proximo_aceite,aceite_usado,obs} = req.body;
    if(!patente||!fecha||!trabajos) return res.json({ok:false,error:'Faltan datos'});
    const pat=patente.toUpperCase().trim();const id=uuidv4();
    const num = await nextNum(req.session.tallerId,'ot');
    await run('INSERT INTO ordenes (id,taller_id,numero,patente,fecha,tecnico,estado,trabajos,items_mano_obra,items_repuestos_taller,items_repuestos_externos,checklist,km_egreso,mano_obra,costo_repuestos_taller,costo_repuestos_externos,total,proximo_aceite,aceite_usado,obs,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [id,req.session.tallerId,num,pat,fecha,tecnico||'',estado||'abierta',trabajos,JSON.stringify(items_mano_obra||[]),JSON.stringify(items_repuestos_taller||[]),JSON.stringify(items_repuestos_externos||[]),JSON.stringify(checklist||{}),km_egreso||0,mano_obra||0,costo_repuestos_taller||0,costo_repuestos_externos||0,total||0,proximo_aceite||0,aceite_usado||'',obs||'',new Date().toISOString()]);
    if(km_egreso) await run('UPDATE vehiculos SET ultimo_km=? WHERE patente=? AND taller_id=?',[km_egreso,pat,req.session.tallerId]);
    if(proximo_aceite) await run('UPDATE vehiculos SET proximo_aceite=? WHERE patente=? AND taller_id=?',[proximo_aceite,pat,req.session.tallerId]);
    const totalIngreso=(mano_obra||0)+(costo_repuestos_taller||0);
    if(totalIngreso>0) await run('INSERT INTO movimientos (id,taller_id,tipo,fecha,categoria,monto,descripcion,orden_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [uuidv4(),req.session.tallerId,'ingreso',fecha,'mano_obra',totalIngreso,'OT N°'+num+' — '+pat,id,new Date().toISOString()]);
    res.json({ok:true,id,numero:num});
  } catch(e){res.json({ok:false,error:e.message});}
});
app.put('/api/ordenes/:id', isTaller, async (req,res) => {
  const {estado,tecnico,trabajos,items_mano_obra,items_repuestos_taller,items_repuestos_externos,checklist,km_egreso,mano_obra,costo_repuestos_taller,costo_repuestos_externos,total,proximo_aceite,aceite_usado,obs} = req.body;
  await run('UPDATE ordenes SET estado=?,tecnico=?,trabajos=?,items_mano_obra=?,items_repuestos_taller=?,items_repuestos_externos=?,checklist=?,km_egreso=?,mano_obra=?,costo_repuestos_taller=?,costo_repuestos_externos=?,total=?,proximo_aceite=?,aceite_usado=?,obs=? WHERE id=? AND taller_id=?',
    [estado,tecnico||'',trabajos,JSON.stringify(items_mano_obra||[]),JSON.stringify(items_repuestos_taller||[]),JSON.stringify(items_repuestos_externos||[]),JSON.stringify(checklist||{}),km_egreso||0,mano_obra||0,costo_repuestos_taller||0,costo_repuestos_externos||0,total||0,proximo_aceite||0,aceite_usado||'',obs||'',req.params.id,req.session.tallerId]);
  res.json({ok:true});
});
app.delete('/api/ordenes/:id', isTaller, async (req,res) => {await run('DELETE FROM ordenes WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// PRESUPUESTOS
app.get('/api/presupuestos', isTaller, async (req,res) => res.json(await all('SELECT * FROM presupuestos WHERE taller_id=? ORDER BY fecha DESC',[req.session.tallerId])));
app.post('/api/presupuestos', isTaller, async (req,res) => {
  const {patente,fecha,fecha_caducidad,cliente_id,descripcion,items,total,obs} = req.body;
  if(!patente||!fecha) return res.json({ok:false,error:'Faltan datos'});
  const id=uuidv4();const num=await nextNum(req.session.tallerId,'presupuesto');
  await run('INSERT INTO presupuestos (id,taller_id,numero,patente,fecha,fecha_caducidad,cliente_id,descripcion,items,total,obs,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
    [id,req.session.tallerId,num,patente.toUpperCase(),fecha,fecha_caducidad||'',cliente_id||'',descripcion||'',JSON.stringify(items||[]),total||0,obs||'',new Date().toISOString()]);
  res.json({ok:true,id,numero:num});
});
app.put('/api/presupuestos/:id', isTaller, async (req,res) => {
  await run('UPDATE presupuestos SET patente=?,fecha=?,fecha_caducidad=?,cliente_id=?,descripcion=?,items=?,total=?,obs=? WHERE id=? AND taller_id=?',
    [req.body.patente||'',req.body.fecha,req.body.fecha_caducidad||'',req.body.cliente_id||'',req.body.descripcion||'',JSON.stringify(req.body.items||[]),req.body.total||0,req.body.obs||'',req.params.id,req.session.tallerId]);
  res.json({ok:true});
});
app.delete('/api/presupuestos/:id', isTaller, async (req,res) => {await run('DELETE FROM presupuestos WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// MOVIMIENTOS
app.get('/api/movimientos', isTaller, async (req,res) => res.json(await all('SELECT * FROM movimientos WHERE taller_id=? ORDER BY fecha DESC,created_at DESC',[req.session.tallerId])));
app.post('/api/movimientos', isTaller, async (req,res) => {
  await run('INSERT INTO movimientos (id,taller_id,tipo,fecha,categoria,monto,descripcion,orden_id,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [uuidv4(),req.session.tallerId,req.body.tipo,req.body.fecha,req.body.categoria||'otros',parseFloat(req.body.monto),req.body.descripcion||'',req.body.orden_id||'',new Date().toISOString()]);
  res.json({ok:true});
});
app.delete('/api/movimientos/:id', isTaller, async (req,res) => {await run('DELETE FROM movimientos WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// GASTOS FIJOS
app.get('/api/gastos-fijos', isAdm, async (req,res) => res.json(await all('SELECT * FROM gastos_fijos WHERE taller_id=? ORDER BY nombre',[req.session.tallerId])));
app.post('/api/gastos-fijos', isAdm, async (req,res) => {
  const {nombre,monto,categoria,periodo_tipo,periodo_valor,proxima_fecha} = req.body;
  await run('INSERT INTO gastos_fijos (id,taller_id,nombre,monto,categoria,periodo_tipo,periodo_valor,proxima_fecha,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
    [uuidv4(),req.session.tallerId,nombre,parseFloat(monto),categoria||'otros',periodo_tipo||'mensual',periodo_valor||1,proxima_fecha||'',new Date().toISOString()]);
  res.json({ok:true});
});
app.put('/api/gastos-fijos/:id', isAdm, async (req,res) => {
  const {nombre,monto,categoria,periodo_tipo,periodo_valor,proxima_fecha} = req.body;
  await run('UPDATE gastos_fijos SET nombre=?,monto=?,categoria=?,periodo_tipo=?,periodo_valor=?,proxima_fecha=? WHERE id=? AND taller_id=?',
    [nombre,parseFloat(monto),categoria||'otros',periodo_tipo||'mensual',periodo_valor||1,proxima_fecha||'',req.params.id,req.session.tallerId]);
  res.json({ok:true});
});
app.delete('/api/gastos-fijos/:id', isAdm, async (req,res) => {await run('DELETE FROM gastos_fijos WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// ALERTAS
app.get('/api/alertas', isTaller, async (req,res) => res.json(await all('SELECT * FROM alertas WHERE taller_id=? AND resuelta=0 ORDER BY fecha_alerta ASC',[req.session.tallerId])));
app.post('/api/alertas', isTaller, async (req,res) => {
  const {patente,telefono_dueno,tipo,fecha_alerta,km_alerta,aceite_usado,filtros_cambiados,notas} = req.body;
  await run('INSERT INTO alertas (id,taller_id,patente,telefono_dueno,tipo,fecha_alerta,km_alerta,aceite_usado,filtros_cambiados,notas,resuelta,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?)',
    [uuidv4(),req.session.tallerId,patente.toUpperCase(),telefono_dueno||'',tipo||'fecha',fecha_alerta||'',km_alerta||0,aceite_usado||'',filtros_cambiados||'',notas||'',new Date().toISOString()]);
  res.json({ok:true});
});
app.put('/api/alertas/:id', isTaller, async (req,res) => {
  await run('UPDATE alertas SET resuelta=?,aceite_usado=?,filtros_cambiados=?,notas=?,telefono_dueno=? WHERE id=? AND taller_id=?',
    [req.body.resuelta?1:0,req.body.aceite_usado||'',req.body.filtros_cambiados||'',req.body.notas||'',req.body.telefono_dueno||'',req.params.id,req.session.tallerId]);
  res.json({ok:true});
});
app.delete('/api/alertas/:id', isTaller, async (req,res) => {await run('DELETE FROM alertas WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// GUIA KM
app.get('/api/guiakm', isTaller, async (req,res) => res.json(await all('SELECT * FROM guia_km WHERE taller_id=? ORDER BY tipo',[req.session.tallerId])));
app.post('/api/guiakm', isTaller, async (req,res) => {await run('INSERT INTO guia_km (id,taller_id,tipo,km) VALUES (?,?,?,?)',[uuidv4(),req.session.tallerId,req.body.tipo,req.body.km]);res.json({ok:true});});
app.delete('/api/guiakm/:id', isTaller, async (req,res) => {await run('DELETE FROM guia_km WHERE id=? AND taller_id=?',[req.params.id,req.session.tallerId]);res.json({ok:true});});

// CHAT
app.get('/api/chat/:taller_id', auth, async (req,res) => {
  const tid=req.session.role==='superadmin'?req.params.taller_id:req.session.tallerId;
  res.json(await all('SELECT * FROM chat_mensajes WHERE taller_id=? ORDER BY created_at ASC',[tid]));
  if(req.session.role==='superadmin') await run("UPDATE chat_mensajes SET leido=1 WHERE taller_id=? AND remitente_role!='superadmin'",[tid]);
  else await run("UPDATE chat_mensajes SET leido=1 WHERE taller_id=? AND remitente_role='superadmin'",[tid]);
});
app.post('/api/chat/:taller_id', auth, async (req,res) => {
  const tid=req.session.role==='superadmin'?req.params.taller_id:req.session.tallerId;
  await run('INSERT INTO chat_mensajes (id,taller_id,remitente_id,remitente_nombre,remitente_role,mensaje,leido,created_at) VALUES (?,?,?,?,?,?,0,?)',
    [uuidv4(),tid,req.session.userId,req.session.nombre,req.session.role,req.body.mensaje,new Date().toISOString()]);
  res.json({ok:true});
});
app.get('/api/chat/unread/count', auth, async (req,res) => {
  if(req.session.role==='superadmin'){
    res.json(await all("SELECT taller_id,COUNT(*) as cnt FROM chat_mensajes WHERE remitente_role!='superadmin' AND leido=0 GROUP BY taller_id"));
  } else {
    const r=await get("SELECT COUNT(*) as cnt FROM chat_mensajes WHERE taller_id=? AND remitente_role='superadmin' AND leido=0",[req.session.tallerId]);
    res.json({count:r?.cnt||0});
  }
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'../public/index.html')));

// Arrancar servidor después de inicializar DB
initDB().then(()=>{
  app.listen(PORT,()=>console.log(`Apuntoll en http://localhost:${PORT}`));
}).catch(e=>{
  console.error('Error iniciando DB:',e);
  process.exit(1);
});

