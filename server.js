const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'skynoak_super_secret_key_change_me';
const USERS_FILE = path.join(__dirname, 'users.json');
const POSTS_FILE = path.join(__dirname, 'posts.json');

app.use(cors());
app.use(express.json());

// ---------- Работа с файлами ----------
function readJSON(file) {
  try {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch { return []; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

// ---------- Инициализация админа ----------
function initAdmin() {
  const users = readJSON(USERS_FILE);
  if (!users.find(u => u.username === 'SkyMonder')) {
    const admin = {
      id: 'admin_' + Date.now(),
      username: 'SkyMonder',
      password: '',             // пустой пароль, задаётся при первом входе
      isAdmin: true,
      avatarLetter: 'S',
      createdAt: new Date().toISOString()
    };
    users.push(admin);
    writeJSON(USERS_FILE, users);
    console.log('✅ Администратор SkyMonder создан (без пароля)');
  }
}
initAdmin();

// ---------- Middleware ----------
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Нет токена' });
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Неверный токен' });
  }
}

// ===================== API =====================
// Регистрация
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || username.length < 2) return res.status(400).json({ error: 'Имя от 2 символов' });
  if (!password || password.length < 3) return res.status(400).json({ error: 'Пароль от 3 символов' });
  const users = readJSON(USERS_FILE);
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Имя занято' });
  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: 'user_' + Date.now(),
    username,
    password: hashed,
    isAdmin: false,
    avatarLetter: username.charAt(0).toUpperCase(),
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  writeJSON(USERS_FILE, users);
  const token = jwt.sign({ id: newUser.id, username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: newUser.id, username, avatarLetter: newUser.avatarLetter, isAdmin: false } });
});

// Вход
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Неверное имя или пароль' });
  // Админ без пароля
  if (user.password === '' && password === '') {
    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: { id: user.id, username, avatarLetter: user.avatarLetter, isAdmin: user.isAdmin }, firstLogin: true });
  }
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Неверное имя или пароль' });
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username, avatarLetter: user.avatarLetter, isAdmin: user.isAdmin } });
});

// Профиль текущего пользователя
app.get('/api/profile', authMiddleware, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json({ id: user.id, username: user.username, avatarLetter: user.avatarLetter, isAdmin: user.isAdmin });
});

// Смена пароля
app.put('/api/profile/password', authMiddleware, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 3) return res.status(400).json({ error: 'Пароль от 3 символов' });
  const users = readJSON(USERS_FILE);
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Пользователь не найден' });
  users[idx].password = await bcrypt.hash(newPassword, 10);
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

// Получить все посты
app.get('/api/posts', (req, res) => {
  const posts = readJSON(POSTS_FILE);
  posts.sort((a, b) => b.timestamp - a.timestamp);
  // Определяем текущего пользователя по токену (если есть)
  let userId = null;
  const authHeader = req.headers.authorization;
  if (authHeader) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      userId = decoded.id;
    } catch {}
  }
  const enriched = posts.map(post => ({
    ...post,
    likedByMe: userId ? post.likes.includes(userId) : false,
    likesCount: post.likes.length
  }));
  res.json(enriched);
});

// Создать пост (авторизация)
app.post('/api/posts', authMiddleware, (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Пост не может быть пустым' });
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  const newPost = {
    id: 'post_' + Date.now(),
    userId: user.id,
    username: user.username,
    avatarLetter: user.avatarLetter,
    content: content.trim(),
    timestamp: Date.now(),
    likes: []
  };
  const posts = readJSON(POSTS_FILE);
  posts.push(newPost);
  writeJSON(POSTS_FILE, posts);
  res.status(201).json(newPost);
});

// Удалить пост (только автор)
app.delete('/api/posts/:id', authMiddleware, (req, res) => {
  const posts = readJSON(POSTS_FILE);
  const idx = posts.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Пост не найден' });
  if (posts[idx].userId !== req.user.id) return res.status(403).json({ error: 'Нельзя удалить чужой пост' });
  posts.splice(idx, 1);
  writeJSON(POSTS_FILE, posts);
  res.json({ success: true });
});

// Лайк / анлайк
app.post('/api/like/:postId', authMiddleware, (req, res) => {
  const posts = readJSON(POSTS_FILE);
  const post = posts.find(p => p.id === req.params.postId);
  if (!post) return res.status(404).json({ error: 'Пост не найден' });
  const userId = req.user.id;
  const index = post.likes.indexOf(userId);
  if (index === -1) {
    post.likes.push(userId);
  } else {
    post.likes.splice(index, 1);
  }
  writeJSON(POSTS_FILE, posts);
  res.json({ liked: index === -1, likesCount: post.likes.length });
});

// ===================== Раздача фронтенда =====================
// Если существует public/index.html – отдаём его, иначе встроенный HTML
const staticIndexPath = path.join(__dirname, 'public', 'index.html');

app.get('/', (req, res) => {
  if (fs.existsSync(staticIndexPath)) {
    res.sendFile(staticIndexPath);
  } else {
    res.send(EMBEDDED_HTML);
  }
});

// Любые другие маршруты, которых нет в API – отдаём index.html (для SPA)
app.get('*', (req, res) => {
  if (fs.existsSync(staticIndexPath)) {
    res.sendFile(staticIndexPath);
  } else {
    res.send(EMBEDDED_HTML);
  }
});

// ---------- Запуск ----------
app.listen(PORT, () => {
  console.log(`🚀 SkyNoak работает на http://localhost:${PORT}`);
});

// ===================== ВСТРОЕННЫЙ ФРОНТЕНД =====================
const EMBEDDED_HTML = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
  <title>SkyNoak — соцсеть будущего</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { background:#0a0a0a; color:#e0e0e0; font-family:'Segoe UI',system-ui,sans-serif; display:flex; justify-content:center; min-height:100vh; }
    #app { width:100%; max-width:650px; padding:0 12px; }
    .header { display:flex; align-items:center; justify-content:space-between; padding:16px 0; border-bottom:1px solid #222; position:sticky; top:0; background:rgba(10,10,10,0.9); backdrop-filter:blur(8px); z-index:10; }
    .logo { font-size:1.8rem; font-weight:800; background:linear-gradient(135deg,#1d9bf0,#a855f7); -webkit-background-clip:text; -webkit-text-fill-color:transparent; cursor:pointer; }
    .user-actions { display:flex; gap:10px; align-items:center; }
    .btn { background:#1d9bf0; color:white; border:none; padding:8px 18px; border-radius:20px; font-weight:600; cursor:pointer; transition:background .2s; font-size:.95rem; }
    .btn:hover { background:#1a8cd8; }
    .btn-outline { background:transparent; border:1px solid #333; color:#ccc; }
    .btn-outline:hover { background:#1a1a1a; border-color:#555; }
    .btn-small { padding:6px 14px; font-size:.85rem; }
    .profile-pic-small { width:36px; height:36px; border-radius:50%; background:#333; display:flex; align-items:center; justify-content:center; font-weight:bold; color:white; cursor:pointer; }
    .post-composer { background:#111; border:1px solid #222; border-radius:14px; padding:14px; margin-bottom:16px; }
    .composer-textarea { width:100%; background:#1a1a1a; border:1px solid #333; border-radius:12px; color:#e0e0e0; padding:12px; font-size:1rem; resize:vertical; min-height:80px; margin-bottom:10px; font-family:inherit; }
    .post { background:#111; border:1px solid #222; border-radius:14px; padding:14px; margin-bottom:12px; transition:border .2s; }
    .post:hover { border-color:#444; }
    .post-header { display:flex; align-items:center; gap:10px; margin-bottom:8px; }
    .post-avatar { width:40px; height:40px; border-radius:50%; background:#2563eb; display:flex; align-items:center; justify-content:center; font-weight:bold; color:white; font-size:1.1rem; }
    .post-user { font-weight:700; color:#f0f0f0; }
    .post-time { color:#777; font-size:0.8rem; }
    .post-content { margin-bottom:10px; white-space:pre-wrap; word-break:break-word; line-height:1.4; }
    .post-actions { display:flex; gap:18px; color:#888; font-size:.95rem; }
    .action-btn { background:none; border:none; color:#888; cursor:pointer; display:flex; align-items:center; gap:4px; font-size:.9rem; transition:color .2s; }
    .action-btn.liked { color:#e74c3c; }
    .action-btn:hover { color:#ccc; }
    .delete-btn { color:#c44; margin-left:auto; }
    .delete-btn:hover { color:#f55; }
    .modal { position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.75); backdrop-filter:blur(4px); display:flex; align-items:center; justify-content:center; z-index:100; }
    .modal-content { background:#1a1a1a; border:1px solid #333; border-radius:16px; padding:24px; width:90%; max-width:380px; }
    .modal-content h2 { margin-bottom:16px; color:#fff; }
    .input-field { width:100%; background:#111; border:1px solid #333; border-radius:10px; color:#fff; padding:10px 14px; margin-bottom:12px; font-size:1rem; }
    .error { color:#f87171; font-size:0.85rem; margin-bottom:8px; }
    .flex-row { display:flex; gap:8px; justify-content:flex-end; }
    .hidden { display:none !important; }
    .settings-box { background:#111; border:1px solid #222; border-radius:14px; padding:20px; margin:16px 0; }
    .settings-box label { display:block; margin-bottom:6px; color:#aaa; font-size:.9rem; }
    hr { border-color:#222; margin:16px 0; }
    .toast { position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:#1d9bf0; color:white; padding:10px 24px; border-radius:30px; font-weight:500; z-index:200; animation:fadeInOut 2s forwards; }
    @keyframes fadeInOut { 0% { opacity:0; bottom:10px; } 10% { opacity:1; bottom:20px; } 80% { opacity:1; } 100% { opacity:0; bottom:30px; } }
    a { color:#1d9bf0; text-decoration:none; }
    a:hover { text-decoration:underline; }
  </style>
</head>
<body>
<div id="app">
  <div class="header">
    <div class="logo" id="logoBtn">SkyNoak</div>
    <div class="user-actions" id="headerActions"></div>
  </div>
  <div id="mainContent"></div>
  <div id="toast" class="toast hidden"></div>
</div>
<script>
  const API = '/api';
  let token = localStorage.getItem('skynoak_token');
  let currentUser = null;

  function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg; t.classList.remove('hidden');
    setTimeout(() => t.classList.add('hidden'), 2000);
  }
  async function apiFetch(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const res = await fetch(url, { ...options, headers });
    if (res.status === 401) { logout(); throw new Error('Unauthorized'); }
    return res.json();
  }
  function saveToken(t) { token = t; localStorage.setItem('skynoak_token', t); }
  function logout() { token = null; localStorage.removeItem('skynoak_token'); currentUser = null; renderHeader(); renderFeed(); showToast('Вы вышли'); }

  async function loadProfile() {
    if (!token) return null;
    try { currentUser = await apiFetch(API+'/profile'); return currentUser; }
    catch { logout(); return null; }
  }

  async function renderHeader() {
    const h = document.getElementById('headerActions');
    if (currentUser) {
      h.innerHTML = '<span style="color:#aaa">@' + currentUser.username + '</span>' +
        '<div class="profile-pic-small" id="profileBtn">' + currentUser.avatarLetter + '</div>' +
        '<button class="btn btn-outline btn-small" id="logoutBtn">Выйти</button>';
      document.getElementById('profileBtn').onclick = renderProfile;
      document.getElementById('logoutBtn').onclick = logout;
    } else {
      h.innerHTML = '<button class="btn" id="loginBtn">Войти</button>';
      document.getElementById('loginBtn').onclick = showLoginModal;
    }
  }

  async function renderFeed() {
    const main = document.getElementById('mainContent');
    let posts = [];
    try { posts = await apiFetch(API+'/posts'); } catch { posts = []; }
    let html = '';
    if (currentUser) {
      html += '<div class="post-composer">' +
        '<textarea class="composer-textarea" id="newPostText" placeholder="Что нового?"></textarea>' +
        '<div class="composer-actions"><span></span><button class="btn" id="publishBtn">Опубликовать</button></div>' +
        '</div>';
    }
    if (posts.length === 0) html += '<p style="color:#666; text-align:center; margin-top:40px;">Пока нет постов.</p>';
    else posts.forEach(p => {
      const date = new Date(p.timestamp);
      const time = date.toLocaleString('ru-RU',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
      html += '<div class="post">' +
        '<div class="post-header"><div class="post-avatar">' + p.avatarLetter + '</div><div><span class="post-user">@' + p.username + '</span><span class="post-time">· ' + time + '</span></div>' +
        (currentUser && currentUser.id === p.userId ? '<button class="action-btn delete-btn" data-id="' + p.id + '">🗑️</button>' : '') +
        '</div><div class="post-content">' + escapeHtml(p.content) + '</div>' +
        '<div class="post-actions"><button class="action-btn like-btn ' + (p.likedByMe ? 'liked' : '') + '" data-id="' + p.id + '">❤️ <span>' + (p.likesCount || 0) + '</span></button></div>' +
        '</div>';
    });
    main.innerHTML = html;
    if (currentUser) {
      document.getElementById('publishBtn')?.addEventListener('click', publishPost);
      document.getElementById('newPostText')?.addEventListener('keydown', e => { if (e.key==='Enter'&&!e.shiftKey){e.preventDefault();publishPost();} });
    }
    document.querySelectorAll('.delete-btn').forEach(b => b.onclick = () => deletePost(b.dataset.id));
    document.querySelectorAll('.like-btn').forEach(b => b.onclick = () => toggleLike(b.dataset.id));
  }

  function escapeHtml(s) { return String(s).replace(/[&<>"]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[m]); }

  async function publishPost() {
    const text = document.getElementById('newPostText').value.trim();
    if (!text) return showToast('Напишите что-нибудь');
    await apiFetch(API+'/posts', { method:'POST', body:JSON.stringify({content:text}) });
    document.getElementById('newPostText').value = '';
    await renderFeed();
    showToast('Пост опубликован!');
  }
  async function deletePost(id) {
    await apiFetch(API+'/posts/'+id, { method:'DELETE' });
    await renderFeed();
    showToast('Пост удалён');
  }
  async function toggleLike(postId) {
    if (!currentUser) return showToast('Войдите, чтобы лайкать');
    await apiFetch(API+'/like/'+postId, { method:'POST' });
    await renderFeed();
  }

  function showLoginModal() {
    const modal = document.createElement('div'); modal.className='modal';
    modal.innerHTML = '<div class="modal-content"><h2>Вход в SkyNoak</h2><div id="loginError" class="error hidden"></div>' +
      '<input class="input-field" id="loginUsername" placeholder="Имя" value="SkyMonder">' +
      '<input class="input-field" id="loginPassword" type="password" placeholder="Пароль">' +
      '<div class="flex-row"><button class="btn btn-outline" id="closeModal">Отмена</button><button class="btn" id="loginSubmit">Войти</button></div>' +
      '<hr><p style="font-size:0.8rem;color:#aaa;">Нет аккаунта? <a href="#" id="toRegister">Создать</a></p></div>';
    document.body.appendChild(modal);
    document.getElementById('closeModal').onclick = ()=>modal.remove();
    document.getElementById('toRegister').onclick = (e)=>{e.preventDefault();modal.remove();showRegisterModal();};
    document.getElementById('loginSubmit').onclick = async ()=>{
      const u = document.getElementById('loginUsername').value.trim();
      const p = document.getElementById('loginPassword').value;
      try {
        const data = await apiFetch(API+'/login', {method:'POST', body:JSON.stringify({username:u, password:p})});
        saveToken(data.token); currentUser = data.user; modal.remove();
        if (data.firstLogin) { showToast('Добро пожаловать! Задайте пароль в профиле.'); renderProfile(); }
        else { await renderAll(); showToast('Вход выполнен!'); }
      } catch(e) { document.getElementById('loginError').textContent = 'Ошибка входа'; document.getElementById('loginError').classList.remove('hidden'); }
    };
    modal.onclick = e => { if(e.target===modal) modal.remove(); };
  }
  function showRegisterModal() {
    const modal = document.createElement('div'); modal.className='modal';
    modal.innerHTML = '<div class="modal-content"><h2>Регистрация</h2><div id="regError" class="error hidden"></div>' +
      '<input class="input-field" id="regUsername" placeholder="Имя"><input class="input-field" id="regPassword" type="password" placeholder="Пароль">' +
      '<div class="flex-row"><button class="btn btn-outline" id="closeReg">Отмена</button><button class="btn" id="regSubmit">Создать</button></div></div>';
    document.body.appendChild(modal);
    document.getElementById('closeReg').onclick = ()=>modal.remove();
    document.getElementById('regSubmit').onclick = async ()=>{
      const u = document.getElementById('regUsername').value.trim();
      const p = document.getElementById('regPassword').value;
      try {
        const data = await apiFetch(API+'/register', {method:'POST', body:JSON.stringify({username:u, password:p})});
        saveToken(data.token); currentUser = data.user; modal.remove();
        await renderAll(); showToast('Аккаунт создан!');
      } catch(e) { document.getElementById('regError').textContent = 'Ошибка регистрации'; document.getElementById('regError').classList.remove('hidden'); }
    };
    modal.onclick = e => { if(e.target===modal) modal.remove(); };
  }

  async function renderProfile() {
    if (!currentUser) return;
    const main = document.getElementById('mainContent');
    main.innerHTML = '<div class="settings-box"><h2>Профиль @' + currentUser.username + '</h2>' +
      '<p style="color:#aaa;">Администратор: ' + (currentUser.isAdmin ? 'Да' : 'Нет') + '</p>' +
      '<label>Новый пароль</label><input class="input-field" id="newPassword" type="password" placeholder="Минимум 3 символа">' +
      '<div><button class="btn" id="savePassword">Сохранить</button>' +
      '<button class="btn btn-outline btn-small" id="backBtn">← Назад</button></div>' +
      '<div id="profileMsg" style="margin-top:8px;color:#4ade80;" class="hidden"></div></div>';
    document.getElementById('savePassword').onclick = async ()=>{
      const pw = document.getElementById('newPassword').value;
      if (!pw || pw.length < 3) { document.getElementById('profileMsg').textContent='Минимум 3 символа'; document.getElementById('profileMsg').classList.remove('hidden'); return; }
      await apiFetch(API+'/profile/password', {method:'PUT', body:JSON.stringify({newPassword:pw})});
      document.getElementById('profileMsg').textContent='Пароль обновлён!'; document.getElementById('profileMsg').classList.remove('hidden');
      showToast('Пароль сохранён');
    };
    document.getElementById('backBtn').onclick = ()=>renderFeed();
  }

  async function renderAll() {
    await renderHeader();
    await renderFeed();
  }

  document.getElementById('logoBtn').addEventListener('click', ()=>renderFeed());

  (async ()=>{
    if (token) { const user = await loadProfile(); if (user) currentUser = user; }
    await renderAll();
  })();
</script>
</body>
</html>`;
