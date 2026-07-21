const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SQLITE_PATH = process.env.SQLITE_PATH
  ? path.resolve(process.env.SQLITE_PATH)
  : path.join(__dirname, 'delivery-db.sqlite');
const SEED_JSON_PATH = path.join(__dirname, 'delivery-db.json');
const APP_HTML_PATH = path.join(__dirname, 'delivery-system.html');
const PASSWORD_HASH_PREFIX = 'scrypt';
const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = '1234';
const sessions = new Map();

const db = new sqlite3.Database(SQLITE_PATH);

app.use(cors());
app.use(express.json());

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows);
    });
  });
}

async function transaction(work) {
  await run('BEGIN');
  try {
    const result = await work();
    await run('COMMIT');
    return result;
  } catch (error) {
    await run('ROLLBACK');
    throw error;
  }
}

function calculateSettlement(fare) {
  const fee100 = 100;
  // Keep fee16 key for backward compatibility with existing frontend payload shape.
  const fee16 = Math.round(fare * 0.033);
  return {
    fee100,
    fee16,
    final: fare - fee100 - fee16,
  };
}

function isPasswordHash(value) {
  return typeof value === 'string' && value.startsWith(`${PASSWORD_HASH_PREFIX}$`);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${PASSWORD_HASH_PREFIX}$${salt}$${derivedKey}`;
}

function verifyPassword(password, storedPassword) {
  if (!isPasswordHash(storedPassword)) {
    return false;
  }

  const [, salt, expectedKey] = storedPassword.split('$');
  const actualKey = crypto.scryptSync(password, salt, 64);
  const expectedBuffer = Buffer.from(expectedKey, 'hex');
  return expectedBuffer.length === actualKey.length && crypto.timingSafeEqual(expectedBuffer, actualKey);
}

function sendError(res, statusCode, message) {
  res.status(statusCode).json({ success: false, message });
}

function createSession(role, user) {
  const token = crypto.randomBytes(24).toString('hex');
  const session = {
    token,
    role,
    userId: user.id,
    username: user.username,
    branch_id: user.branch_id || null,
  };
  sessions.set(token, session);
  return session;
}

function getSessionFromRequest(req) {
  const authorization = req.headers.authorization || '';
  if (!authorization.startsWith('Bearer ')) {
    return null;
  }
  const token = authorization.slice('Bearer '.length).trim();
  return sessions.get(token) || null;
}

function requireSession(req, res) {
  const session = getSessionFromRequest(req);
  if (!session) {
    sendError(res, 401, '로그인이 필요합니다.');
    return null;
  }
  return session;
}

function requireRole(req, res, roles) {
  const session = requireSession(req, res);
  if (!session) {
    return null;
  }
  if (!roles.includes(session.role)) {
    sendError(res, 403, '권한이 없습니다.');
    return null;
  }
  return session;
}

function requireAdmin(req, res) {
  return requireRole(req, res, ['admin']);
}

function requireAdminOrSubAdmin(req, res) {
  return requireRole(req, res, ['admin', 'sub_admin']);
}

function buildStateForSession(session, state) {
  if (session.role === 'admin') {
    return {
      ...state,
      admins: state.admins,
    };
  }

  if (session.role === 'sub_admin') {
    const riders = state.riders.filter((rider) => rider.branch_id === session.branch_id);
    const riderIds = new Set(riders.map((rider) => rider.id));
    return {
      branches: state.branches,
      riders,
      subAdmins: state.subAdmins.filter((subAdmin) => subAdmin.branch_id === session.branch_id),
      deliveries: state.deliveries.filter((delivery) => riderIds.has(delivery.riderId)),
      withdrawals: state.withdrawals.filter((withdrawal) => riderIds.has(withdrawal.riderId)),
      deductionLogs: state.deductionLogs.filter((deduction) => riderIds.has(deduction.riderId)),
    };
  }

  const riders = state.riders.filter((rider) => rider.id === session.userId);
  return {
    branches: state.branches,
    riders,
    subAdmins: [],
    deliveries: state.deliveries.filter((delivery) => delivery.riderId === session.userId),
    withdrawals: state.withdrawals.filter((withdrawal) => withdrawal.riderId === session.userId),
    deductionLogs: state.deductionLogs.filter((deduction) => deduction.riderId === session.userId),
  };
}

function withErrorHandling(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (error) {
      console.error(error);
      if (!res.headersSent) {
        sendError(res, 500, '서버 오류가 발생했습니다.');
      }
    }
  };
}

function revokeSessionsForUser(role, userId) {
  for (const [token, session] of sessions.entries()) {
    if (session.role === role && session.userId === userId) {
      sessions.delete(token);
    }
  }
}

function readSeedData() {
  const defaultSeed = {
    admins: [
      {
        id: 1,
        username: DEFAULT_ADMIN_USERNAME,
        password: DEFAULT_ADMIN_PASSWORD,
        name: '시스템 관리자',
      },
    ],
    branches: [
      { id: 1, name: '강남점' },
      { id: 2, name: '강북점' },
    ],
    riders: [
      {
        id: 1,
        username: 'rider1',
        password: '1234',
        name: '김기사',
        balance: 150000,
        bank: '국민은행',
        account: '1234567890',
        branch_id: 1,
      },
      {
        id: 2,
        username: 'rider2',
        password: '1234',
        name: '이기사',
        balance: 280000,
        bank: '우리은행',
        account: '0987654321',
        branch_id: 1,
      },
    ],
    subAdmins: [
      {
        id: 1,
        username: 'branch1',
        password: '1234',
        company_name: '강남점 운영사',
        branch_id: 1,
      },
    ],
    deliveries: [
      { id: 1, riderId: 1, fare: 5000, fee100: 100, fee16: 80, final: 4820, status: 'completed' },
      { id: 2, riderId: 1, fare: 7000, fee100: 100, fee16: 112, final: 6788, status: 'completed' },
      { id: 3, riderId: 2, fare: 6000, fee100: 100, fee16: 96, final: 5804, status: 'completed' },
    ],
    withdrawals: [
      { id: 1, riderId: 1, amount: 100000, status: 'approved' },
      { id: 2, riderId: 2, amount: 150000, status: 'pending' },
    ],
    deductionLogs: [],
  };

  if (fs.existsSync(SEED_JSON_PATH)) {
    return { ...defaultSeed, ...JSON.parse(fs.readFileSync(SEED_JSON_PATH, 'utf8')) };
  }

  return defaultSeed;
}

async function migrateStoredPasswords() {
  const adminPasswords = await all('SELECT id, password FROM admins');
  for (const admin of adminPasswords) {
    if (!isPasswordHash(admin.password)) {
      await run('UPDATE admins SET password = ? WHERE id = ?', [hashPassword(admin.password), admin.id]);
    }
  }

  const riderPasswords = await all('SELECT id, password FROM riders');
  for (const rider of riderPasswords) {
    if (!isPasswordHash(rider.password)) {
      await run('UPDATE riders SET password = ? WHERE id = ?', [hashPassword(rider.password), rider.id]);
    }
  }

  const subAdminPasswords = await all('SELECT id, password FROM sub_admins');
  for (const subAdmin of subAdminPasswords) {
    if (!isPasswordHash(subAdmin.password)) {
      await run('UPDATE sub_admins SET password = ? WHERE id = ?', [hashPassword(subAdmin.password), subAdmin.id]);
    }
  }
}

async function initializeDatabase() {
  await run('PRAGMA foreign_keys = ON');

  await run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      name TEXT NOT NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS branches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS riders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      balance INTEGER NOT NULL DEFAULT 0,
      bank TEXT NOT NULL DEFAULT '',
      account TEXT NOT NULL DEFAULT '',
      branch_id INTEGER NOT NULL,
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS sub_admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      company_name TEXT NOT NULL,
      branch_id INTEGER NOT NULL,
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS deliveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rider_id INTEGER NOT NULL,
      fare INTEGER NOT NULL,
      fee100 INTEGER NOT NULL,
      fee16 INTEGER NOT NULL,
      final INTEGER NOT NULL,
      status TEXT NOT NULL,
      FOREIGN KEY (rider_id) REFERENCES riders(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rider_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      status TEXT NOT NULL,
      FOREIGN KEY (rider_id) REFERENCES riders(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS deduction_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rider_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      days_count INTEGER,
      weekday TEXT,
      monthly_auto INTEGER NOT NULL DEFAULT 0,
      description TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      created_by_role TEXT NOT NULL DEFAULT 'sub_admin',
      FOREIGN KEY (rider_id) REFERENCES riders(id)
    )
  `);

  const seed = readSeedData();
  const branchCount = await get('SELECT COUNT(*) AS count FROM branches');
  if (branchCount.count === 0) {
    await transaction(async () => {
      for (const admin of seed.admins) {
        await run(
          'INSERT INTO admins (id, username, password, name) VALUES (?, ?, ?, ?)',
          [
            admin.id,
            admin.username,
            isPasswordHash(admin.password) ? admin.password : hashPassword(admin.password),
            admin.name,
          ]
        );
      }

      for (const branch of seed.branches) {
        await run('INSERT INTO branches (id, name) VALUES (?, ?)', [branch.id, branch.name]);
      }

      for (const rider of seed.riders) {
        await run(
          `INSERT INTO riders (id, username, password, name, balance, bank, account, branch_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            rider.id,
            rider.username,
            isPasswordHash(rider.password) ? rider.password : hashPassword(rider.password),
            rider.name,
            rider.balance,
            rider.bank,
            rider.account,
            rider.branch_id,
          ]
        );
      }

      for (const subAdmin of seed.subAdmins) {
        await run(
          `INSERT INTO sub_admins (id, username, password, company_name, branch_id)
           VALUES (?, ?, ?, ?, ?)`,
          [
            subAdmin.id,
            subAdmin.username,
            isPasswordHash(subAdmin.password) ? subAdmin.password : hashPassword(subAdmin.password),
            subAdmin.company_name,
            subAdmin.branch_id,
          ]
        );
      }

      for (const delivery of seed.deliveries) {
        await run(
          `INSERT INTO deliveries (id, rider_id, fare, fee100, fee16, final, status)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [delivery.id, delivery.riderId, delivery.fare, delivery.fee100, delivery.fee16, delivery.final, delivery.status]
        );
      }

      for (const withdrawal of seed.withdrawals) {
        await run(
          'INSERT INTO withdrawals (id, rider_id, amount, status) VALUES (?, ?, ?, ?)',
          [withdrawal.id, withdrawal.riderId, withdrawal.amount, withdrawal.status]
        );
      }

      for (const deduction of seed.deductionLogs || []) {
        await run(
          `INSERT INTO deduction_logs
           (id, rider_id, amount, days_count, weekday, monthly_auto, description, created_at, created_by_role)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            deduction.id,
            deduction.riderId,
            deduction.amount,
            deduction.daysCount || null,
            deduction.weekday || '',
            deduction.monthlyAuto ? 1 : 0,
            deduction.description || '',
            deduction.createdAt || new Date().toISOString(),
            deduction.createdByRole || 'sub_admin',
          ]
        );
      }
    });
  }

  const adminCount = await get('SELECT COUNT(*) AS count FROM admins');
  if (adminCount.count === 0) {
    await run(
      'INSERT INTO admins (username, password, name) VALUES (?, ?, ?)',
      [DEFAULT_ADMIN_USERNAME, hashPassword(process.env.ADMIN_PASSWORD || DEFAULT_ADMIN_PASSWORD), '시스템 관리자']
    );
  }

  await migrateStoredPasswords();
}

async function readState() {
  const [admins, branches, riders, subAdmins, deliveries, withdrawals, deductionLogs] = await Promise.all([
    all('SELECT id, username, name FROM admins ORDER BY id'),
    all('SELECT id, name FROM branches ORDER BY id'),
    all('SELECT id, username, name, balance, bank, account, branch_id FROM riders ORDER BY id'),
    all('SELECT id, username, company_name, branch_id FROM sub_admins ORDER BY id'),
    all('SELECT id, rider_id AS riderId, fare, fee100, fee16, final, status FROM deliveries ORDER BY id'),
    all('SELECT id, rider_id AS riderId, amount, status FROM withdrawals ORDER BY id'),
    all(
      `SELECT id, rider_id AS riderId, amount, days_count AS daysCount, weekday,
              monthly_auto AS monthlyAuto, description, created_at AS createdAt, created_by_role AS createdByRole
       FROM deduction_logs
       ORDER BY id DESC`
    ),
  ]);

  return {
    admins,
    branches,
    riders,
    subAdmins,
    deliveries,
    withdrawals,
    deductionLogs,
  };
}

app.get('/', (req, res) => {
  res.sendFile(APP_HTML_PATH);
});

app.get('/delivery-system.html', (req, res) => {
  res.sendFile(APP_HTML_PATH);
});

app.get('/api/state', withErrorHandling(async (req, res) => {
  const session = requireSession(req, res);
  if (!session) {
    return;
  }
  const state = await readState();
  res.json({ success: true, data: buildStateForSession(session, state) });
}));

app.post('/api/login', withErrorHandling(async (req, res) => {
  const { role, username, password } = req.body;

  if (role === 'admin') {
    const admin = await get(
      'SELECT id, username, password, name FROM admins WHERE username = ?',
      [username]
    );
    if (admin && verifyPassword(password, admin.password)) {
      const session = createSession('admin', admin);
      res.json({ success: true, role: 'admin', admin_id: admin.id, username, name: admin.name, token: session.token });
      return;
    }
    sendError(res, 401, '로그인 실패');
    return;
  }

  if (role === 'rider') {
    const rider = await get(
      'SELECT id, username, password, name, branch_id FROM riders WHERE username = ?',
      [username]
    );
    if (!rider || !verifyPassword(password, rider.password)) {
      sendError(res, 401, '로그인 실패');
      return;
    }
    const session = createSession('rider', rider);
    res.json({
      success: true,
      role: 'rider',
      rider_id: rider.id,
      username: rider.username,
      name: rider.name,
      branch_id: rider.branch_id,
      token: session.token,
    });
    return;
  }

  if (role === 'sub_admin') {
    const subAdmin = await get(
      'SELECT id, username, password, company_name, branch_id FROM sub_admins WHERE username = ?',
      [username]
    );
    if (!subAdmin || !verifyPassword(password, subAdmin.password)) {
      sendError(res, 401, '로그인 실패');
      return;
    }
    const session = createSession('sub_admin', { id: subAdmin.id, username: subAdmin.username, branch_id: subAdmin.branch_id });
    res.json({
      success: true,
      role: 'sub_admin',
      sub_admin_id: subAdmin.id,
      branch_id: subAdmin.branch_id,
      username: subAdmin.username,
      company_name: subAdmin.company_name,
      token: session.token,
    });
    return;
  }

  sendError(res, 400, '지원하지 않는 로그인 유형입니다.');
}));

app.get('/api/admins', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const admins = await all('SELECT id, username, name FROM admins ORDER BY id');
  res.json({ success: true, data: admins });
}));

app.post('/api/admins', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '').trim();
  const name = String(req.body.name || '').trim();

  if (!username || !password || !name) {
    sendError(res, 400, '관리자 정보를 모두 입력하세요.');
    return;
  }

  try {
    const result = await run(
      'INSERT INTO admins (username, password, name) VALUES (?, ?, ?)',
      [username, hashPassword(password), name]
    );
    res.json({
      success: true,
      message: '관리자 계정 생성 완료',
      admin: { id: result.lastID, username, name },
    });
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) {
      sendError(res, 409, '이미 존재하는 관리자 아이디입니다.');
      return;
    }
    throw error;
  }
}));

app.post('/api/admins/:adminId/password', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const adminId = Number(req.params.adminId);
  const currentPassword = String(req.body.currentPassword || '').trim();
  const newPassword = String(req.body.newPassword || '').trim();

  if (!adminId || !currentPassword || !newPassword) {
    sendError(res, 400, '현재 비밀번호와 새 비밀번호를 모두 입력하세요.');
    return;
  }

  const admin = await get('SELECT id, password FROM admins WHERE id = ?', [adminId]);
  if (!admin) {
    sendError(res, 404, '관리자 계정을 찾을 수 없습니다.');
    return;
  }

  if (!verifyPassword(currentPassword, admin.password)) {
    sendError(res, 401, '현재 비밀번호가 일치하지 않습니다.');
    return;
  }

  if (session.userId !== adminId) {
    sendError(res, 403, '본인 비밀번호만 변경할 수 있습니다.');
    return;
  }

  await run('UPDATE admins SET password = ? WHERE id = ?', [hashPassword(newPassword), adminId]);
  res.json({ success: true, message: '관리자 비밀번호 변경 완료' });
}));

app.post('/api/admins/:adminId/reset-password', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const adminId = Number(req.params.adminId);
  const newPassword = String(req.body.newPassword || '').trim();

  if (!adminId || !newPassword) {
    sendError(res, 400, '새 비밀번호를 입력하세요.');
    return;
  }

  const admin = await get('SELECT id, username, name FROM admins WHERE id = ?', [adminId]);
  if (!admin) {
    sendError(res, 404, '관리자 계정을 찾을 수 없습니다.');
    return;
  }

  await run('UPDATE admins SET password = ? WHERE id = ?', [hashPassword(newPassword), adminId]);
  revokeSessionsForUser('admin', adminId);

  res.json({
    success: true,
    message: '관리자 비밀번호 초기화 완료',
    admin: { id: admin.id, username: admin.username, name: admin.name },
  });
}));

app.delete('/api/admins/:adminId', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const adminId = Number(req.params.adminId);
  if (!adminId) {
    sendError(res, 400, '삭제할 관리자 ID가 올바르지 않습니다.');
    return;
  }

  if (session.userId === adminId) {
    sendError(res, 400, '현재 로그인한 관리자는 삭제할 수 없습니다.');
    return;
  }

  const admin = await get('SELECT id, username, name FROM admins WHERE id = ?', [adminId]);
  if (!admin) {
    sendError(res, 404, '관리자 계정을 찾을 수 없습니다.');
    return;
  }

  const adminCount = await get('SELECT COUNT(*) AS count FROM admins');
  if (adminCount.count <= 1) {
    sendError(res, 400, '마지막 관리자 계정은 삭제할 수 없습니다.');
    return;
  }

  await run('DELETE FROM admins WHERE id = ?', [adminId]);
  revokeSessionsForUser('admin', adminId);

  res.json({
    success: true,
    message: '관리자 계정 삭제 완료',
    admin: { id: admin.id, username: admin.username, name: admin.name },
  });
}));

app.post('/api/branches', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const branchName = String(req.body.name || '').trim();
  if (!branchName) {
    sendError(res, 400, '지점명을 입력하세요.');
    return;
  }

  try {
    const result = await run('INSERT INTO branches (name) VALUES (?)', [branchName]);
    res.json({ success: true, message: '지점 생성 완료', branch: { id: result.lastID, name: branchName } });
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) {
      sendError(res, 409, '이미 존재하는 지점명입니다.');
      return;
    }
    throw error;
  }
}));

app.post('/api/sub-admins', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '').trim();
  const companyName = String(req.body.company_name || '').trim();
  const branchId = Number(req.body.branch_id);

  if (!username || !password || !companyName || !branchId) {
    sendError(res, 400, '지사장 정보를 모두 입력하세요.');
    return;
  }

  const branch = await get('SELECT id FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  try {
    const result = await run(
      'INSERT INTO sub_admins (username, password, company_name, branch_id) VALUES (?, ?, ?, ?)',
      [username, hashPassword(password), companyName, branchId]
    );
    res.json({
      success: true,
      message: '지사장 추가 완료',
      subAdmin: { id: result.lastID, username, company_name: companyName, branch_id: branchId },
    });
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) {
      sendError(res, 409, '이미 존재하는 지사장 아이디입니다.');
      return;
    }
    throw error;
  }
}));

app.post('/api/riders', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '').trim();
  const name = String(req.body.name || '').trim();
  const branchId = Number(req.body.branch_id);

  if (!username || !password || !name || !branchId) {
    sendError(res, 400, '기사 정보를 모두 입력하세요.');
    return;
  }

  const branch = await get('SELECT id FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  try {
    const result = await run(
      `INSERT INTO riders (username, password, name, balance, bank, account, branch_id)
       VALUES (?, ?, ?, 0, '', '', ?)`,
      [username, hashPassword(password), name, branchId]
    );
    res.json({
      success: true,
      message: '기사 추가 완료',
      rider: { id: result.lastID, username, name, balance: 0, bank: '', account: '', branch_id: branchId },
    });
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) {
      sendError(res, 409, '이미 존재하는 기사 아이디입니다.');
      return;
    }
    throw error;
  }
}));

app.post('/api/riders/:riderId/charge', withErrorHandling(async (req, res) => {
  const session = requireAdminOrSubAdmin(req, res);
  if (!session) {
    return;
  }
  const riderId = Number(req.params.riderId);
  const amount = Number(req.body.amount);

  if (!riderId || !Number.isFinite(amount) || amount <= 0) {
    sendError(res, 400, '충전 정보가 올바르지 않습니다.');
    return;
  }

  const rider = await get('SELECT id FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (session.role === 'sub_admin') {
    const scopedRider = await get('SELECT id FROM riders WHERE id = ? AND branch_id = ?', [riderId, session.branch_id]);
    if (!scopedRider) {
      sendError(res, 403, '해당 지점 기사만 충전할 수 있습니다.');
      return;
    }
  }

  await run('UPDATE riders SET balance = balance + ? WHERE id = ?', [amount, riderId]);
  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [riderId]
  );
  res.json({ success: true, message: '충전 완료', rider: updatedRider });
}));

app.post('/api/riders/:riderId/deduct', withErrorHandling(async (req, res) => {
  const session = requireAdminOrSubAdmin(req, res);
  if (!session) {
    return;
  }
  const riderId = Number(req.params.riderId);
  const amount = Number(req.body.amount);
  const daysCount = req.body.daysCount === '' || req.body.daysCount == null
    ? null
    : Number(req.body.daysCount);
  const weekday = String(req.body.weekday || '').trim();
  const monthlyAuto = Boolean(req.body.monthlyAuto);
  const description = String(req.body.description || '').trim();

  if (!riderId || !Number.isFinite(amount) || amount <= 0) {
    sendError(res, 400, '차감 정보가 올바르지 않습니다.');
    return;
  }

  if (daysCount != null && (!Number.isInteger(daysCount) || daysCount <= 0)) {
    sendError(res, 400, '일수는 1 이상의 정수여야 합니다.');
    return;
  }

  if (weekday && !['월', '화', '수', '목', '금', '토', '일'].includes(weekday)) {
    sendError(res, 400, '요일 값이 올바르지 않습니다.');
    return;
  }

  if (description.length > 200) {
    sendError(res, 400, '차감내용은 200자 이하로 입력하세요.');
    return;
  }

  const rider = await get('SELECT id, branch_id, balance FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (session.role === 'sub_admin' && rider.branch_id !== session.branch_id) {
    sendError(res, 403, '해당 지점 기사만 차감할 수 있습니다.');
    return;
  }

  if (rider.balance < amount) {
    sendError(res, 400, '기사 잔액이 부족하여 차감할 수 없습니다.');
    return;
  }

  await transaction(async () => {
    await run('UPDATE riders SET balance = balance - ? WHERE id = ?', [amount, riderId]);
    await run(
      `INSERT INTO deduction_logs
       (rider_id, amount, days_count, weekday, monthly_auto, description, created_by_role)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [riderId, amount, daysCount, weekday, monthlyAuto ? 1 : 0, description, session.role]
    );
  });
  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [riderId]
  );
  res.json({
    success: true,
    message: '일차감 완료',
    rider: updatedRider,
    deduction: {
      riderId,
      amount,
      daysCount,
      weekday,
      monthlyAuto,
      description,
    },
  });
}));

app.post('/api/deliveries', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const riderId = Number(req.body.riderId);
  const fare = Number(req.body.fare);

  if (!riderId || !Number.isFinite(fare) || fare <= 0) {
    sendError(res, 400, '배달 정보가 올바르지 않습니다.');
    return;
  }

  const rider = await get('SELECT id FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  const settlement = calculateSettlement(fare);
  const delivery = await transaction(async () => {
    const result = await run(
      `INSERT INTO deliveries (rider_id, fare, fee100, fee16, final, status)
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      [riderId, fare, settlement.fee100, settlement.fee16, settlement.final]
    );
    await run('UPDATE riders SET balance = balance + ? WHERE id = ?', [settlement.final, riderId]);
    return {
      id: result.lastID,
      riderId,
      fare,
      ...settlement,
      status: 'pending',
    };
  });

  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [riderId]
  );
  res.json({ success: true, message: '배달 추가 완료', delivery, rider: updatedRider });
}));

app.post('/api/deliveries/:deliveryId/complete', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['admin', 'rider']);
  if (!session) {
    return;
  }
  const deliveryId = Number(req.params.deliveryId);
  const delivery = await get(
    'SELECT id, rider_id AS riderId, fare, fee100, fee16, final, status FROM deliveries WHERE id = ?',
    [deliveryId]
  );

  if (!delivery) {
    sendError(res, 404, '배달을 찾을 수 없습니다.');
    return;
  }

  if (session.role === 'rider' && delivery.riderId !== session.userId) {
    sendError(res, 403, '본인 배달만 완료할 수 있습니다.');
    return;
  }

  await run(`UPDATE deliveries SET status = 'completed' WHERE id = ?`, [deliveryId]);
  res.json({ success: true, message: '배달 완료', delivery: { ...delivery, status: 'completed' } });
}));

app.post('/api/riders/:riderId/info', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['admin', 'rider']);
  if (!session) {
    return;
  }
  const riderId = Number(req.params.riderId);
  const name = String(req.body.name || '').trim();
  const bank = String(req.body.bank || '').trim();
  const account = String(req.body.account || '').trim();

  const rider = await get('SELECT id FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사 정보를 찾을 수 없습니다.');
    return;
  }

  if (session.role === 'rider' && riderId !== session.userId) {
    sendError(res, 403, '본인 정보만 수정할 수 있습니다.');
    return;
  }

  await run('UPDATE riders SET name = ?, bank = ?, account = ? WHERE id = ?', [name, bank, account, riderId]);
  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [riderId]
  );
  res.json({ success: true, message: '정보 저장 완료', rider: updatedRider });
}));

app.post('/api/withdrawals', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['admin', 'rider']);
  if (!session) {
    return;
  }
  const riderId = Number(req.body.riderId);
  const amount = Number(req.body.amount);

  if (!riderId || !Number.isFinite(amount) || amount <= 0) {
    sendError(res, 400, '출금 금액이 올바르지 않습니다.');
    return;
  }

  if (session.role === 'rider' && riderId !== session.userId) {
    sendError(res, 403, '본인 출금만 요청할 수 있습니다.');
    return;
  }

  const rider = await get('SELECT id, balance FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (rider.balance < amount) {
    sendError(res, 400, '잔액이 부족합니다.');
    return;
  }

  const result = await run(
    `INSERT INTO withdrawals (rider_id, amount, status)
     VALUES (?, ?, 'pending')`,
    [riderId, amount]
  );
  res.json({
    success: true,
    message: '출금신청 완료 (관리자 승인 대기 중)',
    withdrawal: { id: result.lastID, riderId, amount, status: 'pending' },
  });
}));

app.post('/api/withdrawals/:withdrawalId/approve', withErrorHandling(async (req, res) => {
  const session = requireAdminOrSubAdmin(req, res);
  if (!session) {
    return;
  }
  const withdrawalId = Number(req.params.withdrawalId);
  const withdrawal = await get(
    'SELECT id, rider_id AS riderId, amount, status FROM withdrawals WHERE id = ?',
    [withdrawalId]
  );

  if (!withdrawal) {
    sendError(res, 404, '출금 요청을 찾을 수 없습니다.');
    return;
  }

  if (session.role === 'sub_admin') {
    const scopedRider = await get('SELECT id FROM riders WHERE id = ? AND branch_id = ?', [withdrawal.riderId, session.branch_id]);
    if (!scopedRider) {
      sendError(res, 403, '해당 지점 기사 출금만 승인할 수 있습니다.');
      return;
    }
  }

  if (withdrawal.status !== 'pending') {
    sendError(res, 400, '이미 처리된 출금 요청입니다.');
    return;
  }

  const rider = await get('SELECT id, balance FROM riders WHERE id = ?', [withdrawal.riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (rider.balance < withdrawal.amount) {
    sendError(res, 400, '잔액 부족으로 승인할 수 없습니다.');
    return;
  }

  await transaction(async () => {
    await run('UPDATE riders SET balance = balance - ? WHERE id = ?', [withdrawal.amount, withdrawal.riderId]);
    await run(`UPDATE withdrawals SET status = 'approved' WHERE id = ?`, [withdrawalId]);
  });

  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [withdrawal.riderId]
  );
  res.json({
    success: true,
    message: '출금 승인 완료',
    withdrawal: { ...withdrawal, status: 'approved' },
    rider: updatedRider,
  });
}));

app.post('/api/me/password', withErrorHandling(async (req, res) => {
  const session = requireSession(req, res);
  if (!session) {
    return;
  }

  const currentPassword = String(req.body.currentPassword || '').trim();
  const newPassword = String(req.body.newPassword || '').trim();

  if (!currentPassword || !newPassword) {
    sendError(res, 400, '현재 비밀번호와 새 비밀번호를 모두 입력하세요.');
    return;
  }

  if (newPassword.length < 4) {
    sendError(res, 400, '새 비밀번호는 4자 이상이어야 합니다.');
    return;
  }

  let user;
  let tableName;
  if (session.role === 'admin') {
    user = await get('SELECT id, password FROM admins WHERE id = ?', [session.userId]);
    tableName = 'admins';
  } else if (session.role === 'sub_admin') {
    user = await get('SELECT id, password FROM sub_admins WHERE id = ?', [session.userId]);
    tableName = 'sub_admins';
  } else if (session.role === 'rider') {
    user = await get('SELECT id, password FROM riders WHERE id = ?', [session.userId]);
    tableName = 'riders';
  } else {
    sendError(res, 400, '지원하지 않는 사용자 유형입니다.');
    return;
  }

  if (!user) {
    sendError(res, 404, '사용자 계정을 찾을 수 없습니다.');
    return;
  }

  if (!verifyPassword(currentPassword, user.password)) {
    sendError(res, 401, '현재 비밀번호가 일치하지 않습니다.');
    return;
  }

  await run(`UPDATE ${tableName} SET password = ? WHERE id = ?`, [hashPassword(newPassword), session.userId]);
  res.json({ success: true, message: '비밀번호 변경 완료' });
}));

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`배달 정산 시스템 서버가 ${PORT}번 포트에서 실행 중입니다.`);
    });
  })
  .catch((error) => {
    console.error('데이터베이스 초기화 실패:', error);
    process.exit(1);
  });
