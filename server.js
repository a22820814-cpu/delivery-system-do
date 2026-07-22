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
const WITHDRAWAL_FEE = 300;
const CHARGE_FEE = 300;
const AUTO_DEDUCT_INTERVAL_MS = 60 * 1000;
const KOREAN_WEEKDAYS = ['일', '월', '화', '수', '목', '금', '토'];
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

async function addColumnIfMissing(tableName, columnName, definitionSql) {
  const columns = await all(`PRAGMA table_info(${tableName})`);
  const hasColumn = columns.some((column) => column.name === columnName);
  if (!hasColumn) {
    await run(`ALTER TABLE ${tableName} ADD COLUMN ${definitionSql}`);
  }
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

function isSuperAdmin(session) {
  return session.role === 'admin'
    && !session.branch_id
    && (session.userId === 1 || session.username === DEFAULT_ADMIN_USERNAME);
}

function requireSuperAdmin(req, res) {
  const session = requireAdmin(req, res);
  if (!session) {
    return null;
  }
  if (!isSuperAdmin(session)) {
    sendError(res, 403, '최고 관리자만 접근할 수 있습니다.');
    return null;
  }
  return session;
}

function buildStateForSession(session, state) {
  const resolveIntegrationForBranch = (integrationRows, branchId) => {
    if (!branchId) {
      return {
        linked: false,
        branchId: null,
        branchName: '',
        partnerId: '',
        storeId: '',
        baseUrl: '',
        apiKeyMasked: '',
        linkedAt: '',
        lastSyncAt: '',
      };
    }
    const found = (integrationRows || []).find((item) => item.branchId === branchId);
    if (!found) {
      return {
        linked: false,
        branchId,
        branchName: state.branches.find((branch) => branch.id === branchId)?.name || '',
        partnerId: '',
        storeId: '',
        baseUrl: '',
        apiKeyMasked: '',
        linkedAt: '',
        lastSyncAt: '',
      };
    }
    return {
      linked: Boolean(found.linked),
      branchId: found.branchId,
      branchName: found.branchName || '',
      partnerId: found.partnerId || '',
      storeId: found.storeId || '',
      baseUrl: found.baseUrl || '',
      apiKeyMasked: found.apiKey ? String(found.apiKey).replace(/.(?=.{4})/g, '*') : '',
      linkedAt: found.linkedAt || '',
      lastSyncAt: found.lastSyncAt || '',
    };
  };

  const resolveBaeminForBranch = (branchId) => resolveIntegrationForBranch(state.baeminBizIntegrations, branchId);
  const resolveCoupangForBranch = (branchId) => resolveIntegrationForBranch(state.coupangPlusIntegrations, branchId);

  if (session.role === 'admin') {
    if (isSuperAdmin(session)) {
      return {
        ...state,
        admins: state.admins,
        subAdmins: [],
        baeminBiz: resolveBaeminForBranch(state.branches[0]?.id || null),
        coupangPlus: resolveCoupangForBranch(state.branches[0]?.id || null),
      };
    }

    const riders = state.riders.filter((rider) => rider.branch_id === session.branch_id);
    const riderIds = new Set(riders.map((rider) => rider.id));
    return {
      branches: state.branches.filter((branch) => branch.id === session.branch_id),
      riders,
      deliveries: state.deliveries.filter((delivery) => riderIds.has(delivery.riderId)),
      withdrawals: state.withdrawals.filter((withdrawal) => riderIds.has(withdrawal.riderId)),
      deductionLogs: state.deductionLogs.filter((deduction) => riderIds.has(deduction.riderId)),
      chargeLogs: state.chargeLogs.filter((chargeLog) => riderIds.has(chargeLog.riderId)),
      autoDeductRules: state.autoDeductRules.filter((rule) => riderIds.has(rule.riderId)),
      admins: state.admins.filter((admin) => admin.id === session.userId),
      subAdmins: [],
      notice: state.notice,
      businessAccount: {
        ...state.businessAccount,
        accountNumber: state.businessAccount?.accountNumber
          ? String(state.businessAccount.accountNumber).replace(/.(?=.{4})/g, '*')
          : '',
      },
      baeminBiz: resolveBaeminForBranch(session.branch_id || null),
      coupangPlus: resolveCoupangForBranch(session.branch_id || null),
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
    chargeLogs: state.chargeLogs.filter((chargeLog) => chargeLog.riderId === session.userId),
    autoDeductRules: state.autoDeductRules.filter((rule) => rule.riderId === session.userId),
    notice: state.notice,
    businessAccount: {
      linked: false,
      bankName: '',
      accountNumber: '',
      accountHolder: '',
      linkedAt: '',
      balance: 0,
    },
    baeminBiz: {
      linked: false,
      branchId: null,
      branchName: '',
      partnerId: '',
      storeId: '',
      baseUrl: '',
      apiKeyMasked: '',
      linkedAt: '',
      lastSyncAt: '',
    },
    coupangPlus: {
      linked: false,
      branchId: null,
      branchName: '',
      partnerId: '',
      storeId: '',
      baseUrl: '',
      apiKeyMasked: '',
      linkedAt: '',
      lastSyncAt: '',
    },
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
        branch_id: null,
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
    chargeLogs: [],
    autoDeductRules: [],
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

}

async function initializeDatabase() {
  await run('PRAGMA foreign_keys = ON');

  await run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      balance INTEGER NOT NULL DEFAULT 0,
      branch_id INTEGER,
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT ''
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS branches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      balance INTEGER NOT NULL DEFAULT 0
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
    CREATE TABLE IF NOT EXISTS deliveries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rider_id INTEGER NOT NULL,
      fare INTEGER NOT NULL,
      fee100 INTEGER NOT NULL,
      fee16 INTEGER NOT NULL,
      final INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      status TEXT NOT NULL,
      FOREIGN KEY (rider_id) REFERENCES riders(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rider_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      processed_at TEXT,
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
      daily_amount INTEGER,
      total_days INTEGER,
      description TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      created_by_role TEXT NOT NULL DEFAULT 'admin',
      FOREIGN KEY (rider_id) REFERENCES riders(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS charge_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rider_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      fee INTEGER NOT NULL,
      net_amount INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      created_by_admin_id INTEGER,
      FOREIGN KEY (rider_id) REFERENCES riders(id),
      FOREIGN KEY (created_by_admin_id) REFERENCES admins(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS auto_deduct_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      rider_id INTEGER NOT NULL UNIQUE,
      enabled INTEGER NOT NULL DEFAULT 0,
      daily_amount INTEGER NOT NULL DEFAULT 0,
      total_amount INTEGER NOT NULL DEFAULT 0,
      total_days INTEGER NOT NULL DEFAULT 0,
      deducted_amount INTEGER NOT NULL DEFAULT 0,
      applied_days INTEGER NOT NULL DEFAULT 0,
      start_date TEXT,
      weekday TEXT NOT NULL DEFAULT '',
      description TEXT NOT NULL DEFAULT '',
      last_run_date TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (rider_id) REFERENCES riders(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS baemin_biz_integrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      branch_id INTEGER NOT NULL UNIQUE,
      linked INTEGER NOT NULL DEFAULT 0,
      partner_id TEXT NOT NULL DEFAULT '',
      store_id TEXT NOT NULL DEFAULT '',
      api_key TEXT NOT NULL DEFAULT '',
      base_url TEXT NOT NULL DEFAULT '',
      linked_at TEXT,
      last_sync_at TEXT,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS coupang_plus_integrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      branch_id INTEGER NOT NULL UNIQUE,
      linked INTEGER NOT NULL DEFAULT 0,
      partner_id TEXT NOT NULL DEFAULT '',
      store_id TEXT NOT NULL DEFAULT '',
      api_key TEXT NOT NULL DEFAULT '',
      base_url TEXT NOT NULL DEFAULT '',
      linked_at TEXT,
      last_sync_at TEXT,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS baemin_biz_sync_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      branch_id INTEGER NOT NULL,
      imported_orders INTEGER NOT NULL DEFAULT 0,
      imported_revenue INTEGER NOT NULL DEFAULT 0,
      synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS coupang_plus_sync_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      branch_id INTEGER NOT NULL,
      imported_orders INTEGER NOT NULL DEFAULT 0,
      imported_revenue INTEGER NOT NULL DEFAULT 0,
      synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (branch_id) REFERENCES branches(id)
    )
  `);

  await addColumnIfMissing('withdrawals', 'created_at', 'created_at TEXT');
  await addColumnIfMissing('withdrawals', 'processed_at', 'processed_at TEXT');
  await addColumnIfMissing('withdrawals', 'fee', 'fee INTEGER');
  await addColumnIfMissing('deliveries', 'created_at', 'created_at TEXT');
  await addColumnIfMissing('deduction_logs', 'daily_amount', 'daily_amount INTEGER');
  await addColumnIfMissing('deduction_logs', 'total_days', 'total_days INTEGER');
  await addColumnIfMissing('admins', 'balance', 'balance INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('branches', 'balance', 'balance INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('admins', 'branch_id', 'branch_id INTEGER');
  await addColumnIfMissing('charge_logs', 'created_by_admin_id', 'created_by_admin_id INTEGER');
  await addColumnIfMissing('auto_deduct_rules', 'description', "description TEXT NOT NULL DEFAULT ''");
  await addColumnIfMissing('auto_deduct_rules', 'last_run_date', 'last_run_date TEXT');
  await addColumnIfMissing('auto_deduct_rules', 'created_at', 'created_at TEXT');
  await addColumnIfMissing('auto_deduct_rules', 'updated_at', 'updated_at TEXT');
  await addColumnIfMissing('auto_deduct_rules', 'total_amount', 'total_amount INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('auto_deduct_rules', 'total_days', 'total_days INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('auto_deduct_rules', 'deducted_amount', 'deducted_amount INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('auto_deduct_rules', 'applied_days', 'applied_days INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('auto_deduct_rules', 'start_date', 'start_date TEXT');
  await addColumnIfMissing('baemin_biz_integrations', 'base_url', "base_url TEXT NOT NULL DEFAULT ''");
  await addColumnIfMissing('coupang_plus_integrations', 'base_url', "base_url TEXT NOT NULL DEFAULT ''");
  await addColumnIfMissing('baemin_biz_sync_logs', 'imported_revenue', 'imported_revenue INTEGER NOT NULL DEFAULT 0');
  await addColumnIfMissing('coupang_plus_sync_logs', 'imported_revenue', 'imported_revenue INTEGER NOT NULL DEFAULT 0');
  await run('UPDATE deliveries SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)');
  await run('UPDATE withdrawals SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)');
  await run('UPDATE withdrawals SET fee = COALESCE(fee, 0)');
  await run('UPDATE auto_deduct_rules SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)');
  await run('UPDATE auto_deduct_rules SET updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP)');
  await run('UPDATE auto_deduct_rules SET total_amount = COALESCE(total_amount, daily_amount * 30) WHERE total_amount <= 0');
  await run('UPDATE auto_deduct_rules SET total_days = COALESCE(total_days, 30) WHERE total_days <= 0');
  await run('UPDATE auto_deduct_rules SET deducted_amount = COALESCE(deducted_amount, 0)');
  await run('UPDATE auto_deduct_rules SET applied_days = COALESCE(applied_days, 0)');
  await run("UPDATE auto_deduct_rules SET start_date = COALESCE(start_date, date('now', 'localtime'))");
  await run("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('global_notice', '')");
  await run("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('business_account_bank', '')");
  await run("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('business_account_number', '')");
  await run("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('business_account_holder', '')");
  await run("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('business_account_linked', '0')");
  await run("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('business_account_linked_at', '')");
  await run("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('business_account_balance', '0')");

  const seed = readSeedData();
  const branchCount = await get('SELECT COUNT(*) AS count FROM branches');
  if (branchCount.count === 0) {
    await transaction(async () => {
      for (const admin of seed.admins) {
        await run(
          'INSERT INTO admins (id, username, password, name, balance, branch_id) VALUES (?, ?, ?, ?, ?, ?)',
          [
            admin.id,
            admin.username,
            isPasswordHash(admin.password) ? admin.password : hashPassword(admin.password),
            admin.name,
            admin.balance || 0,
            admin.branch_id || null,
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

      for (const delivery of seed.deliveries) {
        await run(
          `INSERT INTO deliveries (id, rider_id, fare, fee100, fee16, final, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            delivery.id,
            delivery.riderId,
            delivery.fare,
            delivery.fee100,
            delivery.fee16,
            delivery.final,
            delivery.status,
            delivery.createdAt || new Date().toISOString(),
          ]
        );
      }

      for (const withdrawal of seed.withdrawals) {
        await run(
          `INSERT INTO withdrawals (id, rider_id, amount, fee, status, created_at, processed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            withdrawal.id,
            withdrawal.riderId,
            withdrawal.amount,
            withdrawal.fee || 0,
            withdrawal.status,
            withdrawal.createdAt || new Date().toISOString(),
            withdrawal.processedAt || null,
          ]
        );
      }

      for (const deduction of seed.deductionLogs || []) {
        await run(
          `INSERT INTO deduction_logs
           (id, rider_id, amount, days_count, weekday, monthly_auto, daily_amount, total_days, description, created_at, created_by_role)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            deduction.id,
            deduction.riderId,
            deduction.amount,
            deduction.daysCount || null,
            deduction.weekday || '',
            deduction.monthlyAuto ? 1 : 0,
            deduction.dailyAmount || null,
            deduction.totalDays || null,
            deduction.description || '',
            deduction.createdAt || new Date().toISOString(),
            deduction.createdByRole || 'admin',
          ]
        );
      }

      for (const chargeLog of seed.chargeLogs || []) {
        await run(
          `INSERT INTO charge_logs
           (id, rider_id, amount, fee, net_amount, created_at, created_by_admin_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            chargeLog.id,
            chargeLog.riderId,
            chargeLog.amount,
            chargeLog.fee || 0,
            chargeLog.netAmount != null
              ? chargeLog.netAmount
              : (chargeLog.amount - (chargeLog.fee || 0)),
            chargeLog.createdAt || new Date().toISOString(),
            chargeLog.createdByAdminId || null,
          ]
        );
      }

      for (const autoRule of seed.autoDeductRules || []) {
        await run(
          `INSERT INTO auto_deduct_rules
           (id, rider_id, enabled, daily_amount, total_amount, total_days,
            deducted_amount, applied_days, start_date, weekday, description,
            last_run_date, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            autoRule.id,
            autoRule.riderId,
            autoRule.enabled ? 1 : 0,
            autoRule.dailyAmount || 0,
            autoRule.totalAmount || ((autoRule.dailyAmount || 0) * (autoRule.totalDays || 30)),
            autoRule.totalDays || 30,
            autoRule.deductedAmount || 0,
            autoRule.appliedDays || 0,
            autoRule.startDate || getTodayDateKey(),
            autoRule.weekday || '',
            autoRule.description || '',
            autoRule.lastRunDate || null,
            autoRule.createdAt || new Date().toISOString(),
            autoRule.updatedAt || new Date().toISOString(),
          ]
        );
      }
    });
  }

  const adminCount = await get('SELECT COUNT(*) AS count FROM admins');
  if (adminCount.count === 0) {
    await run(
      'INSERT INTO admins (username, password, name, balance, branch_id) VALUES (?, ?, ?, ?, ?)',
      [DEFAULT_ADMIN_USERNAME, hashPassword(process.env.ADMIN_PASSWORD || DEFAULT_ADMIN_PASSWORD), '시스템 관리자', 0, null]
    );
  }

  await migrateStoredPasswords();
}

async function readState() {
  const [
    admins,
    branches,
    riders,
    deliveries,
    withdrawals,
    deductionLogs,
    chargeLogs,
    autoDeductRules,
    noticeRow,
    businessBankRow,
    businessNumberRow,
    businessHolderRow,
    businessLinkedRow,
    businessLinkedAtRow,
    businessBalanceRow,
    baeminBizIntegrations,
    coupangPlusIntegrations,
  ] = await Promise.all([
    all('SELECT id, username, name, balance, branch_id FROM admins ORDER BY id'),
    all('SELECT id, name, balance FROM branches ORDER BY id'),
    all('SELECT id, username, name, balance, bank, account, branch_id FROM riders ORDER BY id'),
    all(
      `SELECT id, rider_id AS riderId, fare, fee100, fee16, final,
              created_at AS createdAt, status
       FROM deliveries
       ORDER BY id`
    ),
    all(
      `SELECT id, rider_id AS riderId, amount, fee, status,
              created_at AS createdAt, processed_at AS processedAt
       FROM withdrawals
       ORDER BY id`
    ),
    all(
      `SELECT id, rider_id AS riderId, amount, days_count AS daysCount, weekday,
              monthly_auto AS monthlyAuto, daily_amount AS dailyAmount,
              total_days AS totalDays, description,
              created_at AS createdAt, created_by_role AS createdByRole
       FROM deduction_logs
       ORDER BY id DESC`
    ),
    all(
      `SELECT id, rider_id AS riderId, amount, fee,
              net_amount AS netAmount, created_at AS createdAt,
              created_by_admin_id AS createdByAdminId
       FROM charge_logs
       ORDER BY id DESC`
    ),
    all(
          `SELECT id, rider_id AS riderId, enabled, daily_amount AS dailyAmount,
            total_amount AS totalAmount, total_days AS totalDays,
            deducted_amount AS deductedAmount, applied_days AS appliedDays,
            start_date AS startDate, weekday, description, last_run_date AS lastRunDate,
              created_at AS createdAt, updated_at AS updatedAt
       FROM auto_deduct_rules
       ORDER BY id`
    ),
    get("SELECT value FROM app_settings WHERE key = 'global_notice'"),
    get("SELECT value FROM app_settings WHERE key = 'business_account_bank'"),
    get("SELECT value FROM app_settings WHERE key = 'business_account_number'"),
    get("SELECT value FROM app_settings WHERE key = 'business_account_holder'"),
    get("SELECT value FROM app_settings WHERE key = 'business_account_linked'"),
    get("SELECT value FROM app_settings WHERE key = 'business_account_linked_at'"),
    get("SELECT value FROM app_settings WHERE key = 'business_account_balance'"),
    all(
      `SELECT bbi.branch_id AS branchId, b.name AS branchName,
              bbi.linked, bbi.partner_id AS partnerId, bbi.store_id AS storeId,
              bbi.api_key AS apiKey, bbi.base_url AS baseUrl, bbi.linked_at AS linkedAt,
              bbi.last_sync_at AS lastSyncAt
       FROM baemin_biz_integrations bbi
       JOIN branches b ON b.id = bbi.branch_id
       ORDER BY bbi.branch_id`
    ),
    all(
      `SELECT cpi.branch_id AS branchId, b.name AS branchName,
              cpi.linked, cpi.partner_id AS partnerId, cpi.store_id AS storeId,
              cpi.api_key AS apiKey, cpi.base_url AS baseUrl, cpi.linked_at AS linkedAt,
              cpi.last_sync_at AS lastSyncAt
       FROM coupang_plus_integrations cpi
       JOIN branches b ON b.id = cpi.branch_id
       ORDER BY cpi.branch_id`
    ),
  ]);

  return {
    admins,
    branches,
    riders,
    subAdmins: [],
    deliveries,
    withdrawals,
    deductionLogs,
    chargeLogs,
    autoDeductRules,
    notice: noticeRow?.value || '',
    businessAccount: {
      linked: Number(businessLinkedRow?.value || 0) === 1,
      bankName: businessBankRow?.value || '',
      accountNumber: businessNumberRow?.value || '',
      accountHolder: businessHolderRow?.value || '',
      linkedAt: businessLinkedAtRow?.value || '',
      balance: Number(businessBalanceRow?.value || 0),
    },
    baeminBizIntegrations,
    coupangPlusIntegrations,
  };
}

async function creditBusinessAccount(amount) {
  const safeAmount = Number(amount) || 0;
  if (safeAmount <= 0) {
    return;
  }
  await run(
    `UPDATE app_settings
     SET value = CAST(COALESCE(value, '0') AS INTEGER) + ?
     WHERE key = 'business_account_balance'`,
    [safeAmount]
  );
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
      'SELECT id, username, password, name, branch_id FROM admins WHERE username = ?',
      [username]
    );
    if (admin && verifyPassword(password, admin.password)) {
      const session = createSession('admin', admin);
      res.json({ success: true, role: 'admin', admin_id: admin.id, username, name: admin.name, branch_id: admin.branch_id || null, token: session.token });
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

  sendError(res, 400, '지원하지 않는 로그인 유형입니다.');
}));

app.get('/api/admins', withErrorHandling(async (req, res) => {
  const session = requireSuperAdmin(req, res);
  if (!session) {
    return;
  }
  const admins = await all('SELECT id, username, name, branch_id FROM admins ORDER BY id');
  res.json({ success: true, data: admins });
}));

app.post('/api/admins', withErrorHandling(async (req, res) => {
  const session = requireSuperAdmin(req, res);
  if (!session) {
    return;
  }
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '').trim();
  const name = String(req.body.name || '').trim();
  const branchId = Number(req.body.branch_id);

  if (!username || !password || !name || !branchId) {
    sendError(res, 400, '관리자 정보를 모두 입력하세요.');
    return;
  }

  const branch = await get('SELECT id FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  try {
    const result = await run(
      'INSERT INTO admins (username, password, name, branch_id) VALUES (?, ?, ?, ?)',
      [username, hashPassword(password), name, branchId]
    );
    res.json({
      success: true,
      message: '관리자 계정 생성 완료',
      admin: { id: result.lastID, username, name, branch_id: branchId },
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
  const session = requireSuperAdmin(req, res);
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
  const session = requireSuperAdmin(req, res);
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
  const session = requireSuperAdmin(req, res);
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

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점의 기사만 생성할 수 있습니다.');
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
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const riderId = Number(req.params.riderId);
  const amount = Number(req.body.amount);
  const fee = CHARGE_FEE;
  const netAmount = amount - fee;

  if (!riderId || !Number.isFinite(amount) || amount <= 0) {
    sendError(res, 400, '충전 정보가 올바르지 않습니다.');
    return;
  }

  if (netAmount <= 0) {
    sendError(res, 400, `충전액은 수수료 ${fee}원보다 커야 합니다.`);
    return;
  }

  const rider = await get('SELECT id, branch_id FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && rider.branch_id !== session.branch_id) {
    sendError(res, 403, '해당 지점 기사만 충전할 수 있습니다.');
    return;
  }

  await transaction(async () => {
    await run('UPDATE riders SET balance = balance + ? WHERE id = ?', [netAmount, riderId]);
    await run(
      `INSERT INTO charge_logs (rider_id, amount, fee, net_amount, created_by_admin_id)
       VALUES (?, ?, ?, ?, ?)`,
      [riderId, amount, fee, netAmount, session.userId]
    );
    await creditBusinessAccount(fee);
  });
  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [riderId]
  );
  res.json({
    success: true,
    message: `충전 완료 (입금수수료 ${fee}원, 실충전액 ${netAmount}원)`,
    rider: updatedRider,
    charge: {
      riderId,
      amount,
      fee,
      netAmount,
    },
  });
}));

app.post('/api/riders/:riderId/deduct', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const riderId = Number(req.params.riderId);
  let amount = Number(req.body.amount);
  const dailyAmountRaw = req.body.dailyAmount;
  const dailyAmount = dailyAmountRaw === '' || dailyAmountRaw == null
    ? null
    : Number(dailyAmountRaw);
  const totalDaysRaw = req.body.totalDays;
  const totalDays = totalDaysRaw === '' || totalDaysRaw == null
    ? null
    : Number(totalDaysRaw);
  const daysCount = req.body.daysCount === '' || req.body.daysCount == null
    ? null
    : Number(req.body.daysCount);
  const weekday = String(req.body.weekday || '').trim();
  const monthlyAuto = Boolean(req.body.monthlyAuto);
  const description = String(req.body.description || '').trim();

  const effectiveTotalDays = totalDays == null ? 100 : totalDays;
  if (dailyAmount != null) {
    if (!Number.isFinite(dailyAmount) || dailyAmount <= 0) {
      sendError(res, 400, '하루 차감액은 1원 이상이어야 합니다.');
      return;
    }
    if (!Number.isInteger(effectiveTotalDays) || effectiveTotalDays <= 0) {
      sendError(res, 400, '총 일수는 1일 이상 정수여야 합니다.');
      return;
    }
    amount = dailyAmount * effectiveTotalDays;
  }

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

  if (!isSuperAdmin(session) && rider.branch_id !== session.branch_id) {
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
       (rider_id, amount, days_count, weekday, monthly_auto, daily_amount, total_days, description, created_by_role)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        riderId,
        amount,
        daysCount != null ? daysCount : effectiveTotalDays,
        weekday,
        monthlyAuto ? 1 : 0,
        dailyAmount,
        dailyAmount == null ? null : effectiveTotalDays,
        description,
        session.role,
      ]
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
      dailyAmount,
      totalDays: dailyAmount == null ? null : effectiveTotalDays,
      daysCount,
      weekday,
      monthlyAuto,
      description,
    },
  });
}));

app.post('/api/riders/:riderId/auto-deduct', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const riderId = Number(req.params.riderId);
  const enabled = Boolean(req.body.enabled);
  const totalAmount = Number(req.body.totalAmount);
  const totalDays = Number(req.body.totalDays);
  const startDate = String(req.body.startDate || '').trim();
  const weekday = String(req.body.weekday || '').trim();
  const description = String(req.body.description || '').trim();

  if (!riderId) {
    sendError(res, 400, '기사 정보가 올바르지 않습니다.');
    return;
  }

  if (!Number.isFinite(totalAmount) || totalAmount <= 0 || !Number.isInteger(totalAmount)) {
    sendError(res, 400, '총 자동차감 금액은 1원 이상의 정수여야 합니다.');
    return;
  }

  if (!Number.isFinite(totalDays) || totalDays <= 0 || !Number.isInteger(totalDays)) {
    sendError(res, 400, '분할 일수는 1일 이상의 정수여야 합니다.');
    return;
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(startDate)) {
    sendError(res, 400, '시작일은 YYYY-MM-DD 형식이어야 합니다.');
    return;
  }

  if (weekday && !KOREAN_WEEKDAYS.includes(weekday)) {
    sendError(res, 400, '요일 값이 올바르지 않습니다.');
    return;
  }

  if (description.length > 200) {
    sendError(res, 400, '자동차감 설명은 200자 이하로 입력하세요.');
    return;
  }

  const rider = await get('SELECT id, branch_id FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && rider.branch_id !== session.branch_id) {
    sendError(res, 403, '해당 지점 기사만 설정할 수 있습니다.');
    return;
  }

  const dailyAmount = Math.floor(totalAmount / totalDays);
  if (dailyAmount <= 0) {
    sendError(res, 400, '총금액이 분할 일수보다 작아 하루 차감액이 0원이 됩니다.');
    return;
  }

  await run(
    `INSERT INTO auto_deduct_rules
     (rider_id, enabled, daily_amount, total_amount, total_days,
      deducted_amount, applied_days, start_date, weekday, description, last_run_date, updated_at)
     VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, NULL, CURRENT_TIMESTAMP)
     ON CONFLICT(rider_id) DO UPDATE SET
       enabled = excluded.enabled,
       daily_amount = excluded.daily_amount,
       total_amount = excluded.total_amount,
       total_days = excluded.total_days,
       deducted_amount = 0,
       applied_days = 0,
       start_date = excluded.start_date,
       weekday = excluded.weekday,
       description = excluded.description,
       last_run_date = NULL,
       updated_at = CURRENT_TIMESTAMP`,
    [
      riderId,
      enabled ? 1 : 0,
      dailyAmount,
      totalAmount,
      totalDays,
      startDate,
      weekday,
      description,
    ]
  );

  const rule = await get(
    `SELECT id, rider_id AS riderId, enabled, daily_amount AS dailyAmount,
            total_amount AS totalAmount, total_days AS totalDays,
            deducted_amount AS deductedAmount, applied_days AS appliedDays,
            start_date AS startDate, weekday, description, last_run_date AS lastRunDate,
            created_at AS createdAt, updated_at AS updatedAt
     FROM auto_deduct_rules
     WHERE rider_id = ?`,
    [riderId]
  );

  res.json({
    success: true,
    message: enabled ? '자동차감 설정 완료' : '자동차감 비활성화 완료',
    rule,
  });
}));

app.post('/api/riders/me/auto-deduct-now', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['rider']);
  if (!session) {
    return;
  }

  const riderId = session.userId;
  const today = getTodayDateKey(new Date());

  const rule = await get(
    `SELECT adr.id, adr.rider_id AS riderId, adr.enabled,
            adr.daily_amount AS dailyAmount, adr.total_amount AS totalAmount,
            adr.total_days AS totalDays, adr.deducted_amount AS deductedAmount,
            adr.applied_days AS appliedDays, adr.start_date AS startDate,
            adr.weekday, adr.description, adr.last_run_date AS lastRunDate,
            r.balance, r.branch_id AS branchId
     FROM auto_deduct_rules adr
     JOIN riders r ON r.id = adr.rider_id
     WHERE adr.rider_id = ?`,
    [riderId]
  );

  if (!rule || !rule.enabled) {
    sendError(res, 400, '활성화된 자동차감 규칙이 없습니다.');
    return;
  }

  const totalAmount = Number(rule.totalAmount) || 0;
  const totalDays = Number(rule.totalDays) || 0;
  const appliedDays = Number(rule.appliedDays) || 0;
  const deductedAmount = Number(rule.deductedAmount) || 0;

  if (totalAmount <= 0 || totalDays <= 0 || appliedDays >= totalDays || deductedAmount >= totalAmount) {
    sendError(res, 400, '자동차감이 이미 완료되었거나 규칙 정보가 올바르지 않습니다.');
    return;
  }

  const startEpoch = parseDateKeyToEpoch(rule.startDate);
  const todayEpoch = parseDateKeyToEpoch(today);
  if (Number.isFinite(startEpoch) && Number.isFinite(todayEpoch) && todayEpoch < startEpoch) {
    sendError(res, 400, `자동차감 시작일(${rule.startDate}) 이후에 실행할 수 있습니다.`);
    return;
  }

  if (rule.lastRunDate === today) {
    sendError(res, 400, '오늘은 이미 자동차감이 실행되었습니다.');
    return;
  }

  const amount = calculateInstallmentAmount(totalAmount, totalDays, appliedDays);
  if (amount <= 0) {
    sendError(res, 400, '오늘 차감할 금액이 없습니다.');
    return;
  }

  if (Number(rule.balance) < amount) {
    sendError(res, 400, '잔액이 부족하여 즉시 자동차감을 실행할 수 없습니다.');
    return;
  }

  const nextAppliedDays = appliedDays + 1;
  const nextDeductedAmount = Math.min(totalAmount, deductedAmount + amount);
  const shouldDisable = nextAppliedDays >= totalDays || nextDeductedAmount >= totalAmount;

  await transaction(async () => {
    await run('UPDATE riders SET balance = balance - ? WHERE id = ?', [amount, riderId]);
    if (rule.branchId) {
      await run('UPDATE branches SET balance = balance + ? WHERE id = ?', [amount, rule.branchId]);
      await creditBranchAdmins(rule.branchId, amount);
    }
    await run(
      `INSERT INTO deduction_logs
       (rider_id, amount, days_count, weekday, monthly_auto, daily_amount, total_days, description, created_by_role)
       VALUES (?, ?, ?, ?, 1, ?, NULL, ?, 'rider-immediate')`,
      [
        riderId,
        amount,
        nextAppliedDays,
        rule.weekday || '',
        amount,
        rule.description || '자동차감 즉시 실행',
      ]
    );
    await run(
      `UPDATE auto_deduct_rules
       SET last_run_date = ?,
           applied_days = ?,
           deducted_amount = ?,
           enabled = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [today, nextAppliedDays, nextDeductedAmount, shouldDisable ? 0 : 1, rule.id]
    );
  });

  res.json({
    success: true,
    message: '자동차감 즉시 실행 완료 (지점 관리자 적립 반영)',
    deduction: {
      riderId,
      amount,
      appliedDays: nextAppliedDays,
      remainingDays: Math.max(totalDays - nextAppliedDays, 0),
      remainingAmount: Math.max(totalAmount - nextDeductedAmount, 0),
      branchId: rule.branchId || null,
    },
  });
}));

app.get('/api/riders/me/arrears', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['rider']);
  if (!session) {
    return;
  }

  const riderId = session.userId;
  const today = getTodayDateKey(new Date());

  const rule = await get(
    `SELECT id, rider_id AS riderId, enabled,
            daily_amount AS dailyAmount, total_amount AS totalAmount,
            total_days AS totalDays, deducted_amount AS deductedAmount,
            applied_days AS appliedDays, start_date AS startDate,
            weekday, description, last_run_date AS lastRunDate
     FROM auto_deduct_rules
     WHERE rider_id = ?`,
    [riderId]
  );

  if (!rule) {
    res.json({
      success: true,
      data: {
        hasRule: false,
        summary: {
          todayExpected: 0,
          todayActual: 0,
          todayMissed: 0,
          totalMissed: 0,
          missedDays: 0,
        },
        rows: [],
      },
    });
    return;
  }

  const totalAmount = Number(rule.totalAmount) || 0;
  const totalDays = Math.max(0, Number(rule.totalDays) || 0);
  const startEpoch = parseDateKeyToEpoch(rule.startDate);
  if (!Number.isFinite(startEpoch) || totalAmount <= 0 || totalDays <= 0) {
    res.json({
      success: true,
      data: {
        hasRule: true,
        rule,
        summary: {
          todayExpected: 0,
          todayActual: 0,
          todayMissed: 0,
          totalMissed: 0,
          missedDays: 0,
        },
        rows: [],
      },
    });
    return;
  }

  const logs = await all(
    `SELECT days_count AS daysCount, amount, created_at AS createdAt
     FROM deduction_logs
     WHERE rider_id = ? AND monthly_auto = 1
     ORDER BY created_at ASC, id ASC`,
    [riderId]
  );

  const paidByInstallment = new Map();
  for (const log of logs) {
    const idx = Number(log.daysCount) || 0;
    if (idx > 0 && idx <= totalDays && !paidByInstallment.has(idx)) {
      paidByInstallment.set(idx, log);
    }
  }

  const duePlan = [];
  const cursor = new Date(startEpoch);
  const maxIterations = Math.max(366, totalDays * 10);
  let installmentIndex = 1;
  let iteration = 0;

  while (installmentIndex <= totalDays && iteration < maxIterations) {
    const dateKey = getTodayDateKey(cursor);
    const isDueDate = !rule.weekday || KOREAN_WEEKDAYS[cursor.getDay()] === rule.weekday;
    if (isDueDate) {
      duePlan.push({
        installmentIndex,
        dateKey,
        expectedAmount: calculateInstallmentAmount(totalAmount, totalDays, installmentIndex - 1),
      });
      installmentIndex += 1;
    }
    cursor.setDate(cursor.getDate() + 1);
    iteration += 1;
  }

  const dueRows = duePlan
    .filter((entry) => entry.dateKey <= today)
    .map((entry) => {
      const paidLog = paidByInstallment.get(entry.installmentIndex);
      const paidDateKey = paidLog ? getTodayDateKey(new Date(paidLog.createdAt)) : '';
      const isPaidOnDueDate = paidLog && paidDateKey === entry.dateKey;
      const actualAmount = isPaidOnDueDate ? (Number(paidLog.amount) || 0) : 0;
      const shortfallAmount = Math.max(entry.expectedAmount - actualAmount, 0);
      return {
        installmentIndex: entry.installmentIndex,
        dateKey: entry.dateKey,
        expectedAmount: entry.expectedAmount,
        actualAmount,
        shortfallAmount,
        check: shortfallAmount <= 0 ? 'O' : 'X',
      };
    });

  const todayRow = dueRows.find((row) => row.dateKey === today) || null;
  const totalMissed = dueRows.reduce((sum, row) => sum + row.shortfallAmount, 0);
  const missedDays = dueRows.filter((row) => row.shortfallAmount > 0).length;

  res.json({
    success: true,
    data: {
      hasRule: true,
      rule,
      summary: {
        todayExpected: todayRow?.expectedAmount || 0,
        todayActual: todayRow?.actualAmount || 0,
        todayMissed: todayRow?.shortfallAmount || 0,
        totalMissed,
        missedDays,
      },
      rows: dueRows.reverse(),
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

  const rider = await get('SELECT id, branch_id FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && rider.branch_id !== session.branch_id) {
    sendError(res, 403, '해당 지점 기사 배달만 추가할 수 있습니다.');
    return;
  }

  const settlement = calculateSettlement(fare);
  const delivery = await transaction(async () => {
    const result = await run(
      `INSERT INTO deliveries (rider_id, fare, fee100, fee16, final, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)`,
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

  if (session.role === 'admin' && !isSuperAdmin(session)) {
    const scopedRider = await get('SELECT id, branch_id FROM riders WHERE id = ?', [delivery.riderId]);
    if (!scopedRider) {
      sendError(res, 404, '기사를 찾을 수 없습니다.');
      return;
    }
    if (scopedRider.branch_id !== session.branch_id) {
      sendError(res, 403, '해당 지점 기사 배달만 처리할 수 있습니다.');
      return;
    }
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

  const rider = await get('SELECT id, branch_id FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사 정보를 찾을 수 없습니다.');
    return;
  }

  if (session.role === 'rider' && riderId !== session.userId) {
    sendError(res, 403, '본인 정보만 수정할 수 있습니다.');
    return;
  }

  if (session.role === 'admin' && !isSuperAdmin(session) && rider.branch_id !== session.branch_id) {
    sendError(res, 403, '해당 지점 기사 정보만 수정할 수 있습니다.');
    return;
  }

  const beforeAutoRule = await get(
    `SELECT id, rider_id AS riderId, enabled, daily_amount AS dailyAmount,
            total_amount AS totalAmount, total_days AS totalDays,
            deducted_amount AS deductedAmount, applied_days AS appliedDays,
            start_date AS startDate, weekday, description,
            last_run_date AS lastRunDate
     FROM auto_deduct_rules
     WHERE rider_id = ?`,
    [riderId]
  );

  await run('UPDATE riders SET name = ?, bank = ?, account = ? WHERE id = ?', [name, bank, account, riderId]);

  const afterAutoRule = await get(
    `SELECT id, rider_id AS riderId, enabled, daily_amount AS dailyAmount,
            total_amount AS totalAmount, total_days AS totalDays,
            deducted_amount AS deductedAmount, applied_days AS appliedDays,
            start_date AS startDate, weekday, description,
            last_run_date AS lastRunDate
     FROM auto_deduct_rules
     WHERE rider_id = ?`,
    [riderId]
  );

  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [riderId]
  );
  res.json({
    success: true,
    message: '정보 저장 완료 (자동차감 설정 유지)',
    rider: updatedRider,
    autoDeduct: {
      preserved: true,
      before: beforeAutoRule || null,
      after: afterAutoRule || null,
    },
  });
}));

app.post('/api/withdrawals', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['admin', 'rider']);
  if (!session) {
    return;
  }
  const riderId = Number(req.body.riderId);
  const amount = Number(req.body.amount);
  const fee = WITHDRAWAL_FEE;
  const totalDeduction = amount + fee;

  if (!riderId || !Number.isFinite(amount) || amount <= 0) {
    sendError(res, 400, '출금 금액이 올바르지 않습니다.');
    return;
  }

  if (session.role === 'rider' && riderId !== session.userId) {
    sendError(res, 403, '본인 출금만 요청할 수 있습니다.');
    return;
  }

  const rider = await get('SELECT id, branch_id, balance FROM riders WHERE id = ?', [riderId]);
  if (!rider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }

  if (session.role === 'admin' && !isSuperAdmin(session) && rider.branch_id !== session.branch_id) {
    sendError(res, 403, '해당 지점 기사 출금만 처리할 수 있습니다.');
    return;
  }

  if (rider.balance < totalDeduction) {
    sendError(res, 400, `잔액이 부족합니다. (출금액 ${amount}원 + 출금수수료 ${fee}원)`);
    return;
  }

  const result = await transaction(async () => {
    await run('UPDATE riders SET balance = balance - ? WHERE id = ?', [totalDeduction, riderId]);
    const insertResult = await run(
      `INSERT INTO withdrawals (rider_id, amount, fee, status, processed_at)
       VALUES (?, ?, ?, 'approved', CURRENT_TIMESTAMP)`,
      [riderId, amount, fee]
    );
    await creditBusinessAccount(fee);
    return insertResult;
  });
  const createdWithdrawal = await get(
    `SELECT id, rider_id AS riderId, amount, fee, status,
            created_at AS createdAt, processed_at AS processedAt
     FROM withdrawals
     WHERE id = ?`,
    [result.lastID]
  );
  res.json({
    success: true,
    message: '출금 완료',
    withdrawal: createdWithdrawal,
  });
}));

app.post('/api/withdrawals/:withdrawalId/approve', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }
  const withdrawalId = Number(req.params.withdrawalId);
  const withdrawal = await get(
    'SELECT id, rider_id AS riderId, amount, fee, status FROM withdrawals WHERE id = ?',
    [withdrawalId]
  );

  if (!withdrawal) {
    sendError(res, 404, '출금 요청을 찾을 수 없습니다.');
    return;
  }

  const scopedRider = await get('SELECT id, branch_id FROM riders WHERE id = ?', [withdrawal.riderId]);
  if (!scopedRider) {
    sendError(res, 404, '기사를 찾을 수 없습니다.');
    return;
  }
  if (!isSuperAdmin(session) && scopedRider.branch_id !== session.branch_id) {
    sendError(res, 403, '해당 지점 기사 출금만 처리할 수 있습니다.');
    return;
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

  const withdrawalFee = Number(withdrawal.fee) || 0;
  const totalDeduction = withdrawal.amount + withdrawalFee;

  if (rider.balance < totalDeduction) {
    sendError(res, 400, '잔액 부족으로 승인할 수 없습니다.');
    return;
  }

  await transaction(async () => {
    await run('UPDATE riders SET balance = balance - ? WHERE id = ?', [totalDeduction, withdrawal.riderId]);
    await run(`UPDATE withdrawals SET status = 'approved', processed_at = CURRENT_TIMESTAMP WHERE id = ?`, [withdrawalId]);
    await creditBusinessAccount(withdrawalFee);
  });

  const updatedWithdrawal = await get(
    `SELECT id, rider_id AS riderId, amount, fee, status,
            created_at AS createdAt, processed_at AS processedAt
     FROM withdrawals
     WHERE id = ?`,
    [withdrawalId]
  );

  const updatedRider = await get(
    'SELECT id, username, name, balance, bank, account, branch_id FROM riders WHERE id = ?',
    [withdrawal.riderId]
  );
  res.json({
    success: true,
    message: '출금 승인 완료',
    withdrawal: updatedWithdrawal,
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

app.post('/api/notice', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const notice = String(req.body.notice || '').trim();
  if (notice.length > 500) {
    sendError(res, 400, '공지 내용은 500자 이하로 입력하세요.');
    return;
  }

  await run("UPDATE app_settings SET value = ? WHERE key = 'global_notice'", [notice]);
  res.json({ success: true, message: '공지 저장 완료', notice });
}));

app.get('/api/business-account', withErrorHandling(async (req, res) => {
  const session = requireSuperAdmin(req, res);
  if (!session) {
    return;
  }

  const state = await readState();
  res.json({
    success: true,
    data: state.businessAccount,
  });
}));

app.post('/api/business-account/link', withErrorHandling(async (req, res) => {
  const session = requireSuperAdmin(req, res);
  if (!session) {
    return;
  }

  const bankName = String(req.body.bankName || '').trim();
  const accountNumber = String(req.body.accountNumber || '').trim();
  const accountHolder = String(req.body.accountHolder || '').trim();

  if (!bankName || !accountNumber || !accountHolder) {
    sendError(res, 400, '은행명/계좌번호/예금주를 모두 입력해 주세요.');
    return;
  }

  const nowIso = new Date().toISOString();
  await transaction(async () => {
    await run("UPDATE app_settings SET value = ? WHERE key = 'business_account_bank'", [bankName]);
    await run("UPDATE app_settings SET value = ? WHERE key = 'business_account_number'", [accountNumber]);
    await run("UPDATE app_settings SET value = ? WHERE key = 'business_account_holder'", [accountHolder]);
    await run("UPDATE app_settings SET value = '1' WHERE key = 'business_account_linked'");
    await run("UPDATE app_settings SET value = ? WHERE key = 'business_account_linked_at'", [nowIso]);
  });

  const state = await readState();
  res.json({ success: true, message: '사업자 통장 연동 완료', data: state.businessAccount });
}));

app.post('/api/business-account/unlink', withErrorHandling(async (req, res) => {
  const session = requireSuperAdmin(req, res);
  if (!session) {
    return;
  }

  await run("UPDATE app_settings SET value = '0' WHERE key = 'business_account_linked'");
  const state = await readState();
  res.json({ success: true, message: '사업자 통장 연동 해제 완료', data: state.businessAccount });
}));

function formatBaeminBizIntegrationRow(row, fallbackBranchId = null, fallbackBranchName = '') {
  const branchId = row?.branchId || fallbackBranchId || null;
  const branchName = row?.branchName || fallbackBranchName || '';
  const apiKey = row?.apiKey || '';
  return {
    linked: Boolean(row?.linked),
    branchId,
    branchName,
    partnerId: row?.partnerId || '',
    storeId: row?.storeId || '',
    baseUrl: row?.baseUrl || '',
    apiKeyMasked: apiKey ? String(apiKey).replace(/.(?=.{4})/g, '*') : '',
    linkedAt: row?.linkedAt || '',
    lastSyncAt: row?.lastSyncAt || '',
  };
}

function normalizeUrl(url) {
  const text = String(url || '').trim();
  if (!text) {
    return '';
  }
  try {
    const parsed = new URL(text);
    return parsed.toString().replace(/\/$/, '');
  } catch (error) {
    return '';
  }
}

async function callBaeminConnectBizApi({ baseUrl, syncPath, apiKey, partnerId, storeId }) {
  return callPartnerConnectApi({
    providerLabel: '배민',
    baseUrl,
    syncPath,
    apiKey,
    partnerId,
    storeId,
    partnerHeaderName: 'X-Partner-Id',
  });
}

async function callCoupangPlusApi({ baseUrl, syncPath, apiKey, partnerId, storeId }) {
  return callPartnerConnectApi({
    providerLabel: '쿠팡플러스',
    baseUrl,
    syncPath,
    apiKey,
    partnerId,
    storeId,
    partnerHeaderName: 'X-Coupang-Partner-Id',
  });
}

async function callPartnerConnectApi({ providerLabel, baseUrl, syncPath, apiKey, partnerId, storeId, partnerHeaderName }) {
  if (typeof fetch !== 'function') {
    throw new Error('현재 서버 런타임에서 fetch를 사용할 수 없습니다.');
  }

  const cleanBase = normalizeUrl(baseUrl);
  if (!cleanBase) {
    throw new Error(`${providerLabel} API 베이스 URL이 올바르지 않습니다.`);
  }

  const cleanPath = String(syncPath || '/v1/orders').trim().startsWith('/')
    ? String(syncPath || '/v1/orders').trim()
    : `/${String(syncPath || '/v1/orders').trim()}`;

  const url = new URL(`${cleanBase}${cleanPath}`);
  if (storeId) {
    url.searchParams.set('storeId', storeId);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        [partnerHeaderName]: partnerId || '',
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    const rawText = await response.text();
    let payload = null;
    try {
      payload = rawText ? JSON.parse(rawText) : null;
    } catch (error) {
      payload = rawText;
    }

    if (!response.ok) {
      const shortBody = typeof payload === 'string'
        ? payload.slice(0, 400)
        : JSON.stringify(payload).slice(0, 400);
      throw new Error(`${providerLabel} API 호출 실패 (${response.status}): ${shortBody}`);
    }

    let importedOrders = 0;
    let importedRevenue = 0;
    if (Array.isArray(payload)) {
      importedOrders = payload.length;
    } else if (payload && Array.isArray(payload.orders)) {
      importedOrders = payload.orders.length;
    } else if (payload && payload.data && Array.isArray(payload.data)) {
      importedOrders = payload.data.length;
    }

    const pickRevenue = (value) => {
      const num = Number(value);
      if (Number.isFinite(num) && num >= 0) {
        return Math.round(num);
      }
      return null;
    };

    const directRevenue = pickRevenue(payload?.totalRevenue)
      ?? pickRevenue(payload?.revenue)
      ?? pickRevenue(payload?.amount)
      ?? pickRevenue(payload?.total_amount)
      ?? pickRevenue(payload?.summary?.totalRevenue)
      ?? pickRevenue(payload?.data?.totalRevenue);

    if (directRevenue != null) {
      importedRevenue = directRevenue;
    } else {
      const orders = Array.isArray(payload)
        ? payload
        : (Array.isArray(payload?.orders)
          ? payload.orders
          : (Array.isArray(payload?.data)
            ? payload.data
            : []));

      importedRevenue = orders.reduce((sum, item) => {
        const orderAmount = pickRevenue(item?.amount)
          ?? pickRevenue(item?.price)
          ?? pickRevenue(item?.totalAmount)
          ?? pickRevenue(item?.total_price)
          ?? 0;
        return sum + orderAmount;
      }, 0);
    }

    return { importedOrders, importedRevenue, payload };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function resolveBaeminTargetBranchId(session, rawBranchId) {
  if (!isSuperAdmin(session)) {
    return session.branch_id || null;
  }

  const requested = Number(rawBranchId);
  if (!Number.isInteger(requested) || requested <= 0) {
    return null;
  }
  return requested;
}

async function resolveCoupangTargetBranchId(session, rawBranchId) {
  return resolveBaeminTargetBranchId(session, rawBranchId);
}

async function findBaeminIntegrationByBranchId(branchId) {
  return get(
    `SELECT bbi.branch_id AS branchId, b.name AS branchName,
            bbi.linked, bbi.partner_id AS partnerId,
            bbi.store_id AS storeId, bbi.api_key AS apiKey,
            bbi.base_url AS baseUrl,
            bbi.linked_at AS linkedAt, bbi.last_sync_at AS lastSyncAt
     FROM baemin_biz_integrations bbi
     JOIN branches b ON b.id = bbi.branch_id
     WHERE bbi.branch_id = ?`,
    [branchId]
  );
}

async function findCoupangIntegrationByBranchId(branchId) {
  return get(
    `SELECT cpi.branch_id AS branchId, b.name AS branchName,
            cpi.linked, cpi.partner_id AS partnerId,
            cpi.store_id AS storeId, cpi.api_key AS apiKey,
            cpi.base_url AS baseUrl,
            cpi.linked_at AS linkedAt, cpi.last_sync_at AS lastSyncAt
     FROM coupang_plus_integrations cpi
     JOIN branches b ON b.id = cpi.branch_id
     WHERE cpi.branch_id = ?`,
    [branchId]
  );
}

function filterLeaderboardBySessionBranch(session, rows) {
  if (session?.role !== 'admin') {
    return rows;
  }
  if (isSuperAdmin(session)) {
    return rows;
  }
  return rows.filter((row) => row.branchId === session.branch_id);
}

async function getBranchLeaderboardRows(tableName) {
  return all(
    `SELECT b.id AS branchId,
            b.name AS branchName,
            COALESCE(SUM(log.imported_orders), 0) AS totalOrders,
            COUNT(log.id) AS syncCount,
            MAX(log.synced_at) AS lastSyncedAt
     FROM branches b
     LEFT JOIN ${tableName} log ON log.branch_id = b.id
     GROUP BY b.id, b.name
     ORDER BY totalOrders DESC, syncCount DESC, b.name ASC`
  );
}

async function getPlatformProfitSummary() {
  const [baeminProfitRow, coupangProfitRow, baeminSyncRow, coupangSyncRow] = await Promise.all([
    get('SELECT COALESCE(SUM(imported_revenue), 0) AS totalRevenue FROM baemin_biz_sync_logs'),
    get('SELECT COALESCE(SUM(imported_revenue), 0) AS totalRevenue FROM coupang_plus_sync_logs'),
    get('SELECT COUNT(*) AS syncCount FROM baemin_biz_sync_logs'),
    get('SELECT COUNT(*) AS syncCount FROM coupang_plus_sync_logs'),
  ]);

  const baeminRevenue = Number(baeminProfitRow?.totalRevenue || 0);
  const coupangRevenue = Number(coupangProfitRow?.totalRevenue || 0);
  return {
    baeminRevenue,
    coupangRevenue,
    totalRevenue: baeminRevenue + coupangRevenue,
    baeminSyncCount: Number(baeminSyncRow?.syncCount || 0),
    coupangSyncCount: Number(coupangSyncRow?.syncCount || 0),
  };
}

app.get('/api/baemin-biz', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveBaeminTargetBranchId(session, req.query.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 조회할 수 있습니다.');
    return;
  }

  const found = await findBaeminIntegrationByBranchId(branchId);
  res.json({
    success: true,
    data: formatBaeminBizIntegrationRow(found, branch.id, branch.name),
  });
}));

app.post('/api/baemin-biz/link', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveBaeminTargetBranchId(session, req.body.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 설정할 수 있습니다.');
    return;
  }

  const partnerId = String(req.body.partnerId || '').trim();
  const storeId = String(req.body.storeId || '').trim();
  const apiKey = String(req.body.apiKey || '').trim();
  const baseUrl = normalizeUrl(req.body.baseUrl || '');
  if (!partnerId || !storeId || !apiKey) {
    sendError(res, 400, '파트너 ID, 스토어 ID, API 키를 모두 입력해 주세요.');
    return;
  }

  if (!baseUrl) {
    sendError(res, 400, '배민커넥트비즈 API 베이스 URL을 입력해 주세요.');
    return;
  }

  const nowIso = new Date().toISOString();
  await run(
    `INSERT INTO baemin_biz_integrations
     (branch_id, linked, partner_id, store_id, api_key, base_url, linked_at, updated_at)
     VALUES (?, 1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(branch_id) DO UPDATE SET
       linked = 1,
       partner_id = excluded.partner_id,
       store_id = excluded.store_id,
       api_key = excluded.api_key,
       base_url = excluded.base_url,
       linked_at = excluded.linked_at,
       updated_at = CURRENT_TIMESTAMP`,
    [branchId, partnerId, storeId, apiKey, baseUrl, nowIso]
  );

  const found = await findBaeminIntegrationByBranchId(branchId);
  res.json({
    success: true,
    message: `${branch.name} 배민비즈 연동 저장 완료`,
    data: formatBaeminBizIntegrationRow(found, branch.id, branch.name),
  });
}));

app.post('/api/baemin-biz/unlink', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveBaeminTargetBranchId(session, req.body.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 해제할 수 있습니다.');
    return;
  }

  await run(
    `INSERT INTO baemin_biz_integrations
     (branch_id, linked, partner_id, store_id, api_key, base_url, linked_at, updated_at)
     VALUES (?, 0, '', '', '', '', NULL, CURRENT_TIMESTAMP)
     ON CONFLICT(branch_id) DO UPDATE SET
       linked = 0,
       partner_id = '',
       store_id = '',
       api_key = '',
       base_url = '',
       updated_at = CURRENT_TIMESTAMP`,
    [branchId]
  );

  const found = await findBaeminIntegrationByBranchId(branchId);
  res.json({
    success: true,
    message: `${branch.name} 배민비즈 연동 해제 완료`,
    data: formatBaeminBizIntegrationRow(found, branch.id, branch.name),
  });
}));

app.post('/api/baemin-biz/sync', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveBaeminTargetBranchId(session, req.body.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 동기화할 수 있습니다.');
    return;
  }

  const found = await findBaeminIntegrationByBranchId(branchId);
  if (!found || !found.linked) {
    sendError(res, 400, '해당 지점은 배민비즈가 연동되어 있지 않습니다.');
    return;
  }

  const syncPath = String(req.body.syncPath || '/v1/orders').trim();
  const syncResult = await callBaeminConnectBizApi({
    baseUrl: found.baseUrl,
    syncPath,
    apiKey: found.apiKey,
    partnerId: found.partnerId,
    storeId: found.storeId,
  });

  const nowIso = new Date().toISOString();
  await run(
    `UPDATE baemin_biz_integrations
     SET last_sync_at = ?, updated_at = CURRENT_TIMESTAMP
     WHERE branch_id = ?`,
    [nowIso, branchId]
  );

  await run(
    `INSERT INTO baemin_biz_sync_logs (branch_id, imported_orders, imported_revenue, synced_at)
     VALUES (?, ?, ?, ?)`,
    [branchId, Number(syncResult.importedOrders) || 0, Number(syncResult.importedRevenue) || 0, nowIso]
  );

  res.json({
    success: true,
    message: `${branch.name} 배민비즈 동기화 완료`,
    data: {
      branchId,
      syncedAt: nowIso,
      importedOrders: syncResult.importedOrders || 0,
      importedRevenue: Number(syncResult.importedRevenue) || 0,
      importedRiders: 0,
      endpoint: syncPath,
    },
  });
}));

app.get('/api/coupang-plus', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveCoupangTargetBranchId(session, req.query.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 조회할 수 있습니다.');
    return;
  }

  const found = await findCoupangIntegrationByBranchId(branchId);
  res.json({
    success: true,
    data: formatBaeminBizIntegrationRow(found, branch.id, branch.name),
  });
}));

app.post('/api/coupang-plus/link', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveCoupangTargetBranchId(session, req.body.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 설정할 수 있습니다.');
    return;
  }

  const partnerId = String(req.body.partnerId || '').trim();
  const storeId = String(req.body.storeId || '').trim();
  const apiKey = String(req.body.apiKey || '').trim();
  const baseUrl = normalizeUrl(req.body.baseUrl || '');
  if (!partnerId || !storeId || !apiKey) {
    sendError(res, 400, '파트너 ID, 스토어 ID, API 키를 모두 입력해 주세요.');
    return;
  }

  if (!baseUrl) {
    sendError(res, 400, '쿠팡플러스 API 베이스 URL을 입력해 주세요.');
    return;
  }

  const nowIso = new Date().toISOString();
  await run(
    `INSERT INTO coupang_plus_integrations
     (branch_id, linked, partner_id, store_id, api_key, base_url, linked_at, updated_at)
     VALUES (?, 1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(branch_id) DO UPDATE SET
       linked = 1,
       partner_id = excluded.partner_id,
       store_id = excluded.store_id,
       api_key = excluded.api_key,
       base_url = excluded.base_url,
       linked_at = excluded.linked_at,
       updated_at = CURRENT_TIMESTAMP`,
    [branchId, partnerId, storeId, apiKey, baseUrl, nowIso]
  );

  const found = await findCoupangIntegrationByBranchId(branchId);
  res.json({
    success: true,
    message: `${branch.name} 쿠팡플러스 연동 저장 완료`,
    data: formatBaeminBizIntegrationRow(found, branch.id, branch.name),
  });
}));

app.post('/api/coupang-plus/unlink', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveCoupangTargetBranchId(session, req.body.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 해제할 수 있습니다.');
    return;
  }

  await run(
    `INSERT INTO coupang_plus_integrations
     (branch_id, linked, partner_id, store_id, api_key, base_url, linked_at, updated_at)
     VALUES (?, 0, '', '', '', '', NULL, CURRENT_TIMESTAMP)
     ON CONFLICT(branch_id) DO UPDATE SET
       linked = 0,
       partner_id = '',
       store_id = '',
       api_key = '',
       base_url = '',
       updated_at = CURRENT_TIMESTAMP`,
    [branchId]
  );

  const found = await findCoupangIntegrationByBranchId(branchId);
  res.json({
    success: true,
    message: `${branch.name} 쿠팡플러스 연동 해제 완료`,
    data: formatBaeminBizIntegrationRow(found, branch.id, branch.name),
  });
}));

app.post('/api/coupang-plus/sync', withErrorHandling(async (req, res) => {
  const session = requireAdmin(req, res);
  if (!session) {
    return;
  }

  const branchId = await resolveCoupangTargetBranchId(session, req.body.branchId);
  if (!branchId) {
    sendError(res, 400, '지점을 선택해 주세요.');
    return;
  }

  const branch = await get('SELECT id, name FROM branches WHERE id = ?', [branchId]);
  if (!branch) {
    sendError(res, 404, '지점을 찾을 수 없습니다.');
    return;
  }

  if (!isSuperAdmin(session) && session.branch_id !== branchId) {
    sendError(res, 403, '본인 지점만 동기화할 수 있습니다.');
    return;
  }

  const found = await findCoupangIntegrationByBranchId(branchId);
  if (!found || !found.linked) {
    sendError(res, 400, '해당 지점은 쿠팡플러스가 연동되어 있지 않습니다.');
    return;
  }

  const syncPath = String(req.body.syncPath || '/v1/orders').trim();
  const syncResult = await callCoupangPlusApi({
    baseUrl: found.baseUrl,
    syncPath,
    apiKey: found.apiKey,
    partnerId: found.partnerId,
    storeId: found.storeId,
  });

  const nowIso = new Date().toISOString();
  await run(
    `UPDATE coupang_plus_integrations
     SET last_sync_at = ?, updated_at = CURRENT_TIMESTAMP
     WHERE branch_id = ?`,
    [nowIso, branchId]
  );

  await run(
    `INSERT INTO coupang_plus_sync_logs (branch_id, imported_orders, imported_revenue, synced_at)
     VALUES (?, ?, ?, ?)`,
    [branchId, Number(syncResult.importedOrders) || 0, Number(syncResult.importedRevenue) || 0, nowIso]
  );

  res.json({
    success: true,
    message: `${branch.name} 쿠팡플러스 동기화 완료`,
    data: {
      branchId,
      syncedAt: nowIso,
      importedOrders: syncResult.importedOrders || 0,
      importedRevenue: Number(syncResult.importedRevenue) || 0,
      importedRiders: 0,
      endpoint: syncPath,
    },
  });
}));

app.get('/api/platform-profits', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['admin', 'rider']);
  if (!session) {
    return;
  }

  const summary = await getPlatformProfitSummary();
  res.json({
    success: true,
    data: summary,
  });
}));

app.get('/api/branch-leaderboards', withErrorHandling(async (req, res) => {
  const session = requireRole(req, res, ['admin', 'rider']);
  if (!session) {
    return;
  }

  const [baeminRows, coupangRows] = await Promise.all([
    getBranchLeaderboardRows('baemin_biz_sync_logs'),
    getBranchLeaderboardRows('coupang_plus_sync_logs'),
  ]);

  res.json({
    success: true,
    data: {
      baemin: filterLeaderboardBySessionBranch(session, baeminRows),
      coupang: filterLeaderboardBySessionBranch(session, coupangRows),
    },
  });
}));

function getTodayDateKey(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function parseDateKeyToEpoch(dateKey) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(dateKey || ''))) {
    return NaN;
  }
  return Date.parse(`${dateKey}T00:00:00`);
}

function calculateInstallmentAmount(totalAmount, totalDays, appliedDays) {
  const safeTotal = Math.max(0, Number(totalAmount) || 0);
  const safeDays = Math.max(1, Number(totalDays) || 1);
  const safeApplied = Math.max(0, Number(appliedDays) || 0);
  const base = Math.floor(safeTotal / safeDays);
  const remainder = safeTotal % safeDays;
  return base + (safeApplied < remainder ? 1 : 0);
}

async function creditBranchAdmins(branchId, amount) {
  if (!branchId || amount <= 0) {
    return;
  }

  const admins = await all('SELECT id FROM admins WHERE branch_id = ? ORDER BY id', [branchId]);
  if (admins.length === 0) {
    return;
  }

  const share = Math.floor(amount / admins.length);
  const remainder = amount % admins.length;

  for (let index = 0; index < admins.length; index += 1) {
    const bonus = index < remainder ? 1 : 0;
    const credit = share + bonus;
    if (credit > 0) {
      await run('UPDATE admins SET balance = balance + ? WHERE id = ?', [credit, admins[index].id]);
    }
  }
}

async function runAutoDeductionCycle() {
  const now = new Date();
  const today = getTodayDateKey(now);
  const todayWeekday = KOREAN_WEEKDAYS[now.getDay()];

  const rules = await all(
    `SELECT adr.id, adr.rider_id AS riderId, adr.enabled,
            adr.daily_amount AS dailyAmount, adr.total_amount AS totalAmount,
            adr.total_days AS totalDays, adr.deducted_amount AS deductedAmount,
            adr.applied_days AS appliedDays, adr.start_date AS startDate,
            adr.weekday, adr.description, adr.last_run_date AS lastRunDate,
            r.balance, r.branch_id AS branchId
     FROM auto_deduct_rules adr
     JOIN riders r ON r.id = adr.rider_id
     WHERE adr.enabled = 1`
  );

  for (const rule of rules) {
    const totalAmount = Number(rule.totalAmount) || 0;
    const totalDays = Number(rule.totalDays) || 0;
    const appliedDays = Number(rule.appliedDays) || 0;
    const deductedAmount = Number(rule.deductedAmount) || 0;

    if (totalAmount <= 0 || totalDays <= 0) {
      continue;
    }

    if (appliedDays >= totalDays || deductedAmount >= totalAmount) {
      await run(
        'UPDATE auto_deduct_rules SET enabled = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [rule.id]
      );
      continue;
    }

    const startEpoch = parseDateKeyToEpoch(rule.startDate);
    const todayEpoch = parseDateKeyToEpoch(today);
    if (Number.isFinite(startEpoch) && Number.isFinite(todayEpoch) && todayEpoch < startEpoch) {
      continue;
    }

    const amount = calculateInstallmentAmount(totalAmount, totalDays, appliedDays);
    if (amount <= 0) {
      continue;
    }

    if (rule.weekday && rule.weekday !== todayWeekday) {
      continue;
    }

    if (rule.lastRunDate === today) {
      continue;
    }

    if (Number(rule.balance) < amount) {
      continue;
    }

    const nextAppliedDays = appliedDays + 1;
    const nextDeductedAmount = Math.min(totalAmount, deductedAmount + amount);
    const shouldDisable = nextAppliedDays >= totalDays || nextDeductedAmount >= totalAmount;

    await transaction(async () => {
      await run('UPDATE riders SET balance = balance - ? WHERE id = ?', [amount, rule.riderId]);
      if (rule.branchId) {
        await run('UPDATE branches SET balance = balance + ? WHERE id = ?', [amount, rule.branchId]);
        await creditBranchAdmins(rule.branchId, amount);
      }
      await run(
        `INSERT INTO deduction_logs
         (rider_id, amount, days_count, weekday, monthly_auto, daily_amount, total_days, description, created_by_role)
         VALUES (?, ?, ?, ?, 1, ?, NULL, ?, 'system')`,
        [
          rule.riderId,
          amount,
          nextAppliedDays,
          rule.weekday || todayWeekday,
          amount,
          rule.description || '자동차감',
        ]
      );
      await run(
        `UPDATE auto_deduct_rules
         SET last_run_date = ?,
             applied_days = ?,
             deducted_amount = ?,
             enabled = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [today, nextAppliedDays, nextDeductedAmount, shouldDisable ? 0 : 1, rule.id]
      );
    });
  }
}

function startAutoDeductionScheduler() {
  setInterval(() => {
    runAutoDeductionCycle().catch((error) => {
      console.error('자동차감 실행 실패:', error);
    });
  }, AUTO_DEDUCT_INTERVAL_MS);
}

initializeDatabase()
  .then(() => {
    startAutoDeductionScheduler();
    runAutoDeductionCycle().catch((error) => {
      console.error('자동차감 초기 실행 실패:', error);
    });
    app.listen(PORT, () => {
      console.log(`배달 정산 시스템 서버가 ${PORT}번 포트에서 실행 중입니다.`);
    });
  })
  .catch((error) => {
    console.error('데이터베이스 초기화 실패:', error);
    process.exit(1);
  });
