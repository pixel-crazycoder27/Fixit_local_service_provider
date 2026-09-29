const { createServer } = require('node:http');
const { readFile } = require('node:fs/promises');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { promisify } = require('node:util');
const { randomBytes, scrypt: scryptCallback, timingSafeEqual, createHash } = require('node:crypto');

const scrypt = promisify(scryptCallback);
const databasePath = process.env.DB_PATH || path.join(__dirname, 'fixit.sqlite');
const database = new DatabaseSync(databasePath);
database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('customer', 'provider')),
        zip TEXT NOT NULL,
        phone TEXT NOT NULL,
        trade TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
`);

const contentTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml'
};

function sendJson(response, status, data) {
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end(JSON.stringify(data));
}

function readJson(request) {
    return new Promise((resolve, reject) => {
        let body = '';
        request.setEncoding('utf8');
        request.on('data', chunk => {
            body += chunk;
            if (body.length > 10_000) {
                reject(Object.assign(new Error('Request body is too large.'), { status: 413 }));
                request.destroy();
            }
        });
        request.on('end', () => {
            try {
                resolve(JSON.parse(body || '{}'));
            } catch {
                reject(Object.assign(new Error('Invalid JSON.'), { status: 400 }));
            }
        });
        request.on('error', reject);
    });
}

function publicUser(row) {
    return {
        id: row.id,
        name: row.name,
        email: row.email,
        role: row.role,
        zip: row.zip,
        phone: row.phone,
        trade: row.trade
    };
}

function getSessionToken(request) {
    const cookies = request.headers.cookie || '';
    const sessionCookie = cookies.split(';').map(value => value.trim()).find(value => value.startsWith('fixit_session='));
    return sessionCookie ? decodeURIComponent(sessionCookie.slice('fixit_session='.length)) : '';
}

function createSession(response, userId) {
    const token = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    database.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
        .run(tokenHash, userId, expiresAt);
    response.setHeader('Set-Cookie', `fixit_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800`);
}

function findSessionUser(request) {
    const token = getSessionToken(request);
    if (!token) return null;

    const tokenHash = createHash('sha256').update(token).digest('hex');
    const row = database.prepare(`
        SELECT users.* FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).get(tokenHash, Date.now());
    return row || null;
}

async function handleApi(request, response, url) {
    if (request.method === 'GET' && url.pathname === '/api/auth/session') {
        const user = findSessionUser(request);
        if (!user) return sendJson(response, 200, { user: null });
        return sendJson(response, 200, { user: publicUser(user) });
    }

    if (request.method === 'POST' && url.pathname === '/api/auth/register') {
        const body = await readJson(request);
        const name = typeof body.name === 'string' ? body.name.trim() : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        const role = body.role;
        const zip = typeof body.zip === 'string' ? body.zip.trim() : '';
        const phone = typeof body.phone === 'string' ? body.phone.trim() : '';
        const trade = typeof body.trade === 'string' ? body.trade.trim() : '';

        if (!name || name.length > 100 || !/^\S+@\S+\.\S+$/.test(email) || email.length > 254) {
            return sendJson(response, 400, { error: 'Enter a valid name and email address.' });
        }
        if (password.length < 8 || password.length > 256) {
            return sendJson(response, 400, { error: 'Password must be between 8 and 256 characters.' });
        }
        if (!['customer', 'provider'].includes(role) || !zip || zip.length > 20 || !phone || phone.length > 40) {
            return sendJson(response, 400, { error: 'Complete all required account details.' });
        }

        const salt = randomBytes(16).toString('hex');
        const passwordHash = (await scrypt(password, salt, 64)).toString('hex');
        let result;
        try {
            result = database.prepare(`
                INSERT INTO users (name, email, password_hash, role, zip, phone, trade)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).run(name, email, `${salt}:${passwordHash}`, role, zip, phone, role === 'provider' ? trade : null);
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                return sendJson(response, 409, { error: 'An account with this email already exists.' });
            }
            throw error;
        }

        const user = database.prepare('SELECT * FROM users WHERE id = ?').get(Number(result.lastInsertRowid));
        createSession(response, user.id);
        return sendJson(response, 201, { user: publicUser(user) });
    }

    if (request.method === 'POST' && url.pathname === '/api/auth/login') {
        const body = await readJson(request);
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        const role = body.role;
        const user = database.prepare('SELECT * FROM users WHERE email = ? AND role = ?').get(email, role);
        if (!user || !password) return sendJson(response, 401, { error: 'Email, password, or account type is incorrect.' });

        const [salt, storedHash] = user.password_hash.split(':');
        const suppliedHash = Buffer.from(await scrypt(password, salt, 64)).toString('hex');
        if (!timingSafeEqual(Buffer.from(storedHash, 'hex'), Buffer.from(suppliedHash, 'hex'))) {
            return sendJson(response, 401, { error: 'Email, password, or account type is incorrect.' });
        }

        createSession(response, user.id);
        return sendJson(response, 200, { user: publicUser(user) });
    }

    if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
        const token = getSessionToken(request);
        if (token) {
            const tokenHash = createHash('sha256').update(token).digest('hex');
            database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
        }
        response.setHeader('Set-Cookie', 'fixit_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
        return sendJson(response, 200, { user: null });
    }

    return sendJson(response, 404, { error: 'Not found.' });
}

const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://localhost');
    try {
        if (url.pathname.startsWith('/api/')) return await handleApi(request, response, url);

        const requestPath = decodeURIComponent(url.pathname);
        const fileName = requestPath === '/' ? 'fixit_service_marketplace (1).html' : requestPath.slice(1);
        const filePath = path.resolve(__dirname, fileName);
        if (!filePath.startsWith(`${__dirname}${path.sep}`)) {
            response.writeHead(403).end('Forbidden');
            return;
        }

        const file = await readFile(filePath);
        response.writeHead(200, {
            'Content-Type': contentTypes[path.extname(filePath)] || 'application/octet-stream',
            'X-Content-Type-Options': 'nosniff',
            'Cache-Control': path.extname(filePath) === '.html' ? 'no-store' : 'public, max-age=3600'
        });
        response.end(file);
    } catch (error) {
        if (response.headersSent || response.destroyed) return;
        if (error.code === 'ENOENT') return sendJson(response, 404, { error: 'Not found.' });
        sendJson(response, error.status || 500, { error: error.status ? error.message : 'Server error.' });
        if (!error.status) console.error(error);
    }
});

database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
const port = Number(process.env.PORT) || 3000;
server.listen(port, () => console.log(`FixIt is running at http://localhost:${port}`));