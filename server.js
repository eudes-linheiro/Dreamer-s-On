const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { promisify } = require('node:util');
const {
  createHash,
  randomBytes,
  scrypt,
  timingSafeEqual,
} = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const scryptAsync = promisify(scrypt);
const passwordRecovery = import('./functions/_shared/password-recovery.mjs');
const ROOT = __dirname;
const SESSION_COOKIE = 'dreamers_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_BODY_SIZE = 16 * 1024;
const MAX_PROFILE_PHOTO_BYTES = 2 * 1024 * 1024;
const MAX_PROFILE_PHOTO_BODY_SIZE = Math.ceil(MAX_PROFILE_PHOTO_BYTES * 4 / 3) + 512;
const STATIC_CACHE_TTL_MS = 60 * 60 * 1000;
const STATIC_CACHE = new Map();
const PUBLIC_PAGES = new Set([
  'index.html',
  'about.html',
  'account.html',
  'contact.html',
  'course-payments.html',
  'education.html',
  'forgotpassword.html',
  'login.html',
  'profile.html',
  'signup.html',
  'arts.html',
  'sports.html',
  'technology.html',
  'terms.html',
  'privacy.html',
]);
const PUBLIC_DIRECTORIES = ['css', 'font-awesome', 'img-asset', 'js'];
const COURSES = [
  { id: 'english-foundations', title: 'English foundations', category: 'Language' },
  { id: 'french-essentials', title: 'French essentials', category: 'Language' },
  { id: 'music-theory', title: 'Music theory', category: 'Music' },
  { id: 'music-production', title: 'Music production', category: 'Music' },
];
const CONTENT_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.eot': 'application/vnd.ms-fontobject',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ttf': 'font/ttf',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function sendJson(response, status, body, headers = {}) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function purgeExpiredSessions(database) {
  database.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(Date.now());
}

async function readJson(request, maxBytes = MAX_BODY_SIZE) {
  const contentType = request.headers['content-type'] || '';
  if (!contentType.toLowerCase().startsWith('application/json')) {
    throw httpError(415, 'Content-Type must be application/json.');
  }

  const contentLength = Number(request.headers['content-length'] || 0);
  if (contentLength > maxBytes) {
    throw httpError(413, 'Request body is too large.');
  }

  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) {
      throw httpError(413, 'Request body is too large.');
    }
    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw httpError(400, 'Request body must contain valid JSON.');
  }
}

function decodeProfilePhoto(dataUrl) {
  const match = typeof dataUrl === 'string'
    && /^data:(image\/jpeg|image\/png|image\/webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(dataUrl);
  if (!match) {
    throw httpError(400, 'Choose a JPEG, PNG, or WebP profile photo.');
  }

  const photo = Buffer.from(match[2], 'base64');
  if (photo.length === 0 || photo.length > MAX_PROFILE_PHOTO_BYTES || photo.toString('base64') !== match[2]) {
    throw httpError(400, 'Profile photos must be 2 MB or smaller.');
  }

  const isJpeg = match[1] === 'image/jpeg'
    && photo.length >= 4
    && photo[0] === 0xff && photo[1] === 0xd8 && photo[2] === 0xff
    && photo[photo.length - 2] === 0xff && photo[photo.length - 1] === 0xd9;
  const isPng = match[1] === 'image/png'
    && photo.length >= 8
    && photo.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  const isWebp = match[1] === 'image/webp'
    && photo.length >= 12
    && photo.toString('ascii', 0, 4) === 'RIFF'
    && photo.toString('ascii', 8, 12) === 'WEBP';
  if (!isJpeg && !isPng && !isWebp) {
    throw httpError(400, 'The selected file is not a valid JPEG, PNG, or WebP image.');
  }

  return { data: photo, mimeType: match[1] };
}

function normalizeIdentifier(value) {
  if (typeof value !== 'string') {
    throw httpError(400, 'Enter a valid email address or phone number.');
  }

  const identifier = value.trim();
  if (identifier.includes('@')) {
    return normalizeEmail(identifier);
  }

  if (!/^\+?[\d\s().-]+$/.test(identifier)) {
    throw httpError(400, 'Enter a valid Angola phone number with 9 digits and country code +244.');
  }
  const compact = identifier.replace(/[\s().-]/g, '');
  let nationalNumber = compact;
  if (compact.startsWith('+244')) {
    nationalNumber = compact.slice(4);
  } else if (compact.startsWith('00244')) {
    nationalNumber = compact.slice(5);
  } else if (compact.startsWith('244') && compact.length === 12) {
    nationalNumber = compact.slice(3);
  }
  if (!/^[2-9]\d{8}$/.test(nationalNumber)) {
    throw httpError(400, 'Enter a valid Angola phone number with 9 digits and country code +244.');
  }
  return `+244${nationalNumber}`;
}

function normalizeEmail(value) {
  if (typeof value !== 'string') {
    throw httpError(400, 'Enter a valid email address.');
  }
  const email = value.trim().toLowerCase();
  const [localPart, ...domainParts] = email.split('@');
  const domain = domainParts.join('@');
  const validLocalPart = localPart && localPart.length <= 64
    && !localPart.startsWith('.') && !localPart.endsWith('.') && !localPart.includes('..')
    && /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(localPart);
  const validDomain = domain.length <= 253
    && domain.includes('.')
    && domain.split('.').every((label) => (
      label.length > 0 && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
    ));
  if (!validLocalPart || !validDomain || email.length > 254) {
    throw httpError(400, 'Enter a valid email address.');
  }
  return email;
}

function getName(value, field) {
  if (typeof value !== 'string') {
    throw httpError(400, `Enter your ${field}.`);
  }
  const name = value.trim();
  if (!name || name.length > 80) {
    throw httpError(400, `Enter a ${field} up to 80 characters long.`);
  }
  return name;
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    throw httpError(400, 'Password must be between 8 and 128 characters.');
  }
}

async function hashPassword(password, salt = randomBytes(16)) {
  const hash = await scryptAsync(password, salt, 64);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

async function passwordMatches(password, saltHex, hashHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const expected = Buffer.from(hashHex, 'hex');
  const actual = await scryptAsync(password, salt, expected.length);
  return timingSafeEqual(expected, actual);
}

function hashSession(token) {
  return createHash('sha256').update(token).digest('hex');
}

function getStaticCacheControl(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.html') {
    return 'no-cache';
  }
  if (['.js', '.css', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.woff', '.woff2', '.ttf', '.eot'].includes(ext)) {
    return 'public, max-age=31536000, immutable';
  }
  return 'public, max-age=86400';
}

function getFileEtag(content) {
  return `"${createHash('sha1').update(content).digest('hex')}"`;
}

async function readCachedStaticFile(filePath) {
  const cached = STATIC_CACHE.get(filePath);
  const now = Date.now();
  if (cached && cached.expiresAt > now) {
    return cached.content;
  }

  const content = await fs.promises.readFile(filePath);
  STATIC_CACHE.set(filePath, {
    content,
    expiresAt: now + STATIC_CACHE_TTL_MS,
  });
  return content;
}

function isPublicFile(relativePath) {
  if (PUBLIC_PAGES.has(relativePath)) {
    return true;
  }
  return PUBLIC_DIRECTORIES.some((directory) => relativePath.startsWith(`${directory}/`));
}

function createAuthServer({
  databasePath = process.env.AUTH_DB_PATH || path.join(ROOT, 'data', 'auth.sqlite'),
  secureCookies = process.env.NODE_ENV === 'production',
  environment = process.env,
  sendRecoveryCode,
} = {}) {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  const database = new DatabaseSync(databasePath);
  database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      identifier TEXT NOT NULL UNIQUE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      photo_data BLOB,
      photo_mime TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS password_reset_codes (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      code_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
      requested_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS contact_messages (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS courses (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS course_enrollments (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      enrolled_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, course_id)
    );
    CREATE TABLE IF NOT EXISTS course_payment_requests (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id TEXT NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      transaction_reference TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
      created_at INTEGER NOT NULL,
      reviewed_at INTEGER,
      reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS one_pending_course_payment
      ON course_payment_requests (user_id, course_id)
      WHERE status = 'pending';
    CREATE INDEX IF NOT EXISTS course_payment_requests_status_created
      ON course_payment_requests (status, created_at);
  `);
  const insertCourse = database.prepare(
    'INSERT INTO courses (id, title, category) VALUES (?, ?, ?) ON CONFLICT (id) DO NOTHING',
  );
  COURSES.forEach((course) => insertCourse.run(course.id, course.title, course.category));
  const userColumns = new Set(database.prepare('PRAGMA table_info(users)').all().map((column) => column.name));
  if (!userColumns.has('photo_data')) {
    database.exec('ALTER TABLE users ADD COLUMN photo_data BLOB');
  }
  if (!userColumns.has('photo_mime')) {
    database.exec('ALTER TABLE users ADD COLUMN photo_mime TEXT');
  }

  purgeExpiredSessions(database);

  const rateLimits = new Map();
  const sessionCleanupInterval = setInterval(() => {
    try {
      purgeExpiredSessions(database);
    } catch (error) {
      console.error('Session cleanup failed.', error);
    }
  }, 60_000);

  function allowedByRateLimit(request, route, maximum) {
    const now = Date.now();
    const key = `${route}:${request.socket.remoteAddress || 'unknown'}`;
    const current = rateLimits.get(key);
    if (!current || current.resetAt <= now) {
      rateLimits.set(key, { count: 1, resetAt: now + 60_000 });
      return true;
    }
    current.count += 1;
    return current.count <= maximum;
  }

  function createSession(userId) {
    const token = randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + SESSION_TTL_MS;
    database.prepare(
      'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
    ).run(hashSession(token), userId, expiresAt);
    return token;
  }

  function sessionCookie(token, maxAge = SESSION_TTL_MS / 1000) {
    return `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secureCookies ? '; Secure' : ''}`;
  }

  function findUserForSession(request) {
    const cookieHeader = request.headers.cookie || '';
    const cookie = cookieHeader.split(';').map((part) => part.trim())
      .find((part) => part.startsWith(`${SESSION_COOKIE}=`));
    if (!cookie) {
      return null;
    }
    const token = cookie.slice(SESSION_COOKIE.length + 1);
    if (!/^[\w-]{40,50}$/.test(token)) {
      return null;
    }
    const tokenHash = hashSession(token);
    return database.prepare(`
      SELECT users.id, users.first_name, users.last_name, users.identifier
      FROM sessions JOIN users ON users.id = sessions.user_id
      WHERE sessions.token_hash = ? AND sessions.expires_at > ?
    `).get(tokenHash, Date.now()) || null;
  }

  async function handleApi(request, response, url) {
    const route = url.pathname;
    const isRegister = route === '/api/auth/register';
    const isLogin = route === '/api/auth/login';
    const isLogout = route === '/api/auth/logout';
    const isCurrentUser = route === '/api/auth/me';
    const isAccountUpdate = route === '/api/auth/account';
    const isPasswordChange = route === '/api/auth/password';
    const isPasswordResetRequest = route === '/api/auth/password-reset/request';
    const isPasswordResetVerify = route === '/api/auth/password-reset/verify';
    const isContact = route === '/api/contact';
    const isCourseCatalog = route === '/api/courses';
    const isCourseEnrollments = route === '/api/courses/enrollments';
    const isCoursePaymentDetails = route === '/api/courses/payment-details';
    const isAdminCoursePayments = route === '/api/admin/course-payments';
    const adminCoursePaymentRoute = route.match(/^\/api\/admin\/course-payments\/(\d+)$/);
    const isProfilePhoto = route === '/api/auth/photo';
    const enrollmentRoute = route.match(/^\/api\/courses\/([a-z0-9-]+)\/enrollment$/);

    if (![isRegister, isLogin, isLogout, isCurrentUser, isAccountUpdate, isPasswordChange,
      isPasswordResetRequest, isPasswordResetVerify, isContact, isCourseCatalog,
      isCourseEnrollments, isCoursePaymentDetails, isAdminCoursePayments,
      isProfilePhoto].some(Boolean) && !enrollmentRoute && !adminCoursePaymentRoute) {
      sendJson(response, 404, { error: 'Not found.' });
      return;
    }

    const expectedMethod = isCurrentUser || isCourseCatalog || isCourseEnrollments
      || isCoursePaymentDetails || isAdminCoursePayments || isProfilePhoto ? 'GET' : 'POST';
    const allowedMethods = adminCoursePaymentRoute ? ['POST']
      : enrollmentRoute || isProfilePhoto ? ['GET', 'POST', 'DELETE'] : [expectedMethod];
    if (!allowedMethods.includes(request.method)) {
      sendJson(response, 405, { error: 'Method not allowed.' }, { Allow: allowedMethods.join(', ') });
      return;
    }

    if (isCourseCatalog) {
      sendJson(response, 200, { courses: COURSES });
      return;
    }

    if (isCoursePaymentDetails) {
      sendJson(response, 200, {
        fee: 3000,
        currency: 'AOA',
        instructions: environment.COURSE_PAYMENT_INSTRUCTIONS || '',
      });
      return;
    }

    if (isAdminCoursePayments || adminCoursePaymentRoute) {
      const user = findUserForSession(request);
      if (!user) {
        sendJson(response, 401, { error: 'Not signed in.' });
        return;
      }
      const adminUserId = Number(environment.COURSE_PAYMENT_ADMIN_USER_ID);
      if (!Number.isSafeInteger(adminUserId) || adminUserId < 1) {
        sendJson(response, 503, { error: 'Course payment review is not configured.' });
        return;
      }
      if (user.id !== adminUserId) {
        sendJson(response, 403, { error: 'You are not authorized to review course payments.' });
        return;
      }
      if (isAdminCoursePayments) {
        const requests = database.prepare(`
          SELECT requests.id, requests.transaction_reference AS transactionReference,
            requests.created_at AS createdAt, users.first_name AS firstName,
            users.last_name AS lastName, users.identifier, courses.title AS courseTitle
          FROM course_payment_requests AS requests
          JOIN users ON users.id = requests.user_id
          JOIN courses ON courses.id = requests.course_id
          WHERE requests.status = 'pending'
          ORDER BY requests.created_at ASC
        `).all();
        sendJson(response, 200, { requests });
        return;
      }

      const requestId = Number(adminCoursePaymentRoute[1]);
      if (!Number.isSafeInteger(requestId) || requestId < 1) {
        sendJson(response, 404, { error: 'Payment request not found.' });
        return;
      }
      const input = await readJson(request);
      if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw httpError(400, 'Request body must be a JSON object.');
      }
      if (!['approve', 'reject'].includes(input.action)) {
        throw httpError(400, 'Choose approve or reject.');
      }

      database.exec('BEGIN IMMEDIATE');
      try {
        const payment = database.prepare(
          "SELECT user_id, course_id FROM course_payment_requests WHERE id = ? AND status = 'pending'",
        ).get(requestId);
        if (!payment) {
          const exists = database.prepare('SELECT 1 FROM course_payment_requests WHERE id = ?').get(requestId);
          throw httpError(exists ? 409 : 404, exists ? 'This payment request has already been reviewed.' : 'Payment request not found.');
        }
        database.prepare(`
          UPDATE course_payment_requests
          SET status = ?, reviewed_at = ?, reviewed_by = ?
          WHERE id = ? AND status = 'pending'
        `).run(input.action === 'approve' ? 'approved' : 'rejected', Date.now(), user.id, requestId);
        if (input.action === 'approve') {
          database.prepare(`
            INSERT INTO course_enrollments (user_id, course_id, enrolled_at)
            VALUES (?, ?, ?)
            ON CONFLICT (user_id, course_id) DO NOTHING
          `).run(payment.user_id, payment.course_id, Date.now());
        }
        database.exec('COMMIT');
      } catch (error) {
        if (database.isTransaction) database.exec('ROLLBACK');
        throw error;
      }
      sendJson(response, 200, { status: input.action === 'approve' ? 'approved' : 'rejected' });
      return;
    }

    if (isCurrentUser) {
      const user = findUserForSession(request);
      sendJson(response, user ? 200 : 401, user ? { user } : { error: 'Not signed in.' });
      return;
    }

    if (isProfilePhoto) {
      const user = findUserForSession(request);
      if (!user) {
        sendJson(response, 401, { error: 'Not signed in.' });
        return;
      }

      if (request.method === 'GET') {
        const photo = database.prepare(
          'SELECT photo_data, photo_mime FROM users WHERE id = ?',
        ).get(user.id);
        if (!photo || !photo.photo_data) {
          sendJson(response, 404, { error: 'No profile photo.' });
          return;
        }
        response.writeHead(200, {
          'Cache-Control': 'private, no-store',
          'Content-Type': photo.photo_mime,
          'X-Content-Type-Options': 'nosniff',
        });
        response.end(photo.photo_data);
        return;
      }

      if (!allowedByRateLimit(request, 'profile-photo', 10)) {
        sendJson(response, 429, { error: 'Too many photo changes. Please try again in a minute.' });
        return;
      }
      if (request.method === 'DELETE') {
        database.prepare('UPDATE users SET photo_data = NULL, photo_mime = NULL WHERE id = ?').run(user.id);
        sendJson(response, 200, { ok: true });
        return;
      }

      const input = await readJson(request, MAX_PROFILE_PHOTO_BODY_SIZE);
      if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw httpError(400, 'Request body must be a JSON object.');
      }
      const photo = decodeProfilePhoto(input.dataUrl);
      database.prepare('UPDATE users SET photo_data = ?, photo_mime = ? WHERE id = ?')
        .run(photo.data, photo.mimeType, user.id);
      sendJson(response, 200, { ok: true });
      return;
    }

    if (isRegister && !allowedByRateLimit(request, 'register', 8)) {
      sendJson(response, 429, { error: 'Too many attempts. Please try again in a minute.' });
      return;
    }
    if (isLogin && !allowedByRateLimit(request, 'login', 10)) {
      sendJson(response, 429, { error: 'Too many attempts. Please try again in a minute.' });
      return;
    }
    if (isPasswordResetRequest && !allowedByRateLimit(request, 'password-reset-request', 5)) {
      sendJson(response, 429, { error: 'Too many requests. Wait a minute before trying again.' });
      return;
    }
    if (isPasswordResetVerify && !allowedByRateLimit(request, 'password-reset-verify', 10)) {
      sendJson(response, 429, { error: 'Too many attempts. Wait a minute before trying again.' });
      return;
    }
    if ((isAccountUpdate || isPasswordChange) && !allowedByRateLimit(request, route, 8)) {
      sendJson(response, 429, { error: 'Too many attempts. Please try again in a minute.' });
      return;
    }
    if (isContact && !allowedByRateLimit(request, 'contact', 5)) {
      sendJson(response, 429, { error: 'Too many messages. Please try again in a minute.' });
      return;
    }
    if (enrollmentRoute && !allowedByRateLimit(request, 'course-enrollment', 20)) {
      sendJson(response, 429, { error: 'Too many course changes. Please try again in a minute.' });
      return;
    }

    if (isCourseEnrollments || enrollmentRoute) {
      const user = findUserForSession(request);
      if (!user) {
        sendJson(response, 401, { error: 'Not signed in.' });
        return;
      }

      if (isCourseEnrollments) {
        const enrollments = database.prepare(`
          SELECT course_id, enrolled_at AS enrolledAt
          FROM course_enrollments
          WHERE user_id = ?
          ORDER BY enrolled_at DESC
        `).all(user.id);
        const paymentRequests = database.prepare(`
          SELECT requests.id, requests.course_id AS courseId, courses.title AS courseTitle,
            requests.status, requests.created_at AS createdAt
          FROM course_payment_requests AS requests
          JOIN courses ON courses.id = requests.course_id
          WHERE requests.user_id = ?
            AND requests.status IN ('pending', 'rejected')
            AND requests.id = (
              SELECT MAX(latest.id) FROM course_payment_requests AS latest
              WHERE latest.user_id = requests.user_id AND latest.course_id = requests.course_id
            )
          ORDER BY requests.created_at DESC
        `).all(user.id);
        sendJson(response, 200, {
          courses: enrollments.map((enrollment) => ({
            ...COURSES.find((course) => course.id === enrollment.course_id),
            enrolledAt: enrollment.enrolledAt,
          })),
          paymentRequests,
        });
        return;
      }

      const courseId = enrollmentRoute[1];
      if (!COURSES.some((course) => course.id === courseId)) {
        sendJson(response, 404, { error: 'Course not found.' });
        return;
      }

      if (request.method === 'POST') {
        if (!String(environment.COURSE_PAYMENT_INSTRUCTIONS || '').trim()) {
          sendJson(response, 503, { error: 'Course payment instructions are not configured. Please contact support.' });
          return;
        }
        const input = await readJson(request);
        if (!input || typeof input !== 'object' || Array.isArray(input)) {
          throw httpError(400, 'Request body must be a JSON object.');
        }
        const transactionReference = typeof input.transactionReference === 'string'
          ? input.transactionReference.trim() : '';
        if (transactionReference.length < 3 || transactionReference.length > 100) {
          throw httpError(400, 'Enter a payment reference between 3 and 100 characters.');
        }
        if (database.prepare('SELECT 1 FROM course_enrollments WHERE user_id = ? AND course_id = ?')
          .get(user.id, courseId)) {
          sendJson(response, 200, { enrolled: true, alreadyEnrolled: true });
          return;
        }
        database.prepare(`
          INSERT INTO course_payment_requests (user_id, course_id, transaction_reference, status, created_at)
          SELECT ?, ?, ?, 'pending', ?
          WHERE NOT EXISTS (
            SELECT 1 FROM course_enrollments WHERE user_id = ? AND course_id = ?
          )
          ON CONFLICT DO NOTHING
        `).run(user.id, courseId, transactionReference, Date.now(), user.id, courseId);
        if (database.prepare('SELECT 1 FROM course_enrollments WHERE user_id = ? AND course_id = ?')
          .get(user.id, courseId)) {
          sendJson(response, 200, { enrolled: true, alreadyEnrolled: true });
          return;
        }
        const paymentRequest = database.prepare(`
          SELECT id FROM course_payment_requests
          WHERE user_id = ? AND course_id = ? AND status = 'pending'
        `).get(user.id, courseId);
        sendJson(response, 201, { enrolled: false, paymentPending: true, requestId: paymentRequest.id });
        return;
      }

      const deletion = database.prepare(
        'DELETE FROM course_enrollments WHERE user_id = ? AND course_id = ?',
      ).run(user.id, courseId);
      sendJson(response, 200, { enrolled: false, removed: Number(deletion.changes) > 0 });
      return;
    }

    if (isLogout) {
      const user = findUserForSession(request);
      const cookieHeader = request.headers.cookie || '';
      const cookie = cookieHeader.split(';').map((part) => part.trim())
        .find((part) => part.startsWith(`${SESSION_COOKIE}=`));
      if (cookie) {
        const token = cookie.slice(SESSION_COOKIE.length + 1);
        if (/^[\w-]{40,50}$/.test(token)) {
          database.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashSession(token));
        }
      }
      sendJson(response, 200, { ok: true }, {
        'Set-Cookie': sessionCookie('', 0),
      });
      return;
    }

    const input = await readJson(request);
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw httpError(400, 'Request body must be a JSON object.');
    }

    if (isContact) {
      const name = getName(input.name, 'name');
      const email = normalizeEmail(input.email);
      if (typeof input.message !== 'string') {
        throw httpError(400, 'Enter a message.');
      }
      const message = input.message.trim();
      if (message.length < 10 || message.length > 5000) {
        throw httpError(400, 'Your message must be between 10 and 5000 characters.');
      }
      database.prepare(`
        INSERT INTO contact_messages (name, email, message, created_at)
        VALUES (?, ?, ?, ?)
      `).run(name, email, message, Date.now());
      sendJson(response, 201, {
        ok: true,
        message: 'Your message has been received. Thank you for getting in touch.',
      });
      return;
    }

    if (isPasswordResetRequest) {
      const identifier = normalizeIdentifier(input.identifier);
      const { assertRecoveryConfiguration, createRecoveryCode, deliverRecoveryCode, getRecoveryChannel, hashRecoveryCode } = await passwordRecovery;
      const channel = getRecoveryChannel(identifier);
      try {
        assertRecoveryConfiguration(channel, environment);
      } catch {
        throw httpError(503, 'Password recovery is not configured for this contact method. Please contact support.');
      }

      const user = database.prepare('SELECT id FROM users WHERE identifier = ?').get(identifier);
      if (user) {
        const now = Date.now();
        const code = createRecoveryCode();
        const codeHash = await hashRecoveryCode(environment.PASSWORD_RESET_SECRET, user.id, code);
        const issued = database.prepare(`
          INSERT INTO password_reset_codes (user_id, code_hash, expires_at, attempts, requested_at)
          VALUES (?, ?, ?, 0, ?)
          ON CONFLICT(user_id) DO UPDATE SET
            code_hash = excluded.code_hash,
            expires_at = excluded.expires_at,
            attempts = 0,
            requested_at = excluded.requested_at
          WHERE password_reset_codes.requested_at <= ?
        `).run(user.id, codeHash, now + 10 * 60 * 1000, now, now - 60_000);

        if (Number(issued.changes) === 1) {
          try {
            if (sendRecoveryCode) {
              await sendRecoveryCode(channel, identifier, code);
            } else {
              await deliverRecoveryCode(channel, identifier, code, environment);
            }
          } catch (error) {
            database.prepare('DELETE FROM password_reset_codes WHERE user_id = ? AND code_hash = ?')
              .run(user.id, codeHash);
            console.error('Password reset code delivery failed.', error);
            throw httpError(502, 'We could not send a verification code. Please try again later.');
          }
        }
      }

      sendJson(response, 202, {
        ok: true,
        message: 'If an account matches those details, a verification code has been sent.',
      });
      return;
    }

    if (isPasswordResetVerify) {
      const identifier = normalizeIdentifier(input.identifier);
      const { assertResetSecret } = await passwordRecovery;
      try {
        assertResetSecret(environment.PASSWORD_RESET_SECRET);
      } catch {
        throw httpError(503, 'Password recovery is not configured. Please contact support.');
      }
      if (typeof input.code !== 'string' || !/^\d{6}$/.test(input.code)) {
        throw httpError(400, 'Enter the 6-digit verification code.');
      }
      validatePassword(input.newPassword);
      const user = database.prepare('SELECT id FROM users WHERE identifier = ?').get(identifier);
      if (!user) throw httpError(400, 'The verification code is invalid or expired.');

      const record = database.prepare(`
        SELECT code_hash, expires_at, attempts
        FROM password_reset_codes WHERE user_id = ?
      `).get(user.id);
      const now = Date.now();
      if (!record || record.expires_at <= now || record.attempts >= 5) {
        database.prepare('DELETE FROM password_reset_codes WHERE user_id = ?').run(user.id);
        throw httpError(400, 'The verification code is invalid or expired.');
      }

      const { constantTimeEqual, hashRecoveryCode } = await passwordRecovery;
      const submittedHash = await hashRecoveryCode(environment.PASSWORD_RESET_SECRET, user.id, input.code);
      if (!constantTimeEqual(submittedHash, record.code_hash)) {
        database.prepare(`
          UPDATE password_reset_codes SET attempts = attempts + 1
          WHERE user_id = ? AND attempts < 5
        `).run(user.id);
        throw httpError(400, 'The verification code is invalid or expired.');
      }

      const credentials = await hashPassword(input.newPassword);
      database.exec('BEGIN IMMEDIATE');
      try {
        const consumed = database.prepare(`
          DELETE FROM password_reset_codes
          WHERE user_id = ? AND code_hash = ? AND expires_at > ? AND attempts < 5
        `).run(user.id, record.code_hash, now);
        if (Number(consumed.changes) !== 1) {
          throw httpError(400, 'The verification code is invalid or expired.');
        }
        database.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?')
          .run(credentials.salt, credentials.hash, user.id);
        database.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
        database.exec('COMMIT');
      } catch (error) {
        if (database.isTransaction) database.exec('ROLLBACK');
        throw error;
      }
      sendJson(response, 200, {
        ok: true,
        message: 'Your password has been reset. Sign in with your new password.',
      });
      return;
    }

    if (isAccountUpdate || isPasswordChange) {
      const currentUser = findUserForSession(request);
      if (!currentUser) {
        sendJson(response, 401, { error: 'Not signed in.' });
        return;
      }

      validatePassword(input.currentPassword);
      const storedCredentials = database.prepare(
        'SELECT password_salt, password_hash FROM users WHERE id = ?',
      ).get(currentUser.id);
      const passwordIsValid = storedCredentials && await passwordMatches(
        input.currentPassword,
        storedCredentials.password_salt,
        storedCredentials.password_hash,
      );
      if (!passwordIsValid) {
        sendJson(response, 403, { error: 'Current password is incorrect.' });
        return;
      }

      if (isAccountUpdate) {
        const firstName = getName(input.firstName, 'first name');
        const lastName = getName(input.lastName, 'last name');
        const identifier = normalizeIdentifier(input.identifier);
        try {
          database.prepare(`
            UPDATE users SET first_name = ?, last_name = ?, identifier = ? WHERE id = ?
          `).run(firstName, lastName, identifier, currentUser.id);
        } catch (error) {
          if (/UNIQUE constraint failed/.test(error.message)) {
            throw httpError(409, 'An account with that email or phone number already exists.');
          }
          throw error;
        }
        sendJson(response, 200, {
          ok: true,
          user: {
            id: currentUser.id,
            first_name: firstName,
            last_name: lastName,
            identifier,
          },
        });
        return;
      }

      validatePassword(input.newPassword);
      if (input.currentPassword === input.newPassword) {
        throw httpError(400, 'Choose a new password that is different from your current one.');
      }
      const credentials = await hashPassword(input.newPassword);
      database.prepare(`
        UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?
      `).run(credentials.salt, credentials.hash, currentUser.id);
      database.prepare('DELETE FROM sessions WHERE user_id = ?').run(currentUser.id);
      const token = createSession(currentUser.id);
      sendJson(response, 200, { ok: true }, {
        'Set-Cookie': sessionCookie(token),
      });
      return;
    }

    const identifier = normalizeIdentifier(input.identifier);
    const password = input.password;
    validatePassword(password);

    if (isRegister) {
      const firstName = getName(input.firstName, 'first name');
      const lastName = getName(input.lastName, 'last name');
      const credentials = await hashPassword(password);
      let result;
      try {
        result = database.prepare(`
          INSERT INTO users (first_name, last_name, identifier, password_salt, password_hash, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(firstName, lastName, identifier, credentials.salt, credentials.hash, Date.now());
      } catch (error) {
        if (/UNIQUE constraint failed/.test(error.message)) {
          throw httpError(409, 'An account with that email or phone number already exists.');
        }
        throw error;
      }

      const token = createSession(Number(result.lastInsertRowid));
      sendJson(response, 201, { ok: true }, {
        'Set-Cookie': sessionCookie(token),
      });
      return;
    }

    const user = database.prepare(`
      SELECT id, password_salt, password_hash
      FROM users WHERE identifier = ?
    `).get(identifier);
    const dummyCredentials = {
      salt: '00000000000000000000000000000000',
      hash: '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
    };
    const credentials = user || dummyCredentials;
    const matches = await passwordMatches(password, credentials.password_salt || credentials.salt, credentials.password_hash || credentials.hash);
    if (!user || !matches) {
      sendJson(response, 401, { error: 'Invalid email/phone number or password.' });
      return;
    }

    const token = createSession(user.id);
    sendJson(response, 200, { ok: true }, {
      'Set-Cookie': sessionCookie(token),
    });
  }

  async function handleRequest(request, response) {
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.setHeader('X-Frame-Options', 'DENY');

    let url;
    try {
      url = new URL(request.url, 'http://localhost');
    } catch {
      sendJson(response, 400, { error: 'Invalid request URL.' });
      return;
    }

    try {
      if (url.pathname === '/health' && request.method === 'GET') {
        sendJson(response, 200, { status: 'ok' });
        return;
      }

      if (url.pathname.startsWith('/api/')) {
        await handleApi(request, response, url);
        return;
      }

      if (request.method !== 'GET' && request.method !== 'HEAD') {
        sendJson(response, 405, { error: 'Method not allowed.' }, { Allow: 'GET, HEAD' });
        return;
      }

      let pathname;
      try {
        pathname = decodeURIComponent(url.pathname);
      } catch {
        sendJson(response, 400, { error: 'Invalid request URL.' });
        return;
      }
      const relativePath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
      const filePath = path.resolve(ROOT, relativePath);
      const actualRelativePath = path.relative(ROOT, filePath);
      if (actualRelativePath.startsWith('..') || path.isAbsolute(actualRelativePath) || !isPublicFile(actualRelativePath)) {
        sendJson(response, 404, { error: 'Not found.' });
        return;
      }

      const content = await readCachedStaticFile(filePath);
      const etag = getFileEtag(content);
      const requestEtag = request.headers['if-none-match'];
      if (request.method === 'GET' && requestEtag === etag) {
        response.writeHead(304, {
          'Cache-Control': getStaticCacheControl(filePath),
          ETag: etag,
        });
        response.end();
        return;
      }

      response.writeHead(200, {
        'Cache-Control': getStaticCacheControl(filePath),
        'Content-Type': CONTENT_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
        ETag: etag,
      });
      response.end(request.method === 'HEAD' ? undefined : content);
    } catch (error) {
      if (!response.headersSent) {
        sendJson(response, error.status || 500, {
          error: error.status ? error.message : 'An unexpected server error occurred.',
        });
      }
      if (!error.status) {
        console.error(error);
      }
    }
  }

  const server = http.createServer((request, response) => {
    void handleRequest(request, response);
  });
  server.database = database;
  server.on('close', () => clearInterval(sessionCleanupInterval));
  return server;
}

if (require.main === module) {
  const server = createAuthServer();
  const port = Number(process.env.PORT) || 3000;
  server.listen(port, () => {
    console.log(`Dreamers authentication server listening on port ${port}`);
  });
}

module.exports = { createAuthServer };
