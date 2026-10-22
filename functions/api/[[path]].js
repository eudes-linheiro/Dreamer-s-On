const SESSION_COOKIE = 'dreamers_session';
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const JSON_BODY_LIMIT = 16 * 1024;
const PHOTO_BODY_LIMIT = 2 * 1024 * 1024;
const PASSWORD_ITERATIONS = 120_000;
const COURSES = [
  { id: 'english-foundations', title: 'English foundations', category: 'Language' },
  { id: 'french-essentials', title: 'French essentials', category: 'Language' },
  { id: 'music-theory', title: 'Music theory', category: 'Music' },
  { id: 'music-production', title: 'Music production', category: 'Music' },
];
const rateLimits = new Map();

function jsonResponse(status, body, headers = {}) {
  return Response.json(body, {
    status,
    headers: { 'Cache-Control': 'no-store', ...headers },
  });
}

function errorResponse(status, message) {
  return jsonResponse(status, { error: message });
}

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

async function readBytes(request, maximumBytes) {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > maximumBytes) {
    throw httpError(413, 'Request body is too large.');
  }

  const reader = request.body?.getReader();
  if (!reader) {
    return new Uint8Array();
  }
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximumBytes) {
      await reader.cancel();
      throw httpError(413, 'Request body is too large.');
    }
    chunks.push(value);
  }

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function readJson(request, maximumBytes = JSON_BODY_LIMIT) {
  if (!(request.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) {
    throw httpError(415, 'Content-Type must be application/json.');
  }
  const bytes = await readBytes(request, maximumBytes);
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw httpError(400, 'Request body must contain valid JSON.');
  }
}

function normalizeEmail(value) {
  if (typeof value !== 'string') {
    throw httpError(400, 'Enter a valid email address.');
  }
  const email = value.trim().toLowerCase();
  const [localPart, ...domainParts] = email.split('@');
  const domain = domainParts.join('@');
  const labels = domain.split('.');
  const validLocalPart = localPart && localPart.length <= 64
    && !localPart.startsWith('.') && !localPart.endsWith('.') && !localPart.includes('..')
    && /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(localPart);
  const validDomain = domain.length <= 253 && labels.length >= 2
    && labels.every((label) => label.length > 0 && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label))
    && labels.at(-1).length >= 2;
  if (!validLocalPart || !validDomain || email.length > 254) {
    throw httpError(400, 'Enter a valid email address.');
  }
  return email;
}

function normalizeIdentifier(value) {
  if (typeof value !== 'string') {
    throw httpError(400, 'Enter a valid email address or Angola phone number.');
  }
  const identifier = value.trim();
  if (identifier.includes('@')) return normalizeEmail(identifier);
  if (!/^\+?[\d\s().-]+$/.test(identifier)) {
    throw httpError(400, 'Enter an Angola phone number with 9 digits and country code +244.');
  }
  const compact = identifier.replace(/[\s().-]/g, '');
  let nationalNumber = compact;
  if (compact.startsWith('+244')) nationalNumber = compact.slice(4);
  else if (compact.startsWith('00244')) nationalNumber = compact.slice(5);
  else if (compact.startsWith('244') && compact.length === 12) nationalNumber = compact.slice(3);
  if (!/^[2-9]\d{8}$/.test(nationalNumber)) {
    throw httpError(400, 'Enter an Angola phone number with 9 digits and country code +244.');
  }
  return `+244${nationalNumber}`;
}

function getName(value, field) {
  if (typeof value !== 'string') throw httpError(400, `Enter your ${field}.`);
  const name = value.trim();
  if (!name || name.length > 80) throw httpError(400, `Enter a ${field} up to 80 characters long.`);
  return name;
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    throw httpError(400, 'Password must be between 8 and 128 characters.');
  }
}

function toBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(value) {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64 + '='.repeat((4 - base64.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function hashPassword(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    hash: 'SHA-256',
    salt,
    iterations: PASSWORD_ITERATIONS,
  }, material, 256);
  return { salt: toBase64Url(salt), hash: toBase64Url(new Uint8Array(hash)) };
}

async function passwordMatches(password, saltValue, hashValue) {
  const { hash } = await hashPassword(password, fromBase64Url(saltValue));
  const actual = fromBase64Url(hash);
  const expected = fromBase64Url(hashValue);
  if (actual.length !== expected.length) return false;
  let difference = 0;
  for (let index = 0; index < actual.length; index += 1) difference |= actual[index] ^ expected[index];
  return difference === 0;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

function getCookie(request, name) {
  const entry = (request.headers.get('cookie') || '').split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  return entry ? entry.slice(name.length + 1) : null;
}

function sessionCookie(token, maxAge = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

async function createSession(env, userId) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = toBase64Url(tokenBytes);
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(await sha256(token), userId, expiresAt).run();
  return token;
}

async function findUser(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !/^[\w-]{40,50}$/.test(token)) return null;
  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now).run();
  return env.DB.prepare(`
    SELECT users.id, users.first_name, users.last_name, users.identifier, users.photo_key
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).bind(tokenHash, now).first();
}

function isRateLimited(request, key, maximum) {
  const now = Date.now();
  const address = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rateKey = `${key}:${address}`;
  const current = rateLimits.get(rateKey);
  if (!current || current.resetAt <= now) {
    rateLimits.set(rateKey, { count: 1, resetAt: now + 60_000 });
    return false;
  }
  current.count += 1;
  return current.count > maximum;
}

function validPhoto(bytes, mimeType) {
  if (bytes.length === 0 || bytes.length > PHOTO_BODY_LIMIT) return false;
  if (mimeType === 'image/jpeg') {
    return bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
      && bytes[bytes.length - 2] === 0xff && bytes[bytes.length - 1] === 0xd9;
  }
  if (mimeType === 'image/png') {
    return bytes.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
      .every((byte, index) => bytes[index] === byte);
  }
  if (mimeType === 'image/webp') {
    return bytes.length >= 12
      && new TextDecoder().decode(bytes.subarray(0, 4)) === 'RIFF'
      && new TextDecoder().decode(bytes.subarray(8, 12)) === 'WEBP';
  }
  return false;
}

async function api(request, env, url) {
  const route = url.pathname;
  const isRegister = route === '/api/auth/register';
  const isLogin = route === '/api/auth/login';
  const isLogout = route === '/api/auth/logout';
  const isCurrentUser = route === '/api/auth/me';
  const isAccountUpdate = route === '/api/auth/account';
  const isPasswordChange = route === '/api/auth/password';
  const isPhoto = route === '/api/auth/photo';
  const isContact = route === '/api/contact';
  const isCourseCatalog = route === '/api/courses';
  const isCourseEnrollments = route === '/api/courses/enrollments';
  const enrollmentRoute = route.match(/^\/api\/courses\/([a-z0-9-]+)\/enrollment$/);
  const knownRoute = [isRegister, isLogin, isLogout, isCurrentUser, isAccountUpdate, isPasswordChange,
    isPhoto, isContact, isCourseCatalog, isCourseEnrollments].some(Boolean) || enrollmentRoute;
  if (!knownRoute) return errorResponse(404, 'Not found.');

  const expectedMethod = isCurrentUser || isCourseCatalog || isCourseEnrollments ? 'GET' : 'POST';
  const allowedMethods = isPhoto || enrollmentRoute ? ['GET', 'POST', 'DELETE'] : [expectedMethod];
  if (!allowedMethods.includes(request.method)) {
    return errorResponse(405, 'Method not allowed.');
  }

  if (isCourseCatalog) return jsonResponse(200, { courses: COURSES });

  if (isCurrentUser) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');
    const { photo_key: photoKey, ...publicUser } = user;
    return jsonResponse(200, { user: { ...publicUser, photo_url: photoKey ? '/api/auth/photo' : null } });
  }

  if (isPhoto) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');
    if (request.method === 'GET') {
      if (!user.photo_key) return errorResponse(404, 'No profile photo.');
      const photo = await env.PHOTOS.get(user.photo_key);
      if (!photo) return errorResponse(404, 'No profile photo.');
      return new Response(photo.body, {
        headers: {
          'Cache-Control': 'private, no-store',
          'Content-Type': photo.httpMetadata?.contentType || 'application/octet-stream',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }
    if (isRateLimited(request, 'profile-photo', 10)) return errorResponse(429, 'Too many photo changes. Try again in a minute.');
    if (request.method === 'DELETE') {
      if (user.photo_key) await env.PHOTOS.delete(user.photo_key);
      await env.DB.prepare('UPDATE users SET photo_key = NULL WHERE id = ?').bind(user.id).run();
      return jsonResponse(200, { ok: true });
    }
    const mimeType = (request.headers.get('content-type') || '').toLowerCase().split(';')[0].trim();
    const bytes = await readBytes(request, PHOTO_BODY_LIMIT);
    if (!validPhoto(bytes, mimeType)) return errorResponse(400, 'Choose a valid JPEG, PNG, or WebP photo up to 2 MB.');
    const photoKey = `profiles/${user.id}`;
    await env.PHOTOS.put(photoKey, bytes, { httpMetadata: { contentType: mimeType } });
    await env.DB.prepare('UPDATE users SET photo_key = ? WHERE id = ?').bind(photoKey, user.id).run();
    return jsonResponse(200, { ok: true, photo_url: '/api/auth/photo' });
  }

  if (isRegister && isRateLimited(request, 'register', 8)) return errorResponse(429, 'Too many attempts. Try again in a minute.');
  if (isLogin && isRateLimited(request, 'login', 10)) return errorResponse(429, 'Too many attempts. Try again in a minute.');
  if ((isAccountUpdate || isPasswordChange) && isRateLimited(request, route, 8)) return errorResponse(429, 'Too many attempts. Try again in a minute.');
  if (isContact && isRateLimited(request, 'contact', 5)) return errorResponse(429, 'Too many messages. Try again in a minute.');
  if (enrollmentRoute && isRateLimited(request, 'course-enrollment', 20)) return errorResponse(429, 'Too many course changes. Try again in a minute.');

  if (isCourseEnrollments || enrollmentRoute) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');
    if (isCourseEnrollments) {
      const rows = await env.DB.prepare(`
        SELECT courses.id, courses.title, courses.category, course_enrollments.enrolled_at AS enrolledAt
        FROM course_enrollments JOIN courses ON courses.id = course_enrollments.course_id
        WHERE course_enrollments.user_id = ?
        ORDER BY course_enrollments.enrolled_at DESC
      `).bind(user.id).all();
      return jsonResponse(200, { courses: rows.results });
    }
    const courseId = enrollmentRoute[1];
    const course = COURSES.find((item) => item.id === courseId);
    if (!course) return errorResponse(404, 'Course not found.');
    if (request.method === 'POST') {
      const result = await env.DB.prepare(`
        INSERT INTO course_enrollments (user_id, course_id, enrolled_at)
        VALUES (?, ?, ?)
        ON CONFLICT (user_id, course_id) DO NOTHING
      `).bind(user.id, courseId, Date.now()).run();
      return jsonResponse(200, { enrolled: true, alreadyEnrolled: result.meta.changes === 0 });
    }
    await env.DB.prepare('DELETE FROM course_enrollments WHERE user_id = ? AND course_id = ?')
      .bind(user.id, courseId).run();
    return jsonResponse(200, { enrolled: false });
  }

  if (isLogout) {
    const token = getCookie(request, SESSION_COOKIE);
    if (token && /^[\w-]{40,50}$/.test(token)) {
      await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
    }
    return jsonResponse(200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
  }

  const input = await readJson(request);
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw httpError(400, 'Request body must be a JSON object.');

  if (isContact) {
    const name = getName(input.name, 'name');
    const email = normalizeEmail(input.email);
    if (typeof input.message !== 'string') throw httpError(400, 'Enter a message.');
    const message = input.message.trim();
    if (message.length < 10 || message.length > 5000) throw httpError(400, 'Message must be between 10 and 5000 characters.');
    await env.DB.prepare('INSERT INTO contact_messages (name, email, message, created_at) VALUES (?, ?, ?, ?)')
      .bind(name, email, message, Date.now()).run();
    return jsonResponse(201, { ok: true, message: 'Your message has been received. Thank you for getting in touch.' });
  }

  if (isAccountUpdate || isPasswordChange) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');
    validatePassword(input.currentPassword);
    const credentials = await env.DB.prepare('SELECT password_salt, password_hash FROM users WHERE id = ?')
      .bind(user.id).first();
    if (!await passwordMatches(input.currentPassword, credentials.password_salt, credentials.password_hash)) {
      return errorResponse(403, 'Current password is incorrect.');
    }
    if (isAccountUpdate) {
      const firstName = getName(input.firstName, 'first name');
      const lastName = getName(input.lastName, 'last name');
      const identifier = normalizeIdentifier(input.identifier);
      try {
        await env.DB.prepare('UPDATE users SET first_name = ?, last_name = ?, identifier = ? WHERE id = ?')
          .bind(firstName, lastName, identifier, user.id).run();
      } catch (error) {
        if (/UNIQUE constraint failed/i.test(error.message)) throw httpError(409, 'An account with that email or phone already exists.');
        throw error;
      }
      return jsonResponse(200, { ok: true, user: { id: user.id, first_name: firstName, last_name: lastName, identifier } });
    }
    validatePassword(input.newPassword);
    if (input.currentPassword === input.newPassword) throw httpError(400, 'Choose a new password that differs from your current one.');
    const replacement = await hashPassword(input.newPassword);
    await env.DB.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?')
      .bind(replacement.salt, replacement.hash, user.id).run();
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
    const token = await createSession(env, user.id);
    return jsonResponse(200, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
  }

  const identifier = normalizeIdentifier(input.identifier);
  validatePassword(input.password);
  if (isRegister) {
    const firstName = getName(input.firstName, 'first name');
    const lastName = getName(input.lastName, 'last name');
    const credentials = await hashPassword(input.password);
    let result;
    try {
      result = await env.DB.prepare(`
        INSERT INTO users (first_name, last_name, identifier, password_salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(firstName, lastName, identifier, credentials.salt, credentials.hash, Date.now()).run();
    } catch (error) {
      if (/UNIQUE constraint failed/i.test(error.message)) throw httpError(409, 'An account with that email or phone already exists.');
      throw error;
    }
    const token = await createSession(env, result.meta.last_row_id);
    return jsonResponse(201, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
  }

  const user = await env.DB.prepare('SELECT id, password_salt, password_hash FROM users WHERE identifier = ?')
    .bind(identifier).first();
  const dummy = { salt: 'AAAAAAAAAAAAAAAAAAAAAA', hash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
  const matches = await passwordMatches(input.password, (user || dummy).password_salt || (user || dummy).salt,
    (user || dummy).password_hash || (user || dummy).hash);
  if (!user || !matches) return errorResponse(401, 'Invalid email/phone number or password.');
  const token = await createSession(env, user.id);
  return jsonResponse(200, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
}

export async function onRequest(context) {
  const { request, env } = context;
  try {
    const url = new URL(request.url);
    return await api(request, env, url);
  } catch (error) {
    return errorResponse(error.status || 500, error.status ? error.message : 'An unexpected server error occurred.');
  }
}