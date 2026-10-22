export const app = {
  name: 'Dreamer-s-On',
  status: 'initialized',
};

export default app;

export interface Env {
  DB: D1Database;
  PHOTOS: R2Bucket;
  ASSETS: Fetcher;
  COURSE_PAYMENT_INSTRUCTIONS?: string;
  COURSE_PAYMENT_ADMIN_USER_ID?: string;
  PASSWORD_RESET_SECRET?: string;
  RESEND_API_KEY?: string;
  RESEND_FROM?: string;
  SMS_WEBHOOK_URL?: string;
}

const SESSION_COOKIE = 'dreamers_session';
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const PASSWORD_RESET_CODE_TTL_MS = 10 * 60 * 1000;
const PASSWORD_RESET_RESEND_DELAY_MS = 60 * 1000;
const PASSWORD_RESET_MAX_ATTEMPTS = 5;
const JSON_BODY_LIMIT = 16 * 1024;
const PHOTO_BODY_LIMIT = 2 * 1024 * 1024;
const PASSWORD_ITERATIONS = 120_000;

const COURSES = [
  { id: 'english-foundations', title: 'English foundations', category: 'Language' },
  { id: 'french-essentials', title: 'French essentials', category: 'Language' },
  { id: 'music-theory', title: 'Music theory', category: 'Music' },
  { id: 'music-production', title: 'Music production', category: 'Music' },
];

const rateLimits = new Map<string, { count: number; resetAt: number }>();

function jsonResponse(status: number, body: any, headers: Record<string, string> = {}) {
  return Response.json(body, {
    status,
    headers: { 'Cache-Control': 'no-store', ...headers },
  });
}

function errorResponse(status: number, message: string) {
  return jsonResponse(status, { error: message });
}

function httpError(status: number, message: string) {
  const error = new Error(message) as Error & { status?: number };
  error.status = status;
  return error;
}

async function readBytes(request: Request, maximumBytes: number) {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (contentLength > maximumBytes) {
    throw httpError(413, 'Request body is too large.');
  }

  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();

  const chunks: Uint8Array[] = [];
  let size = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
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

async function readJson(request: Request, maximumBytes = JSON_BODY_LIMIT) {
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

function normalizeEmail(value: unknown) {
  if (typeof value !== 'string') {
    throw httpError(400, 'Enter a valid email address.');
  }

  const email = value.trim().toLowerCase();
  const [localPart, ...domainParts] = email.split('@');
  const domain = domainParts.join('@');
  const labels = domain.split('.');

  const validLocalPart =
    !!localPart &&
    localPart.length <= 64 &&
    !localPart.startsWith('.') &&
    !localPart.endsWith('.') &&
    !localPart.includes('..') &&
    /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/i.test(localPart);

  const validDomain =
    domain.length <= 253 &&
    labels.length >= 2 &&
    labels.every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)) &&
    labels.at(-1)!.length >= 2;

  if (!validLocalPart || !validDomain || email.length > 254) {
    throw httpError(400, 'Enter a valid email address.');
  }

  return email;
}

function normalizeIdentifier(value: unknown) {
  if (typeof value !== 'string') {
    throw httpError(400, 'Enter a valid email address or Angola phone number.');
  }

  const identifier = value.trim();

  if (identifier.includes('@')) return normalizeEmail(identifier);

  if (!/^\\+?[\\d\\s().-]+$/.test(identifier)) {
    throw httpError(400, 'Enter an Angola phone number with 9 digits and country code +244.');
  }

  const compact = identifier.replace(/[\\s().-]/g, '');
  let nationalNumber = compact;

  if (compact.startsWith('+244')) nationalNumber = compact.slice(4);
  else if (compact.startsWith('00244')) nationalNumber = compact.slice(5);
  else if (compact.startsWith('244') && compact.length === 12) nationalNumber = compact.slice(3);

  if (!/^[2-9]\\d{8}$/.test(nationalNumber)) {
    throw httpError(400, 'Enter an Angola phone number with 9 digits and country code +244.');
  }

  return `+244${nationalNumber}`;
}

function getName(value: unknown, field: string) {
  if (typeof value !== 'string') throw httpError(400, `Enter your ${field}.`);
  const name = value.trim();
  if (!name || name.length > 80) throw httpError(400, `Enter a ${field} up to 80 characters long.`);
  return name;
}

function validatePassword(password: unknown) {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    throw httpError(400, 'Password must be between 8 and 128 characters.');
  }
}

function toBase64Url(bytes: Uint8Array) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(value: string) {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function hashPassword(password: string, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations: PASSWORD_ITERATIONS,
    },
    material,
    256
  );

  return {
    salt: toBase64Url(salt),
    hash: toBase64Url(new Uint8Array(hash)),
  };
}

async function passwordMatches(password: string, saltValue: string, hashValue: string) {
  const { hash } = await hashPassword(password, fromBase64Url(saltValue));
  const actual = fromBase64Url(hash);
  const expected = fromBase64Url(hashValue);

  if (actual.length !== expected.length) return false;

  let difference = 0;
  for (let i = 0; i < actual.length; i += 1) {
    difference |= actual[i] ^ expected[i];
  }
  return difference === 0;
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}

function getCookie(request: Request, name: string) {
  const entry = (request.headers.get('cookie') || '')
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));

  return entry ? entry.slice(name.length + 1) : null;
}

function sessionCookie(token: string, maxAge = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

async function createSession(env: Env, userId: number) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = toBase64Url(tokenBytes);
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;

  await env.DB.prepare(
    'INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'
  ).bind(await sha256(token), userId, expiresAt).run();

  return token;
}

async function findUser(request: Request, env: Env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token || !/^[\\w-]{40,50}$/.test(token)) return null;

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(now).run();

  const row = await env.DB.prepare(`
    SELECT users.id, users.first_name, users.last_name, users.identifier, users.photo_key
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).bind(tokenHash, now).first<any>();

  return row;
}

function isRateLimited(request: Request, key: string, maximum: number) {
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

function validPhoto(bytes: Uint8Array, mimeType: string) {
  if (bytes.length === 0 || bytes.length > PHOTO_BODY_LIMIT) return false;

  if (mimeType === 'image/jpeg') {
    return (
      bytes.length >= 4 &&
      bytes[0] === 0xff &&
      bytes[1] === 0xd8 &&
      bytes[2] === 0xff &&
      bytes[bytes.length - 2] === 0xff &&
      bytes[bytes.length - 1] === 0xd9
    );
  }

  if (mimeType === 'image/png') {
    return (
      bytes.length >= 8 &&
      [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((byte, index) => bytes[index] === byte)
    );
  }

  if (mimeType === 'image/webp') {
    return (
      bytes.length >= 12 &&
      new TextDecoder().decode(bytes.subarray(0, 4)) === 'RIFF' &&
      new TextDecoder().decode(bytes.subarray(8, 12)) === 'WEBP'
    );
  }

  return false;
}

function decodeProfilePhoto(dataUrl: unknown) {
  const match =
    typeof dataUrl === 'string' &&
    /^data:(image\/jpeg|image\/png|image\/webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(dataUrl);

  if (!match) {
    throw httpError(400, 'Choose a JPEG, PNG, or WebP profile photo.');
  }

  const photo = Uint8Array.from(atob(match[2]), (char) => char.charCodeAt(0));
  if (photo.length === 0 || photo.length > PHOTO_BODY_LIMIT) {
    throw httpError(400, 'Profile photos must be 2 MB or smaller.');
  }

  const isJpeg =
    match[1] === 'image/jpeg' &&
    photo.length >= 4 &&
    photo[0] === 0xff &&
    photo[1] === 0xd8 &&
    photo[2] === 0xff &&
    photo[photo.length - 2] === 0xff &&
    photo[photo.length - 1] === 0xd9;

  const isPng =
    match[1] === 'image/png' &&
    photo.length >= 8 &&
    [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((byte, index) => photo[index] === byte);

  const isWebp =
    match[1] === 'image/webp' &&
    photo.length >= 12 &&
    new TextDecoder().decode(photo.subarray(0, 4)) === 'RIFF' &&
    new TextDecoder().decode(photo.subarray(8, 12)) === 'WEBP';

  if (!isJpeg && !isPng && !isWebp) {
    throw httpError(400, 'The selected file is not a valid JPEG, PNG, or WebP image.');
  }

  return { data: photo, mimeType: match[1] };
}

function getRecoveryChannel(identifier: string) {
  return identifier.includes('@') ? 'email' : 'sms';
}

function assertRecoveryConfiguration(channel: string, env: Env) {
  if (channel === 'email' && !env.PASSWORD_RESET_SECRET) {
    throw new Error('Email reset is not configured.');
  }
  if (channel === 'sms' && !env.PASSWORD_RESET_SECRET) {
    throw new Error('SMS reset is not configured.');
  }
}

function assertResetSecret(secret: string | undefined) {
  if (!secret) {
    throw new Error('Password reset is not configured.');
  }
}

async function hashRecoveryCode(secret: string | undefined, userId: number, code: string) {
  if (!secret) throw new Error('Password reset secret is not configured.');
  const input = `${secret}:${userId}:${code}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return toBase64Url(new Uint8Array(digest));
}

function constantTimeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function deliverRecoveryCode(channel: string, identifier: string, code: string, env: Env) {
  if (channel === 'email') {
    // Replace this with Resend / SendGrid / SES / your own provider.
    // For dev/testing this just returns successfully.
    if (env.RESEND_API_KEY && env.RESEND_FROM) {
      return;
    }
    return;
  }

  if (channel === 'sms') {
    if (env.SMS_WEBHOOK_URL) {
      return;
    }
    return;
  }

  throw new Error('Unsupported recovery channel.');
}

async function handleApi(request: Request, env: Env, url: URL) {
  const route = url.pathname;

  const isRegister = route === '/api/auth/register';
  const isLogin = route === '/api/auth/login';
  const isLogout = route === '/api/auth/logout';
  const isCurrentUser = route === '/api/auth/me';
  const isAccountUpdate = route === '/api/auth/account';
  const isPasswordChange = route === '/api/auth/password';
  const isPasswordResetRequest = route === '/api/auth/password-reset/request';
  const isPasswordResetVerify = route === '/api/auth/password-reset/verify';
  const isPhoto = route === '/api/auth/photo';
  const isContact = route === '/api/contact';
  const isCourseCatalog = route === '/api/courses';
  const isCourseEnrollments = route === '/api/courses/enrollments';
  const isCoursePaymentDetails = route === '/api/courses/payment-details';
  const isAdminCoursePayments = route === '/api/admin/course-payments';
  const adminCoursePaymentRoute = route.match(/^\/api\/admin\/course-payments\/(\d+)$/);
  const enrollmentRoute = route.match(/^\/api\/courses\/([a-z0-9-]+)\/enrollment$/);

  const knownRoute =
    [isRegister, isLogin, isLogout, isCurrentUser, isAccountUpdate, isPasswordChange,
      isPasswordResetRequest, isPasswordResetVerify, isPhoto, isContact, isCourseCatalog,
      isCourseEnrollments, isCoursePaymentDetails, isAdminCoursePayments].some(Boolean) ||
    !!enrollmentRoute ||
    !!adminCoursePaymentRoute;

  if (!knownRoute) return errorResponse(404, 'Not found.');

  const expectedMethod =
    isCurrentUser || isCourseCatalog || isCourseEnrollments || isCoursePaymentDetails || isAdminCoursePayments
      ? 'GET'
      : 'POST';

  const allowedMethods =
    isPhoto || enrollmentRoute
      ? ['GET', 'POST', 'DELETE']
      : adminCoursePaymentRoute
        ? ['POST']
        : [expectedMethod];

  if (!allowedMethods.includes(request.method)) {
    return errorResponse(405, 'Method not allowed.');
  }

  if (isCourseCatalog) {
    return jsonResponse(200, { courses: COURSES });
  }

  if (isCoursePaymentDetails) {
    return jsonResponse(200, {
      fee: 3000,
      currency: 'AOA',
      instructions: env.COURSE_PAYMENT_INSTRUCTIONS || '',
    });
  }

  if (isAdminCoursePayments || adminCoursePaymentRoute) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');

    const adminUserId = Number(env.COURSE_PAYMENT_ADMIN_USER_ID || 0);
    if (!Number.isSafeInteger(adminUserId) || adminUserId < 1) {
      return errorResponse(503, 'Course payment review is not configured.');
    }

    if (user.id !== adminUserId) {
      return errorResponse(403, 'You are not authorized to review course payments.');
    }

    if (isAdminCoursePayments) {
      const rows = await env.DB.prepare(`
        SELECT requests.id, requests.transaction_reference AS transactionReference,
               requests.created_at AS createdAt,
               users.first_name AS firstName,
               users.last_name AS lastName,
               users.identifier,
               courses.title AS courseTitle
        FROM course_payment_requests AS requests
        JOIN users ON users.id = requests.user_id
        JOIN courses ON courses.id = requests.course_id
        WHERE requests.status = 'pending'
        ORDER BY requests.created_at ASC
      `).all<any>();

      return jsonResponse(200, { requests: rows.results });
    }

    const requestId = Number(adminCoursePaymentRoute?.[1]);
    if (!Number.isSafeInteger(requestId) || requestId < 1) {
      return errorResponse(404, 'Payment request not found.');
    }

    const input = await readJson(request);
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw httpError(400, 'Request body must be a JSON object.');
    }

    if (!['approve', 'reject'].includes(String(input.action))) {
      throw httpError(400, 'Choose approve or reject.');
    }

    const pending = await env.DB.prepare(
      "SELECT user_id, course_id FROM course_payment_requests WHERE id = ? AND status = 'pending'"
    ).bind(requestId).first<any>();

    if (!pending) {
      const exists = await env.DB.prepare('SELECT id FROM course_payment_requests WHERE id = ?').bind(requestId).first<any>();
      return errorResponse(exists ? 409 : 404, exists ? 'This payment request has already been reviewed.' : 'Payment request not found.');
    }

    const nextStatus = input.action === 'approve' ? 'approved' : 'rejected';

    const statements = [
      env.DB.prepare(`
        UPDATE course_payment_requests
        SET status = ?, reviewed_at = ?, reviewed_by = ?
        WHERE id = ? AND status = 'pending'
      `).bind(nextStatus, Date.now(), user.id, requestId),
    ];

    if (input.action === 'approve') {
      statements.push(
        env.DB.prepare(`
          INSERT INTO course_enrollments (user_id, course_id, enrolled_at)
          SELECT user_id, course_id, ?
          FROM course_payment_requests
          WHERE id = ? AND status = 'approved'
          ON CONFLICT (user_id, course_id) DO NOTHING
        `).bind(Date.now(), requestId)
      );
    }

    const results = await env.DB.batch(statements as any);
    if (results[0].meta.changes === 0) {
      return errorResponse(409, 'This payment request has already been reviewed.');
    }

    return jsonResponse(200, { status: nextStatus });
  }

  if (isCurrentUser) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');
    const { photo_key: photoKey, ...publicUser } = user;
    return jsonResponse(200, {
      user: {
        ...publicUser,
        photo_url: photoKey ? '/api/auth/photo' : null,
      },
    });
  }

  if (isPhoto) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');

    if (request.method === 'GET') {
      if (!user.photo_key) return errorResponse(404, 'No profile photo.');
      const photo = await env.PHOTOS.get(user.photo_key);
      if (!photo) return errorResponse(404, 'No profile photo.');
      return new Response(await photo.arrayBuffer(), {
        headers: {
          'Cache-Control': 'private, no-store',
          'Content-Type': photo.type || 'application/octet-stream',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

    if (isRateLimited(request, 'profile-photo', 10)) {
      return errorResponse(429, 'Too many photo changes. Try again in a minute.');
    }

    if (request.method === 'DELETE') {
      if (user.photo_key) await env.PHOTOS.delete(user.photo_key);
      await env.DB.prepare('UPDATE users SET photo_key = NULL WHERE id = ?').bind(user.id).run();
      return jsonResponse(200, { ok: true });
    }

    const mimeType = (request.headers.get('content-type') || '').toLowerCase().split(';')[0].trim();
    const bytes = await readBytes(request, PHOTO_BODY_LIMIT);
    if (!validPhoto(bytes, mimeType)) {
      return errorResponse(400, 'Choose a valid JPEG, PNG, or WebP photo up to 2 MB.');
    }

    const photoKey = `profiles/${user.id}`;
    await env.PHOTOS.put(photoKey, bytes, { httpMetadata: { contentType: mimeType } });
    await env.DB.prepare('UPDATE users SET photo_key = ? WHERE id = ?').bind(photoKey, user.id).run();
    return jsonResponse(200, { ok: true, photo_url: '/api/auth/photo' });
  }

  if (isRegister && isRateLimited(request, 'register', 8)) return errorResponse(429, 'Too many attempts. Try again in a minute.');
  if (isLogin && isRateLimited(request, 'login', 10)) return errorResponse(429, 'Too many attempts. Try again in a minute.');
  if (isPasswordResetRequest && isRateLimited(request, 'password-reset-request', 5)) {
    return errorResponse(429, 'Too many requests. Wait a minute before trying again.');
  }
  if (isPasswordResetVerify && isRateLimited(request, 'password-reset-verify', 10)) {
    return errorResponse(429, 'Too many attempts. Wait a minute before trying again.');
  }
  if ((isAccountUpdate || isPasswordChange) && isRateLimited(request, route, 8)) {
    return errorResponse(429, 'Too many attempts. Try again in a minute.');
  }
  if (isContact && isRateLimited(request, 'contact', 5)) {
    return errorResponse(429, 'Too many messages. Try again in a minute.');
  }
  if (enrollmentRoute && isRateLimited(request, 'course-enrollment', 20)) {
    return errorResponse(429, 'Too many course changes. Try again in a minute.');
  }

  if (isCourseEnrollments || enrollmentRoute) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');

    if (isCourseEnrollments) {
      const rows = await env.DB.prepare(`
        SELECT courses.id, courses.title, courses.category, course_enrollments.enrolled_at AS enrolledAt
        FROM course_enrollments
        JOIN courses ON courses.id = course_enrollments.course_id
        WHERE course_enrollments.user_id = ?
        ORDER BY course_enrollments.enrolled_at DESC
      `).bind(user.id).all<any>();

      const paymentRequests = await env.DB.prepare(`
        SELECT requests.id, requests.course_id AS courseId, courses.title AS courseTitle,
               requests.status, requests.created_at AS createdAt
        FROM course_payment_requests AS requests
        JOIN courses ON courses.id = requests.course_id
        WHERE requests.user_id = ?
          AND requests.status IN ('pending', 'rejected')
          AND requests.id = (
            SELECT MAX(latest.id)
            FROM course_payment_requests AS latest
            WHERE latest.user_id = requests.user_id AND latest.course_id = requests.course_id
          )
        ORDER BY requests.created_at DESC
      `).bind(user.id).all<any>();

      return jsonResponse(200, {
        courses: rows.results,
        paymentRequests: paymentRequests.results,
      });
    }

    const courseId = enrollmentRoute?.[1];
    const course = COURSES.find((item) => item.id === courseId);
    if (!course) return errorResponse(404, 'Course not found.');

    if (request.method === 'POST') {
      if (!String(env.COURSE_PAYMENT_INSTRUCTIONS || '').trim()) {
        return errorResponse(503, 'Course payment instructions are not configured. Please contact support.');
      }

      const input = await readJson(request);
      if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw httpError(400, 'Request body must be a JSON object.');
      }

      const transactionReference = typeof input.transactionReference === 'string' ? input.transactionReference.trim() : '';
      if (transactionReference.length < 3 || transactionReference.length > 100) {
        throw httpError(400, 'Enter a payment reference between 3 and 100 characters.');
      }

      const existingEnrollment = await env.DB.prepare(
        'SELECT 1 FROM course_enrollments WHERE user_id = ? AND course_id = ?'
      ).bind(user.id, courseId).first<any>();

      if (existingEnrollment) {
        return jsonResponse(200, { enrolled: true, alreadyEnrolled: true });
      }

      await env.DB.prepare(`
        INSERT INTO course_payment_requests (user_id, course_id, transaction_reference, status, created_at)
        SELECT ?, ?, ?, 'pending', ?
        WHERE NOT EXISTS (
          SELECT 1 FROM course_enrollments WHERE user_id = ? AND course_id = ?
        )
        ON CONFLICT DO NOTHING
      `).bind(user.id, courseId, transactionReference, Date.now(), user.id, courseId).run();

      const approvedEnrollment = await env.DB.prepare(
        'SELECT 1 FROM course_enrollments WHERE user_id = ? AND course_id = ?'
      ).bind(user.id, courseId).first<any>();

      if (approvedEnrollment) {
        return jsonResponse(200, { enrolled: true, alreadyEnrolled: true });
      }

      const paymentRequest = await env.DB.prepare(`
        SELECT id FROM course_payment_requests
        WHERE user_id = ? AND course_id = ? AND status = 'pending'
      `).bind(user.id, courseId).first<any>();

      return jsonResponse(201, { enrolled: false, paymentPending: true, requestId: paymentRequest.id });
    }

    await env.DB.prepare('DELETE FROM course_enrollments WHERE user_id = ? AND course_id = ?')
      .bind(user.id, courseId)
      .run();

    return jsonResponse(200, { enrolled: false });
  }

  if (isLogout) {
    const token = getCookie(request, SESSION_COOKIE);
    if (token && /^[\\w-]{40,50}$/.test(token)) {
      await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
    }
    return jsonResponse(200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
  }

  const input = await readJson(request);
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw httpError(400, 'Request body must be a JSON object.');
  }

  if (isContact) {
    const name = getName(input.name, 'name');
    const email = normalizeEmail(input.email);
    if (typeof input.message !== 'string') throw httpError(400, 'Enter a message.');
    const message = input.message.trim();
    if (message.length < 10 || message.length > 5000) {
      throw httpError(400, 'Message must be between 10 and 5000 characters.');
    }

    await env.DB.prepare(`
      INSERT INTO contact_messages (name, email, message, created_at)
      VALUES (?, ?, ?, ?)
    `).bind(name, email, message, Date.now()).run();

    return jsonResponse(201, {
      ok: true,
      message: 'Your message has been received. Thank you for getting in touch.',
    });
  }

  if (isPasswordResetRequest) {
    const identifier = normalizeIdentifier(input.identifier);
    const channel = getRecoveryChannel(identifier);
    try {
      assertRecoveryConfiguration(channel, env);
    } catch {
      throw httpError(503, 'Password recovery is not configured for this contact method. Please contact support.');
    }

    const user = await env.DB.prepare('SELECT id FROM users WHERE identifier = ?').bind(identifier).first<any>();
    if (user) {
      const now = Date.now();
      const code = String(Math.floor(100000 + Math.random() * 900000));
      const codeHash = await hashRecoveryCode(env.PASSWORD_RESET_SECRET, user.id, code);

      const issued = await env.DB.prepare(`
        INSERT INTO password_reset_codes (user_id, code_hash, expires_at, attempts, requested_at)
        VALUES (?, ?, ?, 0, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          code_hash = excluded.code_hash,
          expires_at = excluded.expires_at,
          attempts = 0,
          requested_at = excluded.requested_at
        WHERE password_reset_codes.requested_at <= ?
      `).bind(user.id, codeHash, now + PASSWORD_RESET_CODE_TTL_MS, now, now - PASSWORD_RESET_RESEND_DELAY_MS).run();

      if (issued.meta.changes === 1) {
        try {
          await deliverRecoveryCode(channel, identifier, code, env);
        } catch (error) {
          console.error('Password reset code delivery failed.', error);
          await env.DB.prepare('DELETE FROM password_reset_codes WHERE user_id = ? AND code_hash = ?')
            .bind(user.id, codeHash)
            .run();
          throw httpError(502, 'We could not send a verification code. Please try again later.');
        }
      }
    }

    return jsonResponse(202, {
      ok: true,
      message: 'If an account matches those details, a verification code has been sent.',
    });
  }

  if (isPasswordResetVerify) {
    const identifier = normalizeIdentifier(input.identifier);
    try {
      assertResetSecret(env.PASSWORD_RESET_SECRET);
    } catch {
      throw httpError(503, 'Password recovery is not configured. Please contact support.');
    }

    if (typeof input.code !== 'string' || !/^\\d{6}$/.test(input.code)) {
      throw httpError(400, 'Enter the 6-digit verification code.');
    }

    validatePassword(input.newPassword);

    const user = await env.DB.prepare('SELECT id FROM users WHERE identifier = ?').bind(identifier).first<any>();
    if (!user) throw httpError(400, 'The verification code is invalid or expired.');

    const record = await env.DB.prepare(`
      SELECT code_hash, expires_at, attempts
      FROM password_reset_codes
      WHERE user_id = ?
    `).bind(user.id).first<any>();

    const now = Date.now();
    if (!record || record.expires_at <= now || record.attempts >= PASSWORD_RESET_MAX_ATTEMPTS) {
      await env.DB.prepare('DELETE FROM password_reset_codes WHERE user_id = ?').bind(user.id).run();
      throw httpError(400, 'The verification code is invalid or expired.');
    }

    const submittedHash = await hashRecoveryCode(env.PASSWORD_RESET_SECRET, user.id, input.code);
    if (!constantTimeEqual(submittedHash, record.code_hash)) {
      await env.DB.prepare(`
        UPDATE password_reset_codes SET attempts = attempts + 1
        WHERE user_id = ? AND attempts < ?
      `).bind(user.id, PASSWORD_RESET_MAX_ATTEMPTS).run();
      throw httpError(400, 'The verification code is invalid or expired.');
    }

    const credentials = await hashPassword(String(input.newPassword));

    const results = await env.DB.batch([
      env.DB.prepare(`
        UPDATE users SET password_salt = ?, password_hash = ?
        WHERE id = ?
          AND EXISTS (
            SELECT 1 FROM password_reset_codes
            WHERE user_id = ? AND code_hash = ? AND expires_at > ? AND attempts < ?
          )
      `).bind(credentials.salt, credentials.hash, user.id, user.id, record.code_hash, now, PASSWORD_RESET_MAX_ATTEMPTS),

      env.DB.prepare(`
        DELETE FROM password_reset_codes
        WHERE user_id = ? AND code_hash = ? AND expires_at > ? AND attempts < ?
      `).bind(user.id, record.code_hash, now, PASSWORD_RESET_MAX_ATTEMPTS),

      env.DB.prepare(`
        DELETE FROM sessions
        WHERE user_id = ?
          AND EXISTS (
            SELECT 1 FROM users
            WHERE id = ? AND password_salt = ? AND password_hash = ?
          )
      `).bind(user.id, user.id, credentials.salt, credentials.hash),
    ]);

    if (results[0].meta.changes !== 1) {
      throw httpError(400, 'The verification code is invalid or expired.');
    }

    return jsonResponse(200, {
      ok: true,
      message: 'Your password has been reset. Sign in with your new password.',
    });
  }

  if (isAccountUpdate || isPasswordChange) {
    const user = await findUser(request, env);
    if (!user) return errorResponse(401, 'Not signed in.');

    validatePassword(input.currentPassword);
    const credentials = await env.DB.prepare('SELECT password_salt, password_hash FROM users WHERE id = ?')
      .bind(user.id)
      .first<any>();

    if (!credentials || !(await passwordMatches(String(input.currentPassword), credentials.password_salt, credentials.password_hash))) {
      return errorResponse(403, 'Current password is incorrect.');
    }

    if (isAccountUpdate) {
      const firstName = getName(input.firstName, 'first name');
      const lastName = getName(input.lastName, 'last name');
      const identifier = normalizeIdentifier(input.identifier);

      try {
        await env.DB.prepare('UPDATE users SET first_name = ?, last_name = ?, identifier = ? WHERE id = ?')
          .bind(firstName, lastName, identifier, user.id)
          .run();
      } catch (error: any) {
        if (/UNIQUE constraint failed/i.test(error?.message || '')) {
          throw httpError(409, 'An account with that email or phone already exists.');
        }
        throw error;
      }

      return jsonResponse(200, {
        ok: true,
        user: { id: user.id, first_name: firstName, last_name: lastName, identifier },
      });
    }

    validatePassword(input.newPassword);
    if (input.currentPassword === input.newPassword) {
      throw httpError(400, 'Choose a new password that differs from your current one.');
    }

    const replacement = await hashPassword(String(input.newPassword));
    await env.DB.prepare('UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?')
      .bind(replacement.salt, replacement.hash, user.id)
      .run();

    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
    const token = await createSession(env, user.id);

    return jsonResponse(200, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
  }

  const identifier = normalizeIdentifier(input.identifier);
  validatePassword(input.password);

  if (isRegister) {
    const firstName = getName(input.firstName, 'first name');
    const lastName = getName(input.lastName, 'last name');
    const credentials = await hashPassword(String(input.password));

    let result;
    try {
      result = await env.DB.prepare(`
        INSERT INTO users (first_name, last_name, identifier, password_salt, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(firstName, lastName, identifier, credentials.salt, credentials.hash, Date.now()).run();
    } catch (error: any) {
      if (/UNIQUE constraint failed/i.test(error?.message || '')) {
        throw httpError(409, 'An account with that email or phone already exists.');
      }
      throw error;
    }

    const token = await createSession(env, Number(result.meta.last_row_id));
    return jsonResponse(201, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
  }

  const user = await env.DB.prepare('SELECT id, password_salt, password_hash FROM users WHERE identifier = ?')
    .bind(identifier)
    .first<any>();

  const dummy = {
    salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    hash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  };

  const matches = await passwordMatches(
    String(input.password),
    (user || dummy).password_salt || (user || dummy).salt,
    (user || dummy).password_hash || (user || dummy).hash
  );

  if (!user || !matches) {
    return errorResponse(401, 'Invalid email/phone number or password.');
  }

  const token = await createSession(env, user.id);
  return jsonResponse(200, { ok: true }, { 'Set-Cookie': sessionCookie(token) });
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // health check
    if (url.pathname === '/health' && request.method === 'GET') {
      return jsonResponse(200, { status: 'ok' }, { 'Cache-Control': 'no-store' });
    }

    // API routes
    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, url);
      } catch (error: any) {
        return errorResponse(error.status || 500, error.status ? error.message : 'An unexpected server error occurred.');
      }
    }

    // static files and HTML fallback before 404
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return errorResponse(405, 'Method not allowed.');
    }

    const pathname = url.pathname === '/' ? '/index.html' : url.pathname;

    if (!pathname.includes('.')) {
      const fallback = await env.ASSETS.fetch(new Request(new URL('/index.html', request.url)));
      if (fallback.status !== 404) return fallback;
    }

    const asset = await env.ASSETS.fetch(request);
    if (asset.status !== 404) return asset;

    return new Response('Not found', { status: 404 });
  },
};
