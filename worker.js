const SESSION_COOKIE = "dreamers_session";
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const COURSES = [
  { id: "english-foundations", title: "English foundations", category: "Language" },
  { id: "french-essentials", title: "French essentials", category: "Language" },
  { id: "music-theory", title: "Music theory", category: "Music" },
  { id: "music-production", title: "Music production", category: "Music" },
];

const HTML_PAGES = new Set([
  "/",
  "/index.html",
  "/about.html",
  "/contact.html",
  "/education.html",
  "/arts.html",
  "/technology.html",
  "/sports.html",
  "/login.html",
  "/signup.html",
  "/forgotpassword.html",
  "/profile.html",
  "/account.html",
  "/terms.html",
  "/privacy.html",
  "/course-payments.html",
]);

const STATIC_PREFIXES = [
  "/css/",
  "/js/",
  "/img-asset/",
  "/font-awesome/",
  "/fonts/",
  "/assets/",
];

const state = {
  users: new Map(),
  sessions: new Map(),
  resetCodes: new Map(),
  courseEnrollments: new Map(),
  coursePaymentRequests: new Map(),
  contactMessages: [],
};

function jsonResponse(status, body, extraHeaders = {}) {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function getCookieValue(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const entry = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));
  if (!entry) return null;
  return decodeURIComponent(entry.slice(name.length + 1));
}

function setSessionCookie(token) {
  return `dreamers_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`;
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hashPassword(password, saltBytes = crypto.getRandomValues(new Uint8Array(16))) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: 120000,
    },
    key,
    256
  );
  return {
    salt: Array.from(saltBytes).map((byte) => byte.toString(16).padStart(2, "0")).join(""),
    hash: Array.from(new Uint8Array(derived)).map((byte) => byte.toString(16).padStart(2, "0")).join(""),
  };
}

async function verifyPassword(password, saltHex, hashHex) {
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g).map((byte) => Number.parseInt(byte, 16)));
  const expected = new Uint8Array(hashHex.match(/.{1,2}/g).map((byte) => Number.parseInt(byte, 16)));
  const candidate = await hashPassword(password, salt);
  const candidateHash = new Uint8Array(candidate.hash.match(/.{1,2}/g).map((byte) => Number.parseInt(byte, 16)));
  let diff = 0;
  for (let i = 0; i < expected.length; i += 1) {
    diff |= expected[i] ^ candidateHash[i];
  }
  return diff === 0;
}

function normalizeIdentifier(value) {
  if (typeof value !== "string") throw new Error("Enter a valid email address or Angola phone number.");
  const identifier = value.trim();
  if (!identifier) throw new Error("Enter a valid email address or Angola phone number.");
  if (identifier.includes("@")) {
    const email = identifier.toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw new Error("Enter a valid email address.");
    }
    return email;
  }
  const compact = identifier.replace(/[\s().-]/g, "");
  let national = compact;
  if (compact.startsWith("+244")) national = compact.slice(4);
  else if (compact.startsWith("00244")) national = compact.slice(5);
  else if (compact.startsWith("244") && compact.length === 12) national = compact.slice(3);
  if (!/^[2-9]\d{8}$/.test(national)) {
    throw new Error("Enter an Angola phone number with 9 digits and country code +244.");
  }
  return `+244${national}`;
}

function getName(value, fieldName) {
  if (typeof value !== "string") {
    throw new Error(`Enter your ${fieldName}.`);
  }
  const name = value.trim();
  if (!name || name.length > 80) {
    throw new Error(`Enter a ${fieldName} up to 80 characters long.`);
  }
  return name;
}

function validatePassword(value) {
  if (typeof value !== "string" || value.length < 8 || value.length > 128) {
    throw new Error("Password must be between 8 and 128 characters.");
  }
}

function getUserFromRequest(request) {
  const token = getCookieValue(request, SESSION_COOKIE);
  if (!token) return null;
  return state.sessions.get(token) || null;
}

function createSession(userId) {
  const token = randomToken();
  const expiresAt = Date.now() + SESSION_TTL_MS;
  state.sessions.set(token, { userId, expiresAt });
  return { token, expiresAt };
}

function clearExpiredSessions() {
  for (const [token, session] of state.sessions.entries()) {
    if (session.expiresAt <= Date.now()) {
      state.sessions.delete(token);
    }
  }
}

function createResetCode(identifier) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 10 * 60 * 1000;
  state.resetCodes.set(identifier, { code, expiresAt, attempts: 0 });
  return code;
}

function verifyResetCode(identifier, submittedCode) {
  const record = state.resetCodes.get(identifier);
  if (!record) return false;
  if (record.expiresAt < Date.now()) {
    state.resetCodes.delete(identifier);
    return false;
  }
  const match = record.code === submittedCode;
  if (!match) {
    record.attempts += 1;
    if (record.attempts >= 5) state.resetCodes.delete(identifier);
  }
  return match;
}

async function parseJsonBody(request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("Content-Type must be application/json.");
  }
  return await request.json();
}

function toPublicUser(user) {
  return {
    id: user.id,
    first_name: user.firstName,
    last_name: user.lastName,
    identifier: user.identifier,
    photo_url: user.photo_url || null,
  };
}

async function ensureStaticAsset(request, env, pathname) {
  if (!env.ASSETS) {
    return new Response("Static asset not available in this worker.", {
      status: 404,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const assetUrl = new URL(pathname, request.url);
  const asset = await env.ASSETS.fetch(assetUrl);
  if (asset.status === 404) {
    return new Response("Asset not found", {
      status: 404,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  return asset;
}

async function handleAuth(request, url, body) {
  const route = url.pathname;

  if (route === "/api/auth/me") {
    if (request.method !== "GET") return jsonResponse(405, { error: "Method not allowed." });
    const user = getUserFromRequest(request);
    if (!user) return jsonResponse(401, { error: "Not signed in." });
    const actualUser = state.users.get(user.userId);
    if (!actualUser) return jsonResponse(401, { error: "Not signed in." });
    return jsonResponse(200, { user: toPublicUser(actualUser) });
  }

  if (route === "/api/auth/logout") {
    if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
    const token = getCookieValue(request, SESSION_COOKIE);
    if (token) state.sessions.delete(token);
    return jsonResponse(200, { ok: true }, { "Set-Cookie": `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` });
  }

  if (route === "/api/auth/register") {
    if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
    try {
      const identifier = normalizeIdentifier(body.identifier);
      const firstName = getName(body.firstName, "first name");
      const lastName = getName(body.lastName, "last name");
      validatePassword(body.password);
      if (body.password !== body.confirmPassword) {
        return jsonResponse(400, { error: "Passwords do not match." });
      }
      if (state.users.has(identifier)) {
        return jsonResponse(409, { error: "An account with that email or phone already exists." });
      }
      const credentials = await hashPassword(body.password);
      const userId = String(Date.now()) + Math.random().toString(36).slice(2, 10);
      const user = {
        id: userId,
        firstName,
        lastName,
        identifier,
        passwordHash: credentials.hash,
        passwordSalt: credentials.salt,
        photo_url: null,
        createdAt: Date.now(),
      };
      state.users.set(identifier, user);
      const session = createSession(userId);
      return jsonResponse(201, { ok: true }, { "Set-Cookie": setSessionCookie(session.token) });
    } catch (error) {
      return jsonResponse(400, { error: error.message || "Unable to create your account." });
    }
  }

  if (route === "/api/auth/login") {
    if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
    try {
      const identifier = normalizeIdentifier(body.identifier);
      validatePassword(body.password);
      const user = state.users.get(identifier);
      if (!user) return jsonResponse(401, { error: "Invalid email/phone number or password." });
      const matches = await verifyPassword(body.password, user.passwordSalt, user.passwordHash);
      if (!matches) return jsonResponse(401, { error: "Invalid email/phone number or password." });
      const session = createSession(user.id);
      return jsonResponse(200, { ok: true }, { "Set-Cookie": setSessionCookie(session.token) });
    } catch (error) {
      return jsonResponse(400, { error: error.message || "Unable to sign in." });
    }
  }

  if (route === "/api/auth/password") {
    if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
    const currentUser = getUserFromRequest(request);
    if (!currentUser) return jsonResponse(401, { error: "Not signed in." });
    const user = state.users.get(currentUser.identifier) || [...state.users.values()].find((entry) => entry.id === currentUser.userId);
    if (!user) return jsonResponse(401, { error: "Not signed in." });
    try {
      validatePassword(body.currentPassword);
      validatePassword(body.newPassword);
      if (body.currentPassword === body.newPassword) {
        return jsonResponse(400, { error: "Choose a new password that differs from your current one." });
      }
      const matches = await verifyPassword(body.currentPassword, user.passwordSalt, user.passwordHash);
      if (!matches) return jsonResponse(403, { error: "Current password is incorrect." });
      const credentials = await hashPassword(body.newPassword);
      user.passwordHash = credentials.hash;
      user.passwordSalt = credentials.salt;
      return jsonResponse(200, { ok: true });
    } catch (error) {
      return jsonResponse(400, { error: error.message || "Unable to change password." });
    }
  }

  if (route === "/api/auth/account") {
    if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
    const currentUser = getUserFromRequest(request);
    if (!currentUser) return jsonResponse(401, { error: "Not signed in." });
    const user = state.users.get(currentUser.identifier) || [...state.users.values()].find((entry) => entry.id === currentUser.userId);
    if (!user) return jsonResponse(401, { error: "Not signed in." });
    try {
      const firstName = getName(body.firstName, "first name");
      const lastName = getName(body.lastName, "last name");
      const identifier = normalizeIdentifier(body.identifier);
      if (identifier !== user.identifier && state.users.has(identifier)) {
        return jsonResponse(409, { error: "An account with that email or phone already exists." });
      }
      user.firstName = firstName;
      user.lastName = lastName;
      if (identifier !== user.identifier) {
        state.users.delete(user.identifier);
        user.identifier = identifier;
        state.users.set(identifier, user);
      }
      return jsonResponse(200, { ok: true, user: toPublicUser(user) });
    } catch (error) {
      return jsonResponse(400, { error: error.message || "Unable to update your account." });
    }
  }

  if (route === "/api/auth/password-reset/request") {
    if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
    try {
      const identifier = normalizeIdentifier(body.identifier);
      const user = state.users.get(identifier);
      if (user) {
        const code = createResetCode(identifier);
        console.log(`Password reset code for ${identifier}: ${code}`);
      }
      return jsonResponse(202, {
        ok: true,
        message: "If an account matches those details, a verification code has been sent.",
      });
    } catch (error) {
      return jsonResponse(400, { error: error.message || "Unable to request a reset code." });
    }
  }

  if (route === "/api/auth/password-reset/verify") {
    if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
    try {
      const identifier = normalizeIdentifier(body.identifier);
      if (typeof body.code !== "string" || !/^\d{6}$/.test(body.code)) {
        return jsonResponse(400, { error: "Enter the 6-digit verification code." });
      }
      validatePassword(body.newPassword);
      const resetCode = state.resetCodes.get(identifier);
      if (!resetCode || !verifyResetCode(identifier, body.code)) {
        return jsonResponse(400, { error: "The verification code is invalid or expired." });
      }
      const user = state.users.get(identifier);
      if (!user) {
        state.resetCodes.delete(identifier);
        return jsonResponse(400, { error: "The verification code is invalid or expired." });
      }
      const credentials = await hashPassword(body.newPassword);
      user.passwordHash = credentials.hash;
      user.passwordSalt = credentials.salt;
      state.resetCodes.delete(identifier);
      return jsonResponse(200, {
        ok: true,
        message: "Your password has been reset. Sign in with your new password.",
      });
    } catch (error) {
      return jsonResponse(400, { error: error.message || "Unable to complete password reset." });
    }
  }

  return jsonResponse(404, { error: "Not found." });
}

async function handleCourses(request, url) {
  const path = url.pathname;

  if (path === "/api/courses") {
    if (request.method !== "GET") return jsonResponse(405, { error: "Method not allowed." });
    return jsonResponse(200, { courses: COURSES });
  }

  if (path === "/api/courses/payment-details") {
    if (request.method !== "GET") return jsonResponse(405, { error: "Method not allowed." });
    return jsonResponse(200, {
      fee: 3000,
      currency: "AOA",
      instructions: "Please transfer to Dreamer's On account and share your payment reference when enrolling.",
    });
  }

  if (path === "/api/courses/enrollments") {
    if (request.method !== "GET") return jsonResponse(405, { error: "Method not allowed." });
    const user = getUserFromRequest(request);
    if (!user) return jsonResponse(401, { error: "Not signed in." });
    const enrolled = [...(state.courseEnrollments.get(user.userId) || [])];
    const paymentRequests = [...(state.coursePaymentRequests.get(user.userId) || [])];
    return jsonResponse(200, {
      courses: enrolled.map((courseId) => COURSES.find((course) => course.id === courseId)).filter(Boolean),
      paymentRequests,
    });
  }

  const enrollmentMatch = path.match(/^\/api\/courses\/([a-z0-9-]+)\/enrollment$/);
  if (enrollmentMatch) {
    const courseId = enrollmentMatch[1];
    const course = COURSES.find((entry) => entry.id === courseId);
    if (!course) return jsonResponse(404, { error: "Course not found." });
    const user = getUserFromRequest(request);
    if (!user) return jsonResponse(401, { error: "Not signed in." });

    if (request.method === "POST") {
      try {
        const body = await parseJsonBody(request);
        const transactionReference = String(body.transactionReference || "").trim();
        if (!transactionReference || transactionReference.length < 3) {
          return jsonResponse(400, { error: "Enter a payment reference between 3 and 100 characters." });
        }
        const userEnrollments = state.courseEnrollments.get(user.userId) || new Set();
        if (userEnrollments.has(courseId)) {
          return jsonResponse(200, { enrolled: true, alreadyEnrolled: true });
        }
        const paymentRequests = state.coursePaymentRequests.get(user.userId) || [];
        const existingRequest = paymentRequests.find((requestEntry) => requestEntry.courseId === courseId && requestEntry.status === "pending");
        if (existingRequest) {
          return jsonResponse(201, { enrolled: false, paymentPending: true, requestId: existingRequest.id });
        }
        const paymentRequest = {
          id: crypto.randomUUID(),
          userId: user.userId,
          courseId,
          transactionReference,
          status: "pending",
          createdAt: Date.now(),
        };
        paymentRequests.push(paymentRequest);
        state.coursePaymentRequests.set(user.userId, paymentRequests);
        return jsonResponse(201, { enrolled: false, paymentPending: true, requestId: paymentRequest.id });
      } catch (error) {
        return jsonResponse(400, { error: error.message || "Unable to submit payment reference." });
      }
    }

    if (request.method === "DELETE") {
      const userEnrollments = state.courseEnrollments.get(user.userId) || new Set();
      userEnrollments.delete(courseId);
      state.courseEnrollments.set(user.userId, userEnrollments);
      return jsonResponse(200, { enrolled: false });
    }

    return jsonResponse(405, { error: "Method not allowed." });
  }

  return jsonResponse(404, { error: "Not found." });
}

async function handleContact(request, url) {
  if (url.pathname !== "/api/contact") return null;
  if (request.method !== "POST") return jsonResponse(405, { error: "Method not allowed." });
  try {
    const body = await parseJsonBody(request);
    const name = getName(body.name, "name");
    const email = normalizeIdentifier(body.email);
    if (typeof body.message !== "string") throw new Error("Enter a message.");
    const message = body.message.trim();
    if (message.length < 10 || message.length > 5000) throw new Error("Message must be between 10 and 5000 characters.");
    state.contactMessages.push({ name, email, message, createdAt: Date.now() });
    return jsonResponse(201, { ok: true, message: "Your message has been received. Thank you for getting in touch." });
  } catch (error) {
    return jsonResponse(400, { error: error.message || "Unable to send message." });
  }
}

async function servePageOrAsset(request, env, pathname) {
  const filePath = pathname === "/" ? "/index.html" : pathname;

  if (env.ASSETS) {
    return ensureStaticAsset(request, env, filePath);
  }

  const staticResponse = new Response("This worker is running without an ASSETS binding.", {
    status: 404,
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
  return staticResponse;
}

export default {
  async fetch(request, env) {
    clearExpiredSessions();

    const url = new URL(request.url);
    const pathname = url.pathname;

    if (pathname === "/health" && request.method === "GET") {
      return jsonResponse(200, { status: "ok" });
    }

    if (pathname.startsWith("/api/")) {
      try {
        if (pathname.startsWith("/api/auth/")) {
          const body = await parseJsonBody(request).catch(() => ({}));
          return await handleAuth(request, url, body);
        }

        if (pathname.startsWith("/api/courses")) {
          return await handleCourses(request, url);
        }

        if (pathname === "/api/contact") {
          return await handleContact(request, url);
        }

        return jsonResponse(404, { error: "Not found." });
      } catch (error) {
        return jsonResponse(500, { error: error.message || "An unexpected server error occurred." });
      }
    }

    if (HTML_PAGES.has(pathname) || pathname === "/") {
      return servePageOrAsset(request, env, pathname);
    }

    if (STATIC_PREFIXES.some((prefix) => pathname.startsWith(prefix))) {
      return servePageOrAsset(request, env, pathname);
    }

    if (pathname.startsWith("/favicon")) {
      return servePageOrAsset(request, env, "/img-asset/brand.png");
    }

    return new Response("Page not found", {
      status: 404,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  },
};
