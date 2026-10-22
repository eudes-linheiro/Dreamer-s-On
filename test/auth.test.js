const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');
const { createAuthServer } = require('../server');

let server;
let baseUrl;
let temporaryDirectory;
const recoveryDeliveries = [];
let testEnvironment;

before(async () => {
  temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'dreamers-auth-'));
  testEnvironment = {
    PASSWORD_RESET_SECRET: 'test-password-recovery-secret-with-at-least-32-characters',
    RESEND_API_KEY: 'test-resend-key',
    RESEND_FROM_EMAIL: 'test@example.test',
    TWILIO_ACCOUNT_SID: 'test-account',
    TWILIO_AUTH_TOKEN: 'test-token',
    TWILIO_FROM_PHONE: '+15555550123',
    COURSE_PAYMENT_INSTRUCTIONS: 'Send 3,000 AOA to the test account and enter the transfer reference.',
  };
  server = createAuthServer({
    databasePath: path.join(temporaryDirectory, 'test.sqlite'),
    secureCookies: false,
    environment: testEnvironment,
    sendRecoveryCode: async (channel, destination, code) => {
      recoveryDeliveries.push({ channel, destination, code });
    },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  server.database.close();
  fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

async function postJson(route, payload, cookie) {
  return fetch(`${baseUrl}/api/auth/${route}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body: JSON.stringify(payload),
  });
}

test('registers with a phone number, logs in, and enforces unique identifiers', async () => {
  const registration = await postJson('register', {
    firstName: 'Ada',
    lastName: 'Dreamer',
    identifier: '+244 923 456 789',
    password: 'a-secure-password',
  });
  assert.equal(registration.status, 201);
  const registrationCookie = registration.headers.get('set-cookie');
  assert.match(registrationCookie, /HttpOnly/);
  assert.match(registrationCookie, /SameSite=Strict/);

  const duplicate = await postJson('register', {
    firstName: 'Another',
    lastName: 'Person',
    identifier: '923 456 789',
    password: 'a-secure-password',
  });
  assert.equal(duplicate.status, 409);

  const login = await postJson('login', {
    identifier: '00244 923 456 789',
    password: 'a-secure-password',
  });
  assert.equal(login.status, 200);
  const loginCookie = login.headers.get('set-cookie').split(';')[0];

  const currentUser = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Cookie: loginCookie },
  });
  assert.equal(currentUser.status, 200);
  assert.deepEqual((await currentUser.json()).user, {
    id: 1,
    first_name: 'Ada',
    last_name: 'Dreamer',
    identifier: '+244923456789',
  });

  const invalidLogin = await postJson('login', {
    identifier: '+244923456789',
    password: 'wrong-password',
  });
  assert.equal(invalidLogin.status, 401);
});

test('rejects invalid registration data', async () => {
  const response = await postJson('register', {
    firstName: 'Ada',
    lastName: 'Dreamer',
    identifier: '+1 555 123 4567',
    password: 'a-secure-password',
  });
  assert.equal(response.status, 400);
});

test('validates email syntax and reports the same login error for unknown users and wrong passwords', async () => {
  const invalidEmail = await postJson('register', {
    firstName: 'Ada',
    lastName: 'Dreamer',
    identifier: 'ada@@example..com',
    password: 'a-secure-password',
  });
  assert.equal(invalidEmail.status, 400);

  const unknownAccount = await postJson('login', {
    identifier: 'missing@example.test',
    password: 'a-secure-password',
  });
  const wrongPassword = await postJson('login', {
    identifier: '923456789',
    password: 'wrong-password',
  });
  assert.equal(unknownAccount.status, 401);
  assert.equal(wrongPassword.status, 401);
  assert.deepEqual(await unknownAccount.json(), await wrongPassword.json());
});

test('resets passwords using one-time codes sent to email or phone', async () => {
  recoveryDeliveries.length = 0;
  const registration = await postJson('register', {
    firstName: 'Reset',
    lastName: 'Email',
    identifier: 'reset@example.test',
    password: 'original-password-123',
  });
  const originalCookie = registration.headers.get('set-cookie').split(';')[0];

  const emailRequest = await postJson('password-reset/request', { identifier: 'RESET@example.test' });
  assert.equal(emailRequest.status, 202);
  assert.match((await emailRequest.json()).message, /if an account matches/i);
  assert.deepEqual(recoveryDeliveries[0] && {
    channel: recoveryDeliveries[0].channel,
    destination: recoveryDeliveries[0].destination,
  }, { channel: 'email', destination: 'reset@example.test' });

  const resetUser = server.database.prepare('SELECT id FROM users WHERE identifier = ?').get('reset@example.test');
  const storedCode = server.database.prepare(`
    SELECT code_hash FROM password_reset_codes WHERE user_id = ?
  `).get(resetUser.id);
  assert.notEqual(storedCode.code_hash, recoveryDeliveries[0].code);

  const unknownRequest = await postJson('password-reset/request', { identifier: 'nobody@example.test' });
  assert.equal(unknownRequest.status, 202);
  assert.deepEqual(await unknownRequest.json(), {
    ok: true,
    message: 'If an account matches those details, a verification code has been sent.',
  });
  assert.equal(recoveryDeliveries.length, 1);

  const invalidCode = await postJson('password-reset/verify', {
    identifier: 'reset@example.test',
    code: '000000',
    newPassword: 'replacement-password-456',
  });
  assert.equal(invalidCode.status, 400);

  const reset = await postJson('password-reset/verify', {
    identifier: 'reset@example.test',
    code: recoveryDeliveries[0].code,
    newPassword: 'replacement-password-456',
  });
  assert.equal(reset.status, 200);
  assert.equal((await reset.json()).ok, true);

  const replay = await postJson('password-reset/verify', {
    identifier: 'reset@example.test',
    code: recoveryDeliveries[0].code,
    newPassword: 'another-password-789',
  });
  assert.equal(replay.status, 400);

  const revokedSession = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Cookie: originalCookie },
  });
  assert.equal(revokedSession.status, 401);
  assert.equal((await postJson('login', {
    identifier: 'reset@example.test',
    password: 'original-password-123',
  })).status, 401);
  assert.equal((await postJson('login', {
    identifier: 'reset@example.test',
    password: 'replacement-password-456',
  })).status, 200);

  const phoneRegistration = await postJson('register', {
    firstName: 'Reset',
    lastName: 'Phone',
    identifier: '+244 923 456 781',
    password: 'original-password-123',
  });
  assert.equal(phoneRegistration.status, 201);
  const smsRequest = await postJson('password-reset/request', { identifier: '00244 923 456 781' });
  assert.equal(smsRequest.status, 202);
  assert.deepEqual(recoveryDeliveries[1] && {
    channel: recoveryDeliveries[1].channel,
    destination: recoveryDeliveries[1].destination,
  }, { channel: 'sms', destination: '+244923456781' });
});

test('expires recovery codes and limits verification attempts', async () => {
  recoveryDeliveries.length = 0;
  const identifier = '+244923456781';
  const user = server.database.prepare('SELECT id FROM users WHERE identifier = ?').get(identifier);
  server.database.prepare('UPDATE password_reset_codes SET requested_at = ? WHERE user_id = ?')
    .run(Date.now() - 60_001, user.id);

  const request = await postJson('password-reset/request', { identifier });
  assert.equal(request.status, 202);
  const code = recoveryDeliveries[0].code;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await postJson('password-reset/verify', {
      identifier,
      code: '000000',
      newPassword: 'replacement-password-456',
    });
    assert.equal(response.status, 400);
  }
  const locked = await postJson('password-reset/verify', {
    identifier,
    code,
    newPassword: 'replacement-password-456',
  });
  assert.equal(locked.status, 400);
  assert.equal(server.database.prepare('SELECT 1 FROM password_reset_codes WHERE user_id = ?').get(user.id), undefined);

  const expiredRequest = await postJson('password-reset/request', { identifier });
  assert.equal(expiredRequest.status, 202);
  server.database.prepare('UPDATE password_reset_codes SET expires_at = ? WHERE user_id = ?')
    .run(Date.now() - 1, user.id);
  const expired = await postJson('password-reset/verify', {
    identifier,
    code: recoveryDeliveries[1].code,
    newPassword: 'replacement-password-456',
  });
  assert.equal(expired.status, 400);
});

test('stores valid contact messages and returns a confirmation', async () => {
  const response = await fetch(`${baseUrl}/api/contact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
    name: 'Amina Example',
    email: 'AMINA@example.test',
    message: 'I would like to learn more about the community.',
    }),
  });
  assert.equal(response.status, 201);
  assert.match((await response.json()).message, /message has been received/i);
  const storedMessage = server.database.prepare(
    'SELECT name, email FROM contact_messages ORDER BY id DESC LIMIT 1',
  ).get();
  assert.deepEqual({ ...storedMessage }, { name: 'Amina Example', email: 'amina@example.test' });
});

test('serves the profile page', async () => {
  const response = await fetch(`${baseUrl}/profile.html`);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Your profile/);
});

test('serves the protected course payment review interface', async () => {
  const response = await fetch(`${baseUrl}/course-payments.html`);
  assert.equal(response.status, 200);
  assert.match(await response.text(), /js\/course-payment-admin\.js/);
});

test('reports server health', async () => {
  const response = await fetch(`${baseUrl}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
});

test('serves each homepage focus area page', async () => {
  const pages = [
    ['education.html', 'Education'],
    ['technology.html', 'Technology'],
    ['arts.html', 'Arts'],
    ['sports.html', 'Sports'],
  ];

  for (const [page, heading] of pages) {
    const response = await fetch(`${baseUrl}/${page}`);
    assert.equal(response.status, 200, `${page} should be served`);
    const html = await response.text();
    assert.match(html, new RegExp(`<h1[^>]*>${heading}</h1>`));
    if (page === 'education.html') {
      assert.match(html, /Registration is 3,000 AOA per course/);
      assert.match(html, /id="course-payment-dialog"/);
      for (const course of ['English foundations', 'French essentials', 'Music theory', 'Music production']) {
        assert.ok(html.includes(`<h3>${course}</h3>`), `${course} should be listed`);
      }
    }
  }
});

test('keeps every site navigation focused on the main destinations', async () => {
  const pages = [
    'index.html',
    'about.html',
    'contact.html',
    'course-payments.html',
    'education.html',
    'forgotpassword.html',
    'login.html',
    'signup.html',
    'profile.html',
    'account.html',
    'arts.html',
    'sports.html',
    'technology.html',
  ];

  for (const page of pages) {
    const response = await fetch(`${baseUrl}/${page}`);
    assert.equal(response.status, 200, `${page} should be served`);
    const html = await response.text();
    const navigation = html.match(/<nav\b[^>]*aria-label="Main navigation"[^>]*>[\s\S]*?<\/nav>/);
    assert.ok(navigation, `${page} should have a main navigation`);
    assert.match(navigation[0], /data-menu-toggle/, `${page} should have a responsive menu toggle`);
    assert.match(navigation[0], /aria-controls="main-navigation"/, `${page} should connect the toggle to its menu`);
    assert.match(html, /<script src="js\/navigation\.js" defer><\/script>/, `${page} should load the navigation behavior`);
    const expectedDestinations = ['about.html', 'contact.html', 'profile.html'];
    if (page === 'about.html' || page === 'contact.html') expectedDestinations.unshift('index.html');
    assert.equal((navigation[0].match(/<a\b/g) || []).length, expectedDestinations.length, `${page} should have only its expected navigation links`);
    for (const destination of expectedDestinations) {
      assert.ok(navigation[0].includes(`href="${destination}"`), `${page} should link to ${destination}`);
    }
    if (page !== 'about.html' && page !== 'contact.html') {
      assert.doesNotMatch(navigation[0], /href="index\.html"/, `${page} should omit Home from the main navigation`);
    }
    assert.doesNotMatch(navigation[0], /href="(?:login|signup)\.html"/, `${page} should omit authentication links from the main navigation`);
    assert.match(navigation[0], /class="nav-profile-link"/, `${page} should show the profile icon`);
    assert.doesNotMatch(navigation[0], /class="nav-profile-link"[^>]*hidden/, `${page} should not hide the profile icon`);
    assert.doesNotMatch(navigation[0], /href="account\.html"/, `${page} should omit account settings from the main navigation`);
  }
});

test('provides terms and privacy links in every site footer', async () => {
  const pages = [
    'index.html',
    'about.html',
    'contact.html',
    'course-payments.html',
    'education.html',
    'forgotpassword.html',
    'login.html',
    'signup.html',
    'profile.html',
    'account.html',
    'arts.html',
    'sports.html',
    'technology.html',
    'terms.html',
    'privacy.html',
  ];

  for (const page of pages) {
    const response = await fetch(`${baseUrl}/${page}`);
    assert.equal(response.status, 200, `${page} should be served`);
    const html = await response.text();
    const footer = html.match(/<footer\b[\s\S]*?<\/footer>/);
    assert.ok(footer, `${page} should have a footer`);
    assert.match(footer[0], /href="terms\.html"/, `${page} should link to the Terms of Use`);
    assert.match(footer[0], /href="privacy\.html"/, `${page} should link to the Privacy Policy`);
    if (page === 'forgotpassword.html') {
      assert.match(html, /id="recovery-request-form"/);
      assert.match(html, /id="recovery-verify-form" hidden/);
      assert.match(html, /id="recovery-complete" hidden/);
      assert.match(html, /js\/forgot-password\.js/);
    }
    if (page === 'terms.html') assert.match(html, /<h1>Terms of Use<\/h1>/);
    if (page === 'privacy.html') assert.match(html, /<h1>Privacy Policy<\/h1>/);
  }
});

test('requires the current password for account changes and rotates sessions on password change', async () => {
  const registration = await postJson('register', {
    firstName: 'Sam',
    lastName: 'Member',
    identifier: 'sam@example.test',
    password: 'old-password-123',
  });
  assert.equal(registration.status, 201);
  const originalCookie = registration.headers.get('set-cookie').split(';')[0];
  const registeredUser = server.database.prepare('SELECT id FROM users WHERE identifier = ?').get('sam@example.test');

  const unauthorizedUpdate = await postJson('account', {
    firstName: 'Sam',
    lastName: 'Member',
    identifier: 'sam@example.test',
    currentPassword: 'old-password-123',
  });
  assert.equal(unauthorizedUpdate.status, 401);

  const invalidPasswordUpdate = await postJson('account', {
    firstName: 'Sam',
    lastName: 'Member',
    identifier: 'sam@example.test',
    currentPassword: 'incorrect-password',
  }, originalCookie);
  assert.equal(invalidPasswordUpdate.status, 403);

  const accountUpdate = await postJson('account', {
    firstName: 'Samantha',
    lastName: 'Member',
    identifier: 'sam.member@example.test',
    currentPassword: 'old-password-123',
  }, originalCookie);
  assert.equal(accountUpdate.status, 200);
  assert.deepEqual((await accountUpdate.json()).user, {
    id: registeredUser.id,
    first_name: 'Samantha',
    last_name: 'Member',
    identifier: 'sam.member@example.test',
  });

  const passwordUpdate = await postJson('password', {
    currentPassword: 'old-password-123',
    newPassword: 'new-password-456',
  }, originalCookie);
  assert.equal(passwordUpdate.status, 200);
  const replacementCookie = passwordUpdate.headers.get('set-cookie').split(';')[0];

  const oldSession = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Cookie: originalCookie },
  });
  assert.equal(oldSession.status, 401);

  const newSession = await fetch(`${baseUrl}/api/auth/me`, {
    headers: { Cookie: replacementCookie },
  });
  assert.equal(newSession.status, 200);

  const oldPasswordLogin = await postJson('login', {
    identifier: 'sam.member@example.test',
    password: 'old-password-123',
  });
  assert.equal(oldPasswordLogin.status, 401);
  const newPasswordLogin = await postJson('login', {
    identifier: 'sam.member@example.test',
    password: 'new-password-456',
  });
  assert.equal(newPasswordLogin.status, 200);
});

test('requires payment review before course enrollment and supports unenrollment', async () => {
  const registration = await postJson('register', {
    firstName: 'Course',
    lastName: 'Learner',
    identifier: 'learner@example.test',
    password: 'course-password-123',
  });
  const cookie = registration.headers.get('set-cookie').split(';')[0];

  const catalog = await fetch(`${baseUrl}/api/courses`);
  assert.equal(catalog.status, 200);
  assert.deepEqual((await catalog.json()).courses.map((course) => course.id), [
    'english-foundations',
    'french-essentials',
    'music-theory',
    'music-production',
  ]);

  const unauthorized = await fetch(`${baseUrl}/api/courses/english-foundations/enrollment`, {
    method: 'POST',
  });
  assert.equal(unauthorized.status, 401);

  const enrollmentUrl = `${baseUrl}/api/courses/english-foundations/enrollment`;
  const paymentDetails = await fetch(`${baseUrl}/api/courses/payment-details`);
  assert.deepEqual(await paymentDetails.json(), {
    fee: 3000,
    currency: 'AOA',
    instructions: 'Send 3,000 AOA to the test account and enter the transfer reference.',
  });

  const missingReference = await fetch(enrollmentUrl, {
    method: 'POST',
    headers: { Cookie: cookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(missingReference.status, 400);

  const enrollment = await fetch(enrollmentUrl, {
    method: 'POST',
    headers: { Cookie: cookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ transactionReference: 'transfer-english-001' }),
  });
  assert.equal(enrollment.status, 201);
  const paymentRequest = await enrollment.json();
  assert.equal(paymentRequest.paymentPending, true);
  assert.equal(paymentRequest.enrolled, false);

  const duplicate = await fetch(enrollmentUrl, {
    method: 'POST',
    headers: { Cookie: cookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ transactionReference: 'transfer-english-duplicate' }),
  });
  assert.equal((await duplicate.json()).requestId, paymentRequest.requestId);

  const enrollments = await fetch(`${baseUrl}/api/courses/enrollments`, {
    headers: { Cookie: cookie },
  });
  assert.equal(enrollments.status, 200);
  const memberStatus = await enrollments.json();
  assert.deepEqual(memberStatus.courses, []);
  assert.equal(memberStatus.paymentRequests[0].status, 'pending');

  const unauthorizedReview = await fetch(`${baseUrl}/api/admin/course-payments`, {
    headers: { Cookie: cookie },
  });
  assert.equal(unauthorizedReview.status, 503);

  const adminLogin = await postJson('login', {
    identifier: 'sam.member@example.test',
    password: 'new-password-456',
  });
  const adminCookie = adminLogin.headers.get('set-cookie').split(';')[0];
  const adminAccount = await fetch(`${baseUrl}/api/auth/me`, { headers: { Cookie: adminCookie } });
  testEnvironment.COURSE_PAYMENT_ADMIN_USER_ID = String((await adminAccount.json()).user.id);
  const forbiddenReview = await fetch(`${baseUrl}/api/admin/course-payments`, {
    headers: { Cookie: cookie },
  });
  assert.equal(forbiddenReview.status, 403);
  const reviewQueue = await fetch(`${baseUrl}/api/admin/course-payments`, {
    headers: { Cookie: adminCookie },
  });
  const reviewRequests = (await reviewQueue.json()).requests;
  assert.equal(reviewRequests.length, 1);
  assert.equal(reviewRequests[0].id, paymentRequest.requestId);

  const approval = await fetch(`${baseUrl}/api/admin/course-payments/${paymentRequest.requestId}`, {
    method: 'POST',
    headers: { Cookie: adminCookie, 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'approve' }),
  });
  assert.equal(approval.status, 200);
  assert.deepEqual(await approval.json(), { status: 'approved' });

  const approvedEnrollments = await fetch(`${baseUrl}/api/courses/enrollments`, {
    headers: { Cookie: cookie },
  });
  assert.equal((await approvedEnrollments.json()).courses[0].id, 'english-foundations');

  const unenrollment = await fetch(enrollmentUrl, {
    method: 'DELETE',
    headers: { Cookie: cookie },
  });
  assert.deepEqual(await unenrollment.json(), { enrolled: false, removed: true });
  const emptyEnrollments = await fetch(`${baseUrl}/api/courses/enrollments`, {
    headers: { Cookie: cookie },
  });
  assert.deepEqual((await emptyEnrollments.json()).courses, []);
});