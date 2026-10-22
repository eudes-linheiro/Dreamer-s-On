const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');
const { createAuthServer } = require('../server');

let server;
let baseUrl;
let temporaryDirectory;

before(async () => {
  temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'dreamers-auth-'));
  server = createAuthServer({
    databasePath: path.join(temporaryDirectory, 'test.sqlite'),
    secureCookies: false,
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
      for (const course of ['English foundations', 'French essentials', 'Music theory', 'Music production']) {
        assert.ok(html.includes(`<h3>${course}</h3>`), `${course} should be listed`);
      }
    }
  }
});

test('includes profile and account links in every site navigation', async () => {
  const pages = [
    'index.html',
    'about.html',
    'contact.html',
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
    assert.match(navigation[0], /href="profile\.html"/, `${page} should link to Profile`);
    assert.match(navigation[0], /href="account\.html"/, `${page} should link to Account`);
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
    id: 2,
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

test('persists course enrollment per user and supports unenrollment', async () => {
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
  const enrollment = await fetch(enrollmentUrl, {
    method: 'POST',
    headers: { Cookie: cookie },
  });
  assert.equal(enrollment.status, 200);
  assert.deepEqual(await enrollment.json(), { enrolled: true, alreadyEnrolled: false });

  const duplicate = await fetch(enrollmentUrl, {
    method: 'POST',
    headers: { Cookie: cookie },
  });
  assert.deepEqual(await duplicate.json(), { enrolled: true, alreadyEnrolled: true });

  const enrollments = await fetch(`${baseUrl}/api/courses/enrollments`, {
    headers: { Cookie: cookie },
  });
  assert.equal(enrollments.status, 200);
  assert.equal((await enrollments.json()).courses[0].id, 'english-foundations');

  const unenrollment = await fetch(enrollmentUrl, {
    method: 'DELETE',
    headers: { Cookie: cookie },
  });
  assert.deepEqual(await unenrollment.json(), { enrolled: false });

  const emptyEnrollments = await fetch(`${baseUrl}/api/courses/enrollments`, {
    headers: { Cookie: cookie },
  });
  assert.deepEqual((await emptyEnrollments.json()).courses, []);
});