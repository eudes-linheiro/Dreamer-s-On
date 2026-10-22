const textEncoder = new TextEncoder();

export function getRecoveryChannel(identifier) {
  return identifier.includes('@') ? 'email' : 'sms';
}

export function assertResetSecret(secret) {
  if (typeof secret !== 'string' || secret.length < 32) {
    throw new Error('Password recovery is not configured.');
  }
}

export function assertRecoveryConfiguration(channel, env) {
  assertResetSecret(env.PASSWORD_RESET_SECRET);

  if (channel === 'email') {
    if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL) {
      throw new Error('Email recovery is not configured.');
    }
    return;
  }

  if (!env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN || !env.TWILIO_FROM_PHONE) {
    throw new Error('SMS recovery is not configured.');
  }
}

export function createRecoveryCode() {
  const range = 900_000;
  const limit = Math.floor(0x1_0000_0000 / range) * range;
  const randomValues = new Uint32Array(1);
  let value;
  do {
    crypto.getRandomValues(randomValues);
    [value] = randomValues;
  } while (value >= limit);
  return String(100_000 + (value % range));
}

export async function hashRecoveryCode(secret, userId, code) {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const digest = await crypto.subtle.sign('HMAC', key, textEncoder.encode(`${userId}:${code}`));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function constantTimeEqual(first, second) {
  let difference = first.length ^ second.length;
  for (let index = 0; index < Math.min(first.length, second.length); index += 1) {
    difference |= first.charCodeAt(index) ^ second.charCodeAt(index);
  }
  return difference === 0;
}

export async function deliverRecoveryCode(channel, destination, code, env) {
  assertRecoveryConfiguration(channel, env);

  const message = `Your Dreamer's On verification code is ${code}. It expires in 10 minutes. If you did not request this code, you can ignore this message.`;
  let response;
  if (channel === 'email') {
    response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: env.RESEND_FROM_EMAIL,
        to: [destination],
        subject: 'Your Dreamer’s On password reset code',
        text: message,
      }),
      signal: AbortSignal.timeout(10_000),
    });
  } else {
    const credentials = btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);
    const body = new URLSearchParams({
      From: env.TWILIO_FROM_PHONE,
      To: destination,
      Body: message,
    });
    response = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(env.TWILIO_ACCOUNT_SID)}/Messages.json`,
      {
        method: 'POST',
        headers: {
          Authorization: `Basic ${credentials}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
        signal: AbortSignal.timeout(10_000),
      },
    );
  }

  if (!response.ok) {
    throw new Error(`Recovery message delivery failed with status ${response.status}.`);
  }
}
