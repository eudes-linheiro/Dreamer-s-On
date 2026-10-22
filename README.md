# Dreamer-s-On
A community of Dreamers

## Run the website and authentication API

Requires Node.js 22.5 or later.

```sh
npm start
```

Open `http://localhost:3000`. Registration and login accept a valid email address or an Angola phone number with a 9-digit national number (for example, `+244 923 456 789`). Login intentionally uses the same error for an unknown account and a wrong password so the form cannot be used to discover registered accounts. Signed-in members can update their name and login identifier or change their password from the account page; changes require the current password, and a password change signs out other sessions. Accounts are stored in `data/auth.sqlite`; passwords are hashed with Node.js scrypt, and successful authentication uses an HTTP-only session cookie. The database directory is excluded from Git.

Contact form submissions are saved to `contact_messages` in the same SQLite database, and the form confirms receipt after the save succeeds. Password recovery sends a one-time code to the account's registered email or phone, then lets the user choose a new password. Codes expire after 10 minutes, can be tried at most five times, and successful resets invalidate existing sessions.

Course enrollment requires a **3,000 AOA fee for each course**. Members submit a payment reference after paying using the configured bank or Multicaixa instructions. A course is not added to the member's account until an administrator approves the request at `/course-payments.html`. Rejected requests can be resubmitted with a new reference.

Configure course payment review before accepting course payments:

- `COURSE_PAYMENT_INSTRUCTIONS`: the payment destination and instructions shown to members. This is public information; do not put credentials or private banking access details here.
- `COURSE_PAYMENT_ADMIN_USER_ID`: the database user ID of the account allowed to review requests. Create the administrator account first, then set its numeric ID. Do not use an email-only allowlist: account emails are not verified by this application.

For local Node development, set both variables before starting the server. For local Wrangler Pages development, put them in the ignored `.dev.vars` file. In a deployed Pages project, set them as secrets with `wrangler pages secret put <NAME> --project-name dreamers-on`. On Render, add them in the service environment settings. Apply the D1 migration with `npx wrangler d1 migrations apply dreamers-on-db --remote` before deploying. Check the administrator's ID in the local `users` table or with `npx wrangler d1 execute dreamers-on-db --remote --command "SELECT id, identifier FROM users"`.

Configure password recovery before enabling it:

- `PASSWORD_RESET_SECRET`: a private random secret of at least 32 characters (generate one with `openssl rand -hex 32`).
- Email via Resend: `RESEND_API_KEY` and `RESEND_FROM_EMAIL` (the sender must be verified with Resend).
- SMS via Twilio: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_FROM_PHONE` (an SMS-capable E.164 sender).

For local Node development, export these variables before `npm start`. For local Wrangler Pages development, put them in the ignored `.dev.vars` file. For a deployed Pages project, set them as secrets with `wrangler pages secret put <NAME> --project-name dreamers-on`. Never commit real keys. Apply the new D1 schema with `npx wrangler d1 migrations apply dreamers-on-db --remote` before deploying.

Run the API tests with `npm test`.

This project currently uses a same-origin API. GitHub Pages can host the static pages but cannot run this backend; deploy the Node server to an HTTPS-capable host, or configure a same-origin reverse proxy to it. Set `NODE_ENV=production` to enable the cookie's `Secure` attribute.

## Deploy to Render

The `render.yaml` Blueprint configures the Node web service and a persistent disk for the SQLite database. In Render, create a Blueprint from this repository and confirm the paid web-service/disk plan before deploying; SQLite data is stored on the mounted disk. Render sets `PORT` automatically, and the service uses `/health` for health checks.

After the first deploy, add `drevmeron.com` as a custom domain in the Render service settings and apply the DNS records Render provides at the domain registrar. Keep HTTPS enabled so secure session cookies work. Set the password-recovery environment variables in the Render service settings as well; email addresses and phone numbers are not verified at registration, so recovery codes go only to the contact detail currently stored on the account.
