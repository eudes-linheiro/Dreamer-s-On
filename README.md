# Dreamer-s-On
A community of Dreamers

## Run the website and authentication API

Requires Node.js 22.5 or later.

```sh
npm start
```

Open `http://localhost:3000`. Registration and login accept a valid email address or an Angola phone number with a 9-digit national number (for example, `+244 923 456 789`). Login intentionally uses the same error for an unknown account and a wrong password so the form cannot be used to discover registered accounts. Signed-in members can update their name and login identifier or change their password from the account page; changes require the current password, and a password change signs out other sessions. Accounts are stored in `data/auth.sqlite`; passwords are hashed with Node.js scrypt, and successful authentication uses an HTTP-only session cookie. The database directory is excluded from Git.

Contact form submissions are saved to `contact_messages` in the same SQLite database, and the form confirms receipt after the save succeeds. Messages are not emailed automatically; configure an email delivery provider before promising email replies. The forgotten-password page links to contact support until a password-reset email provider is configured.

Run the API tests with `npm test`.

This project currently uses a same-origin API. GitHub Pages can host the static pages but cannot run this backend; deploy the Node server to an HTTPS-capable host, or configure a same-origin reverse proxy to it. Set `NODE_ENV=production` to enable the cookie's `Secure` attribute.

## Deploy to Render

The `render.yaml` Blueprint configures the Node web service and a persistent disk for the SQLite database. In Render, create a Blueprint from this repository and confirm the paid web-service/disk plan before deploying; SQLite data is stored on the mounted disk. Render sets `PORT` automatically, and the service uses `/health` for health checks.

After the first deploy, add `drevmeron.com` as a custom domain in the Render service settings and apply the DNS records Render provides at the domain registrar. Keep HTTPS enabled so secure session cookies work. Email addresses and phone numbers are not verified by this application, so add an email/SMS verification service before relying on them for account recovery or identity checks.
