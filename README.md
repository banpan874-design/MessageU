# MessageU — real-time messaging app

MessageU is a responsive, installable web app with real accounts, direct messages, group chats, persistent PostgreSQL storage, and live message delivery through Socket.IO. Its styling uses a dark glassmorphism / neon-gradient visual system.

## Deploy it for people to use (no Termux required)

The easiest route is Render + a managed PostgreSQL database.

1. Create a GitHub repository and upload this project's files.
2. Create a PostgreSQL database on Render (or another PostgreSQL host).
3. Create a Render **Web Service** connected to the repository.
   - Build command: `npm install`
   - Start command: `npm start`
4. Add environment variables in the service settings:
   - `DATABASE_URL`: the database's internal connection URL (use the provider's recommended URL).
   - `JWT_SECRET`: a long random secret, at least 32 characters.
   - `DATABASE_SSL`: `true` if required by the database provider; Render managed PostgreSQL typically uses SSL.
5. Deploy. Visit the HTTPS URL Render gives you, create accounts for two users, and test direct and group messaging.
6. On Android, open the deployed HTTPS site in Chrome and choose **Add to Home screen**. On iPhone, open it in Safari and use **Share → Add to Home Screen**.

The included `render.yaml` documents the deployment settings, but the database still needs to be created and its URL added.

## Features

- Registration and sign-in with hashed passwords
- Unique usernames
- Direct conversations by username
- Group creation with multiple existing usernames
- Real-time messages via Socket.IO
- PostgreSQL persistence
- Responsive mobile / desktop layout
- Installable PWA shell
- Emoji picker, search, profile screen, conversation details
- Glassmorphism styling, neon gradients, custom app icon

## Current limitations

This is a functional starter release, not a full WhatsApp replacement. It does not yet include end-to-end encryption, media upload, voice/video calling, push notifications, typing indicators, read receipts, message editing/deletion, password reset, account verification, moderation/reporting, or robust abuse prevention. The calls/status screens from the initial mockup are not represented as working network features. Add rate limiting, email verification, backups, privacy policy/terms, and security review before a public production launch. The current unread filter is intentionally not wired to read receipts.

## Security notes

- Use HTTPS in deployment.
- Keep `JWT_SECRET` and database credentials private.
- Do not commit `.env`.
- Use a managed PostgreSQL database with backups.
- Consider adding rate limiting and stronger account-recovery safeguards before inviting a large public audience.
