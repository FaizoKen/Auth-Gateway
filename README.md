# Auth Gateway

Centralized Discord OAuth gateway for all [RoleLogic](https://rolelogic.faizo.net) plugins. Handles Discord login, session management, and guild membership refresh for every plugin hosted on `your-domain.com`.

## How it works

1. User clicks "Login with Discord" on any plugin
2. Plugin redirects to `/auth/login?return_to=/{plugin-name}/verify`
3. Auth Gateway handles Discord OAuth (single redirect URI for all plugins)
4. Sets a shared `rl_session` cookie on the domain (`path=/`)
5. Redirects back to the plugin's `return_to` path
6. Plugin reads the `rl_session` cookie — user is authenticated

This eliminates the need to register a separate Discord OAuth redirect URI per plugin. One redirect URI (`/auth/callback`) serves all plugins.

### Guild refresh

The Auth Gateway runs a single `guild_refresh_worker` that periodically refreshes Discord guild memberships for all users. This replaces the duplicate guild refresh workers that previously ran inside each plugin.

## Setup

```bash
cp .env.example .env
# Edit .env with your values
```

### Environment Variables

| Variable                | Required | Default        | Description                                    |
| ----------------------- | -------- | -------------- | ---------------------------------------------- |
| `DATABASE_URL`          | Yes      | --             | PostgreSQL connection string                   |
| `DISCORD_CLIENT_ID`     | Yes      | --             | Discord OAuth app ID (shared across all plugins) |
| `DISCORD_CLIENT_SECRET` | Yes      | --             | Discord OAuth app secret                       |
| `SESSION_SECRET`        | Yes      | --             | HMAC key for `rl_session` cookie (must match all plugins) |
| `BASE_URL`              | Yes      | --             | Domain root: `https://your-domain.com` |
| `LISTEN_ADDR`           | No       | `0.0.0.0:8090` | Server bind address                            |

## Run

### Docker (recommended)

```bash
docker compose up -d
```

### From source

```bash
cargo run              # development
cargo build --release  # production
```

## Endpoints

All routes are nested under `/auth`:

| Method | Path             | Description                         |
| ------ | ---------------- | ----------------------------------- |
| `GET`  | `/auth/login`    | Start Discord OAuth (accepts `?return_to=` path) |
| `GET`  | `/auth/callback` | Discord OAuth callback              |
| `POST` | `/auth/logout`   | Clear session cookie                |
| `GET`  | `/auth/health`   | Health check (DB + Discord API)     |

## Cloudflare Tunnel

Add this ingress rule:

```
hostname: your-domain.com
path: ^/auth
service: http://localhost:8090
```

## Adding a new plugin

No changes needed in the Auth Gateway when adding a new plugin. The gateway accepts any `return_to` path that starts with `/`. Just make sure the new plugin:

1. Sets `SESSION_SECRET` to the same value as the gateway
2. Reads the `rl_session` cookie via `services/session.rs`
3. Redirects its login handler to `/auth/login?return_to=/{plugin-name}/verify`

## API Reference

- [RoleLogic Role Link API](https://docs-rolelogic.faizo.net/reference/role-link-api)
- [Discord OAuth2](https://discord.com/developers/docs/topics/oauth2)

## License

[MIT](LICENSE)
