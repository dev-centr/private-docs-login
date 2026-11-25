# Agent notes

Private Docs Login is a login provider for private documentation sites. It is an OpenID Connect issuer. The reference host is a Node HTTP server. DevCentr also deploys it as a Cloudflare Worker from `deploy/cloudflare/`; that target stays optional. Code in `src/` must not import a Workers-only module or need `wrangler.toml`. Sign-in state goes through the adapters in `src/store.mjs` (memory for tests, SQLite for Node, D1 for the Worker).

Config is SDL. Secrets are environment names, documented in `docs/modules/private-docs-login/pages/environment-variables.adoc`. Do not commit PEM files, client secrets, or tokens.

GitHub opt-in is an installation of the app named Private Docs Login. GitLab opt-in is membership of the configured user. Do not treat every group a person belongs to as opted in.

Registering a relying party does not switch a live Cloudflare Access identity provider.
