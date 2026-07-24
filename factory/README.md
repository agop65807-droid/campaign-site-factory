# Factory Control Plane — setup guide

This is **Phase 2** of the PRD: the internal tool your team uses to spin up new
tenant campaign sites. It deploys as its own Vercel project, backed by its own
Supabase project — completely separate from every tenant it creates.

## 0. ⚠️ Two things to fix before you deploy, from the credentials shared in chat

1. **The key labeled as a service-role key is actually the `anon` key.**
   Decoding the JWT you shared shows `"role":"anon"`, not `"role":"service_role"`.
   The anon key is subject to Row Level Security and cannot do what this
   backend needs (create sessions, write analytics, manage admins, etc. across
   all rows). Get the real one from **Supabase dashboard → Project Settings →
   API → `service_role` secret** (or, if your project has migrated to the new
   key system, the `secret` key from **API → API Keys**) and use that for both
   `FACTORY_SUPABASE_SERVICE_ROLE_KEY` and `SUPABASE_SERVICE_ROLE_KEY` below.
2. **`SUPABASE_ACCESS_TOKEN` was still the literal placeholder text**
   (`your-supabase-management-api-token`) — not a real value. You only need
   this for the "create a new tenant" feature (it's a Management API token,
   different from the project's own API keys) — get one from **Supabase
   dashboard → Organization → Access Tokens** (starts with `sbp_`). Everything
   else (the dashboard, the existing site) works without it.

Also — since these values were pasted into a chat, treat them as exposed:
rotate the Vercel token (Vercel dashboard → Settings → Tokens → regenerate)
and the Supabase keys once you've finished initial setup, and from then on
paste secrets only directly into Vercel's Environment Variables screen, never
into a chat or a file that gets committed.

## 1. One-time setup

### 1.1 Supabase project — shared mode
The env vars you're using put the factory's own control-plane tables
(`tenants`, `provisioning_jobs`, `super_admins`, …) and the live tenant
site's tables (`campaigns`, `tweets`, `site_settings`, …) in **the same**
Supabase project (`FACTORY_SUPABASE_URL` and `SUPABASE_URL` point at the same
place). That's a valid simplification for now — there's no table name
collision between the two schemas — but it means this one project is no
longer isolated per PRD §6.3 until you actually provision additional tenants
through the wizard (which *does* create a separate project per tenant). Run
**all three** migration files against this one project, in order:
```
tenant-template/migrations/001_base_schema.sql
tenant-template/migrations/002_share_platforms_and_site_settings.sql
factory/migrations/001_factory_schema.sql
```

### 1.2 Deploy — two separate Vercel projects, one shared database
Deploy `tenant-template/` and `factory/` as **two separate Vercel projects**
(that's the existing live campaign site, plus the new dashboard). Paste each
block below into that project's **Vercel dashboard → Settings → Environment
Variables → bulk import** — Vercel accepts a pasted `.env`-style block
directly, so you never need to type secrets into a file:

**On the `factory` project:**
```
FACTORY_SUPABASE_URL=<your Supabase project URL>
FACTORY_SUPABASE_SERVICE_ROLE_KEY=<the REAL service_role key — see §0 above>
FACTORY_ENCRYPTION_KEY=<32-byte key, hex or base64 — you already generated one>
FACTORY_BOOTSTRAP_SECRET=<any long random string, used once>
FACTORY_REQUIRE_2FA=true
VERCEL_TOKEN=<your Vercel personal/team token>
VERCEL_TEAM_ID=<your Vercel team id>
SUPABASE_ACCESS_TOKEN=<a REAL Management API token — see §0 above>
SUPABASE_ORG_ID=<your Supabase organization id>
TENANT_GIT_REPO=your-org/campaign-site-template
TENANT_GIT_REPO_ID=<numeric/string repo id — see note below>
TENANT_BASE_DOMAIN=campaigns.ourdomain.com
```
(`SUPABASE_URL` / `SUPABASE_KEY` also still work as older/alternate names for
the first two, and `FACTORY_MASTER_KEY` for the encryption key, if you'd
rather keep those names instead.)

`TENANT_GIT_REPO_ID` — the numeric/string repo id Vercel's deployments API
wants for `gitSource.repoId`. Find it via `GET /v9/projects/{any-project-
linked-to-that-repo}` or your git provider's API. Only needed for the
"create new tenant" / "update template" features — not for the dashboard
itself to load.

**On the `tenant-template` (existing live site) project:**
```
SUPABASE_URL=<same Supabase project URL as above, in shared mode>
SUPABASE_SERVICE_ROLE_KEY=<the REAL service_role key>
```
(`SUPABASE_KEY` also still works as the original name.)

Also copy `tenant-template/migrations/*.sql` into `factory/tenant-migrations/`
(already done in this build) — `lib/provisioning.js` bundles these into every
new tenant database when you provision one through the wizard. **Keep them in
sync**: any time you change the tenant template's schema, copy the updated
migration file(s) here too.

### 1.3 Create the first super_admin
```bash
curl -X POST https://<factory-domain>/api/factory/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"bootstrapSecret":"<FACTORY_BOOTSTRAP_SECRET>","name":"اسمك","username":"you","password":"<a strong password>"}'
```
Then open the dashboard, log in, and (since `FACTORY_REQUIRE_2FA=true`)
you'll be walked through TOTP (2FA) enrollment automatically — it's
mandatory, per §11 item 3.

### 1.4 Vercel/Supabase master tokens — already handled via env vars
With `VERCEL_TOKEN`, `VERCEL_TEAM_ID`, `SUPABASE_ACCESS_TOKEN`, and
`SUPABASE_ORG_ID` set as env vars (§1.2 above), the API reads those directly
— no extra setup step needed. `/api/factory/vault/bootstrap` (storing these
encrypted in `secrets_vault` instead — §11 item 1) is still there as an
alternative for teams that would rather not put these in plain env vars at
all; env vars take priority if both are present.

## 2. Creating a tenant

Use the dashboard wizard (`/`), or `POST /api/factory/tenants` directly. Either
way this kicks off `lib/provisioning.js`, which runs the 12-step pipeline from
PRD §7b and reports live progress via `GET /api/factory/jobs/:id`.

## 3. Things to verify before your first **real** run

This code was written and syntax-checked without live network access to
Vercel/Supabase, so before pointing it at production:

1. **Re-check the Vercel deployments endpoint version** (`createDeployment` /
   `getDeployment` in `lib/vercelClient.js` use `/v13/deployments` — this is
   the resource Vercel has changed most often historically). Confirm against
   https://vercel.com/docs/rest-api/reference/endpoints/deployments before
   first use.
2. **`gitSource.repoId`** — confirm the exact shape Vercel expects for your
   git provider (GitHub/GitLab/Bitbucket differ slightly).
3. **Supabase key system migration** — Supabase is moving from anon/service_role
   keys to publishable/secret keys. `getApiKeys()` in
   `lib/supabaseManagementClient.js` tries the new endpoint and falls back to
   the legacy shape, but confirm which your organization is on.
4. **Run the whole pipeline once against a throwaway tenant** before creating
   any real one — this is also what the PRD itself instructs (§16).
5. **Serverless timeout**: a full provisioning run can take several minutes
   (two cloud-provider provisioning waits + a build). `vercel.json` sets
   `maxDuration: 300` for the API function, which requires a Vercel plan that
   supports extended function duration. If yours doesn't, switch
   `handleCreateTenant` in `api/[...path].js` to enqueue the job and drive it
   with a Vercel Cron hitting a `/api/factory/jobs/tick` endpoint that
   advances one step per invocation — `lib/provisioning.js` is already
   structured so each step is a discrete, resumable unit for exactly this.

## 4. Security notes specific to this control plane

- This dashboard/API is intentionally **not** CORS-open (unlike the tenant
  sites' public `/api/config`) — same-origin only.
- `factory_activity_logs` should have DB-level grants that only allow INSERT
  and SELECT for the application role — never UPDATE/DELETE — so the audit
  trail can't be tampered with even if application code has a bug.
- `FACTORY_MASTER_KEY` is the single point of failure called out in PRD §14.
  Treat it as a root credential. If it's ever exposed, rotate it and
  re-encrypt every row in `secrets_vault`.
