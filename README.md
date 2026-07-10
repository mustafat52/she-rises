# She Rises — Web Platform

A working platform for the She Rises Dawoodi Bohra women's initiative: a
public website, an internal case-management dashboard for volunteers and
counsellors, a gated page for the media manager to publish content, and an
admin panel for approving team members and reviewing usage — all wired to
run on a real Supabase backend.

## What's in this package

| File | What it is |
|---|---|
| `index.html` | Public website — Home, Voices, Find Support, Find a Counsellor, Resources, About |
| `dashboard.html` | Internal tool for volunteers/counsellors — triage inbox, case tagging, assignment, case notes |
| `add-media.html` | Gated page (`/add-media`) for the media manager to add/remove podcasts, reels, articles |
| `admin.html` | Gated page (`/admin`) for designated admins — usage analytics, approving new team members, managing roles and the public counsellor directory |
| `join.html` | Public page (`/join`) where new volunteers/counsellors/media managers request an account |
| `schema.sql` | Full Supabase/Postgres schema — tables, Row Level Security policies, indexes, the self-signup trigger |
| `vercel.json` | Basic Vercel config (clean URLs + security headers) |

Every HTML file is self-contained (styles, scripts, and the logo are
embedded directly) — no build step, no npm install. Data comes from a real
Supabase project via the `@supabase/supabase-js` client, loaded from a CDN
at the top of each file.

## Setup — do this before deploying

**1. Create the Supabase project**
- Go to [supabase.com](https://supabase.com), create a free account and a new project.
- Open the **SQL Editor**, paste in the full contents of `schema.sql`, and run it.
  This creates every table, the enums, and — importantly — the Row Level
  Security policies that keep counsellors from seeing each other's cases.

**2. Get your API credentials**
- In Supabase: **Project Settings → API**.
- Copy the **Project URL** and the **anon public** key (not the service
  role key — that one must never go in client-side code).

**3. Paste them into all five HTML files**
- Each of `index.html`, `dashboard.html`, `add-media.html`, `admin.html`, and
  `join.html` has this near the top of its `<script>` section:
  ```js
  const SUPABASE_URL = 'YOUR_SUPABASE_PROJECT_URL';
  const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';
  ```
  Replace both placeholders in all five files with the real values from step 2.

**4. Create the first admin account**
- Have that person sign up at `/join` like anyone else (this creates their
  account, inactive by default).
- In Supabase **Table Editor → profiles**, find their row and manually set
  `role = admin` and `is_active = true`. This is the one manual bootstrap
  step — every admin after this first one can be promoted from inside
  `/admin` itself.

**5. Everyone else joins themselves**
- Send new volunteers, counsellors, and the media manager to `/join`. They
  create their own account, which starts inactive.
- The admin opens `/admin → Pending Approvals`, and activates each person
  with the right role in one click. For counsellors, there's a follow-up
  "Edit Public Listing" action in `/admin → Manage Team` to fill in what
  shows on the public Find a Counsellor page (credential, location,
  languages, specialties, bio) and toggle whether they're publicly listed
  at all.

**6. Add a few media entries (optional)**
- Sign in to `/add-media` with a `media_manager` or `admin` account and add
  real podcast/reel/article links — or add rows directly in the `media`
  table in Supabase.

Once steps 1–4 are done, every page is fully live — real login, real
shared case data, real Row-Level-Security-enforced access control.

## Deploying to Vercel

**Option A — Vercel dashboard (easiest for a demo):**
1. Go to [vercel.com](https://vercel.com) and log in.
2. **Add New → Project → "Deploy without Git"**, and drag in this whole folder (or a zip of it).
3. Framework preset: **Other** (static HTML, no build command).
4. **Deploy** — you'll get a live `*.vercel.app` URL in under a minute.

**Option B — Vercel CLI:**
```bash
npm install -g vercel
cd sherises-deploy
vercel        # preview deploy
vercel --prod # production deploy
```

**Option C — GitHub + Vercel (best if you'll keep iterating):**
Push this folder to a GitHub repo, then **Add New → Project → Import Git
Repository** in Vercel. Every push to `main` auto-deploys after that.

Once deployed, the dashboard is at `your-project.vercel.app/dashboard`,
the media manager page at `your-project.vercel.app/add-media`, the admin
panel at `your-project.vercel.app/admin`, and the team signup page at
`your-project.vercel.app/join`.

## Still on the roadmap before real cases go through this

1. **The WhatsApp bot is not connected yet.** "Log New Case" in the
   dashboard simulates what the bot will do automatically — it inserts a
   row into the `cases` table exactly like a real webhook would. Wiring
   the actual WhatsApp Business API to call this same insert is the next
   backend step (a Vercel serverless function or Supabase Edge Function
   that receives the webhook and calls `supabase.from('cases').insert(...)`).
2. **The crisis/escalation protocol is still a placeholder.** Severity
   tagging and the `crisis_alerts` table exist, but the real protocol —
   who gets notified instantly for a crisis-tagged case, and how — needs
   sign-off from whoever leads the counselling side before launch.
3. **"Deactivate" in the admin panel doesn't delete anyone's login.** It
   flips `is_active` to false, which blocks them from every internal tool
   immediately — but their Supabase Auth account still technically exists.
   To fully delete someone's account (e.g. they're leaving for good), an
   admin needs to remove them in Supabase's **Authentication → Users**
   directly; this can't be done safely from client-side code.
4. **`/join` is technically public** — anyone with the link can create an
   account. That's fine as designed, since a new signup is inactive and
   useless until an admin approves it in `/admin`, but it's worth not
   posting that link somewhere fully public (e.g. the open Instagram bio).
5. **Row Level Security is only as good as the schema it's checked against.**
   Before going live with real sensitive data, it's worth having someone
   technical review the policies in `schema.sql` against Supabase's docs.

## Design language

The visual identity draws on Fatimid architecture (the Dawoodi Bohra
community's historical lineage) — the four-centred "keel" arch shape used
throughout, a muqarnas-inspired stepped frieze as a section divider, and a
faint geometric jaali lattice texture in hero sections — paired with a deep
rose and gold palette pulled from the official She Rises logo.
