// Creates a team member's login directly, on an admin's behalf.
//
// Every other way onto this platform (/join, /apply-counsellor) is
// self-signup, reviewed and activated afterward. This is the one path
// where the account is created outright by someone already trusted —
// for onboarding people the org already knows, rather than waiting for
// them to find a public form.
//
// Why this has to be a server-side endpoint, not a plain Supabase client
// call from the browser: actually creating a login (not just a profiles
// row) means inserting into Supabase's own auth.users table, via the
// admin API (supabase.auth.admin.createUser). That API requires the
// project's service-role key — a credential that must never be shipped
// to browser code, for exactly the same reason api/delete-user.js and
// api/notify-assignment.js already keep it server-side only.
//
// Authorization mirrors api/delete-user.js exactly: this verifies the
// caller's own Supabase session token and checks their live role in the
// database, so the check can't be spoofed by tampering with client-side
// JS — not a shared secret, since this is a specific person clicking a
// button, not a database trigger calling itself.
//
// handle_new_user() (see schema.sql) fires on every auth.users insert,
// including this one, and creates a baseline profiles row itself
// (role='volunteer', is_active=false) — that's the existing self-signup
// default. This function's job after createUser succeeds is to update
// that row into what was actually asked for: the real role, active
// immediately (an admin creating the account IS the vetting step), and
// must_change_password=true so the handed-over password only works once.

const { createClient } = require('@supabase/supabase-js');

// Kept in one place so a future role addition doesn't also require
// remembering to update this list separately from the dropdown in
// dashboard-admin.html.
const VALID_ROLES = ['volunteer', 'super_volunteer', 'counsellor', 'media_manager', 'admin'];

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!token) {
    res.status(401).send('Unauthorized');
    return;
  }

  const { full_name, email, password, role } = req.body || {};
  if (!full_name || !email || !password || !role) {
    res.status(400).json({ error: 'Missing full_name, email, password, or role' });
    return;
  }
  if (!VALID_ROLES.includes(role)) {
    res.status(400).json({ error: 'Not a recognized role' });
    return;
  }
  if (password.length < 6) {
    res.status(400).json({ error: 'Password must be at least 6 characters' });
    return;
  }

  const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

  // Verify the token actually belongs to a real, current session.
  const { data: callerData, error: callerErr } = await supabaseAdmin.auth.getUser(token);
  if (callerErr || !callerData || !callerData.user) {
    res.status(401).send('Unauthorized');
    return;
  }

  // Verify that session belongs to someone who is actually an admin, right
  // now — not just trusting a role claim baked into the token or sent by
  // the client. Deliberately no further restriction on which role the new
  // account gets (including admin) — any admin creating an account here is
  // treated as a deliberate, informed choice, the same trust already placed
  // in the "Promote to Admin" button elsewhere in the dashboard.
  const { data: callerProfile, error: profErr } = await supabaseAdmin
    .from('profiles').select('role').eq('id', callerData.user.id).single();
  if (profErr || !callerProfile || callerProfile.role !== 'admin') {
    res.status(403).json({ error: 'Admin access required' });
    return;
  }

  const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true, // she needs to log in with this password right away — no confirmation email exists to click
    user_metadata: { full_name },
  });
  if (createErr) {
    // Supabase's own message for this ("User already registered") is
    // already clear enough to act on directly (pick a different email),
    // so it's passed through rather than rewritten.
    res.status(409).json({ error: createErr.message || 'Could not create this account' });
    return;
  }

  const { error: updateErr } = await supabaseAdmin
    .from('profiles')
    .update({
      full_name,
      role,
      is_active: true,
      must_change_password: true,
      created_by: callerData.user.id,
    })
    .eq('id', created.user.id);

  if (updateErr) {
    // The auth account now exists but the profile wasn't finished — flag
    // this clearly rather than reporting a clean success, since a stray
    // 'volunteer'/inactive row would otherwise sit there unexplained.
    res.status(500).json({ error: 'Account was created but could not be fully set up: ' + updateErr.message });
    return;
  }

  res.status(200).json({ created: true });
};