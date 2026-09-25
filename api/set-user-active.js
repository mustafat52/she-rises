// Deactivates or reactivates a team member's account.
//
// Why this has to be a server-side endpoint, not a plain Supabase client
// call from the browser: the old "Deactivate" only ever flipped
// profiles.is_active to false. That never touched Supabase's own
// auth.users — her email/password kept working, and any session she
// already held stayed fully valid against RLS (current_role_name() only
// checked role, never is_active — see schema.sql for the accompanying fix
// to that function). Actually blocking sign-in means calling Supabase's
// Auth Admin API (auth.admin.updateUserById with ban_duration), which
// requires the service-role key — a credential that must never be shipped
// to browser code, for exactly the same reason api/delete-user.js and
// api/notify-assignment.js already keep it server-side only.
//
// Unlike delete, this is reversible: reactivating clears the ban
// (ban_duration: 'none') and flips is_active back to true, restoring
// exactly the role/permissions she had before — nothing about her
// account, case history, or role is ever touched or lost.
//
// Authorization here follows the same pattern as delete-user.js: verifies
// the caller's own Supabase session token and checks their live role in
// the database, rather than trusting a role claim from the client.

const { createClient } = require('@supabase/supabase-js');

// ~100 years — Supabase's own documented convention for "indefinitely
// banned until explicitly unbanned" (there's no true "forever" value).
const INDEFINITE_BAN_DURATION = '876000h';

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

  const { profile_id, active } = req.body || {};
  if (!profile_id || typeof active !== 'boolean') {
    res.status(400).json({ error: 'Missing profile_id or active' });
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
  // the client.
  const { data: callerProfile, error: profErr } = await supabaseAdmin
    .from('profiles').select('role').eq('id', callerData.user.id).single();
  if (profErr || !callerProfile || callerProfile.role !== 'admin') {
    res.status(403).json({ error: 'Admin access required' });
    return;
  }

  // Don't allow an admin to deactivate their own account through this
  // button — a mistaken click here would be an unrecoverable-without-
  // another-admin, self-inflicted lockout (reactivating also requires
  // being signed in as an admin).
  if (!active && profile_id === callerData.user.id) {
    res.status(400).json({ error: "You can't deactivate your own account this way." });
    return;
  }

  const { error: banErr } = await supabaseAdmin.auth.admin.updateUserById(profile_id, {
    ban_duration: active ? 'none' : INDEFINITE_BAN_DURATION,
  });
  if (banErr) {
    res.status(500).json({ error: banErr.message || 'Could not update this account\'s sign-in access' });
    return;
  }

  const profileUpdate = active
    ? { is_active: true, deactivated_at: null }
    : { is_active: false, deactivated_at: new Date().toISOString() };

  const { error: updErr } = await supabaseAdmin.from('profiles').update(profileUpdate).eq('id', profile_id);
  if (updErr) {
    // The ban/unban already went through at this point — the account's
    // actual sign-in access is correct either way, this only means the
    // profiles row (and therefore what the dashboard displays) is now out
    // of sync with it. Surfacing this distinctly matters: silently
    // swallowing it would leave someone looking "still active" in Manage
    // Team while actually being unable to sign in, or vice versa.
    res.status(500).json({ error: 'Sign-in access was updated, but saving that to the profile failed: ' + (updErr.message || 'unknown error') });
    return;
  }

  res.status(200).json({ ok: true, active });
};