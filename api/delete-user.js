// Permanently deletes a team member's account.
//
// Why this has to be a server-side endpoint, not a plain Supabase client
// call from the browser: actually removing someone's ability to log in
// forever (not just flipping is_active to false) means deleting their row
// in Supabase's own auth.users table, via the admin API
// (supabase.auth.admin.deleteUser). That API requires the project's
// service-role key — a credential that must never be shipped to browser
// code, for exactly the same reason api/notify-assignment.js already keeps
// it server-side only. profiles.id references auth.users(id) on delete
// cascade (see schema.sql), so deleting the auth user also removes their
// profiles row in the same call — no separate profile delete needed.
//
// Authorization here is NOT a shared secret like notify-assignment.js uses
// (that pattern fits a database trigger calling itself, not a specific
// person clicking a button) — instead this verifies the caller's own
// Supabase session token and checks their live role in the database,
// so the check can't be spoofed by tampering with client-side JS.

const { createClient } = require('@supabase/supabase-js');

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

  const { profile_id } = req.body || {};
  if (!profile_id) {
    res.status(400).json({ error: 'Missing profile_id' });
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

  // Don't allow an admin to delete their own account through this button —
  // a mistaken click here would be an unrecoverable, self-inflicted lockout.
  if (profile_id === callerData.user.id) {
    res.status(400).json({ error: "You can't delete your own account this way." });
    return;
  }

  const { error: delErr } = await supabaseAdmin.auth.admin.deleteUser(profile_id);
  if (delErr) {
    // cases.assigned_to / assigned_counsellor / created_by / closed_by all
    // reference profiles(id) with no ON DELETE clause specified in
    // schema.sql — meaning Postgres's default (RESTRICT) blocks deleting
    // anyone who has ever been attached to a case, rather than silently
    // rewriting historical case-attribution data. That's the right
    // behavior, but the raw error is a confusing wall of Postgres text for
    // an admin clicking a button — this turns it into a plain-language
    // explanation with the actual next step, when the message matches that
    // known pattern; otherwise the underlying message is passed through.
    const raw = delErr.message || '';
    const isForeignKeyBlock = /foreign key|violat|constraint/i.test(raw);
    const message = isForeignKeyBlock
      ? 'This account has case history tied to it (assigned cases, notes, etc.) and cannot be permanently deleted. Use Deactivate instead — it removes their access while keeping the case record intact.'
      : (raw || 'Could not delete this account');
    res.status(409).json({ error: message });
    return;
  }

  res.status(200).json({ deleted: true });
};