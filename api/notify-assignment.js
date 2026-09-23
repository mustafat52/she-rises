// Called by a Postgres trigger (see the "PUSH NOTIFICATIONS ON CASE
// ASSIGNMENT" section in schema.sql) whenever a case gets assigned to a
// volunteer or a counsellor. Looks up that person's saved device token and
// pushes a notification straight to their phone/browser via Firebase.
//
// Required Vercel environment variables (set in Project Settings > Environment Variables):
//   NOTIFY_WEBHOOK_SECRET       — must match the 'notify_webhook_secret' row in app_config
//   SUPABASE_URL                — same as your site's SUPABASE_URL
//   SUPABASE_SERVICE_ROLE_KEY   — the SERVICE ROLE key (not the anon key!) — Project Settings > API in Supabase
//   FIREBASE_SERVICE_ACCOUNT    — the full service account JSON, as a single-line string
//                                 (Firebase Console > Project Settings > Service Accounts > Generate new private key)

const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)),
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }

  // --- verify the shared secret so randoms on the internet can't spam your volunteers ---
  const secret = req.headers['x-webhook-secret'];
  if (!secret || secret !== process.env.NOTIFY_WEBHOOK_SECRET) {
    res.status(401).send('Unauthorized');
    return;
  }

  const { profile_id, case_ref, role } = req.body || {};
  if (!profile_id) {
    res.status(400).send('Missing profile_id');
    return;
  }

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

  // Best-effort, fire-and-forget: a logging failure should never crash the
  // actual notification attempt, so this isn't awaited or allowed to throw.
  // This is the entire data source behind the Ops Monitor screen — without
  // it, "did the notification fire" required manually reading pg_net's own
  // internal response table, which is what we did by hand before this existed.
  function logOutcome(status, detail){
    supabase.from('notification_log').insert({
      case_ref: case_ref || null,
      profile_id,
      role: role || null,
      status,
      detail: detail || null,
    }).then(({ error }) => {
      if (error) console.error('notification_log insert failed:', error);
    });
  }

  try {
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('fcm_token, full_name')
      .eq('id', profile_id)
      .single();

    if (error || !profile || !profile.fcm_token) {
      // Not an error worth failing loudly on — they just haven't enabled
      // notifications on a device yet.
      logOutcome('skipped', 'no fcm_token on file');
      res.status(200).json({ skipped: true, reason: 'no fcm_token on file' });
      return;
    }

    const name = profile.full_name || 'there';
    const title = role === 'counsellor'
      ? `${name}, a case has been assigned to you`
      : `${name}, you have been assigned a case`;
    const body = case_ref ? `Case ${case_ref} — open She Rises to respond.` : 'Open She Rises to respond.';

    // data-only payload, not `notification` — a `notification` payload gets
    // auto-displayed by the browser AND handled by our own service worker
    // code, showing the same push twice. Data-only means only our own
    // onBackgroundMessage handler ever displays it, exactly once.
    // Deep-link to the right dashboard for whichever role this notification
    // is actually for — this was previously hardcoded to /dashboard-counsellor
    // regardless of role, so a volunteer tapping her notification would get
    // sent to the counsellor dashboard and bounced by its role gate instead
    // of landing on her actual case.
    const dashboardPath = role === 'counsellor' ? 'dashboard-counsellor' : 'dashboard-volunteer';

    try {
      await admin.messaging().send({
        token: profile.fcm_token,
        data: {
          title,
          body,
          url: `https://she-rises-kappa.vercel.app/${dashboardPath}`,
        },
      });
    } catch (sendErr) {
      // A dead token (uninstalled app, cleared site data, token rotated by
      // the browser, etc.) is expected to happen over time — it's not an
      // operational failure worth paging anyone over, and leaving the dead
      // token in place would just make every future assignment to this
      // person fail the same way until she happens to log in again. Firebase
      // Admin SDK reports this as one of these specific error codes; treat
      // only those as "stale", and let anything else fall through to the
      // real-failure path below.
      const code = sendErr && sendErr.code;
      const isStaleToken = code === 'messaging/registration-token-not-registered'
        || code === 'messaging/invalid-registration-token'
        || code === 'messaging/invalid-argument';

      if (isStaleToken) {
        const { error: clearErr } = await supabase
          .from('profiles')
          .update({ fcm_token: null, fcm_token_set_at: null })
          .eq('id', profile_id);
        if (clearErr) console.error('Failed to clear stale fcm_token:', clearErr);

        logOutcome('stale_token_cleared', code || String((sendErr && sendErr.message) || sendErr));
        // 200, not 500 — from the trigger's point of view this attempt is
        // fully handled, not something that needs retrying.
        res.status(200).json({ staleTokenCleared: true });
        return;
      }
      throw sendErr; // genuine failure — handled by the outer catch below
    }

    res.status(200).json({ sent: true });
    logOutcome('sent', null);
  } catch (err) {
    console.error('notify-assignment error:', err);
    logOutcome('error', String((err && err.message) || err));
    res.status(500).json({ error: 'Could not send notification' });
  }
};