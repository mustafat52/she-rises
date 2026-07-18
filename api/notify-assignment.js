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

  try {
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
    const { data: profile, error } = await supabase
      .from('profiles')
      .select('fcm_token, full_name')
      .eq('id', profile_id)
      .single();

    if (error || !profile || !profile.fcm_token) {
      // Not an error worth failing loudly on — they just haven't enabled
      // notifications on a device yet.
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
    await admin.messaging().send({
      token: profile.fcm_token,
      data: {
        title,
        body,
        url: 'https://she-rises-kappa.vercel.app/dashboard',
      },
    });

    res.status(200).json({ sent: true });
  } catch (err) {
    console.error('notify-assignment error:', err);
    res.status(500).json({ error: 'Could not send notification' });
  }
};