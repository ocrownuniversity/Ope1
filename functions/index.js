/**
 * ZMONIE — Cloud Functions (Node 18/20, Firebase Functions v2)
 * Requires the Blaze (pay-as-you-go) plan — needed for outbound
 * network calls to Paystack/Flutterwave and for HTTPS functions.
 *
 * Deploy with:
 *   cd functions && npm install
 *   firebase deploy --only functions
 *
 * Configure secrets first (one-time, from the project root):
 *   firebase functions:secrets:set PAYSTACK_SECRET_KEY
 *   firebase functions:secrets:set FLUTTERWAVE_SECRET_KEY
 *   firebase functions:secrets:set FLUTTERWAVE_WEBHOOK_SECRET
 *
 * These functions purposely do NOT read the secret/public keys that
 * the admin panel writes into Firestore (settings/paystack,
 * adminSettings/flutterwaveSecrets) for the *secret* key — those
 * documents are useful for the admin UI to show status/public key,
 * but the actual verification calls below prefer the Secret Manager
 * value first and fall back to Firestore only if a secret isn't set,
 * so this works whether you configure keys via `firebase functions:
 * secrets:set` (recommended) or by pasting them into the admin panel.
 */

const {onCall, onRequest, HttpsError} = require('firebase-functions/v2/https');
const {defineSecret} = require('firebase-functions/params');
const logger = require('firebase-functions/logger');
const admin = require('firebase-admin');
const crypto = require('crypto');

admin.initializeApp();
const db = admin.firestore();

const PAYSTACK_SECRET_KEY = defineSecret('PAYSTACK_SECRET_KEY');
const FLUTTERWAVE_SECRET_KEY = defineSecret('FLUTTERWAVE_SECRET_KEY');
const FLUTTERWAVE_WEBHOOK_SECRET = defineSecret('FLUTTERWAVE_WEBHOOK_SECRET');

const REGION = 'us-central1';

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/** Fetch is global in Node 18+ runtimes used by Cloud Functions v2. */

async function getPaystackSecretKey() {
  if (PAYSTACK_SECRET_KEY.value()) return PAYSTACK_SECRET_KEY.value();
  const snap = await db.collection('settings').doc('paystack').get();
  const key = snap.exists ? snap.data().secretKey : null;
  if (!key) throw new HttpsError('failed-precondition', 'Paystack secret key is not configured.');
  return key;
}

async function getFlutterwaveSecretKey() {
  if (FLUTTERWAVE_SECRET_KEY.value()) return FLUTTERWAVE_SECRET_KEY.value();
  const snap = await db.collection('adminSettings').doc('flutterwaveSecrets').get();
  const key = snap.exists ? snap.data().secretKey : null;
  if (!key) throw new HttpsError('failed-precondition', 'Flutterwave secret key is not configured.');
  return key;
}

async function getFlutterwaveWebhookSecret() {
  if (FLUTTERWAVE_WEBHOOK_SECRET.value()) return FLUTTERWAVE_WEBHOOK_SECRET.value();
  const snap = await db.collection('adminSettings').doc('flutterwaveSecrets').get();
  return snap.exists ? snap.data().webhookSecret || null : null;
}

async function getPaystackWebhookSecret() {
  const snap = await db.collection('settings').doc('paystack').get();
  return snap.exists ? snap.data().webhookSecret || null : null;
}

/** Credit a user's wallet exactly once for a given provider reference. */
async function creditWalletOnce({uid, amount, provider, reference, description}) {
  const ledgerRef = db.collection('processedPayments').doc(`${provider}_${reference}`);
  const userRef = db.collection('users').doc(uid);

  return db.runTransaction(async (tx) => {
    const ledgerSnap = await tx.get(ledgerRef);
    if (ledgerSnap.exists) {
      // Already credited — return the existing outcome so retries/webhook
      // races are safe (idempotent).
      return {alreadyProcessed: true};
    }
    const userSnap = await tx.get(userRef);
    if (!userSnap.exists) throw new HttpsError('not-found', 'User not found.');
    const userData = userSnap.data();

    tx.set(ledgerRef, {
      uid, amount, provider, reference,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    tx.update(userRef, {
      balance: admin.firestore.FieldValue.increment(amount),
      hasFundedFirst: true,
    });

    const txDocRef = db.collection('transactions').doc();
    tx.set(txDocRef, {
      userId: uid,
      type: 'credit',
      amount,
      description,
      status: 'success',
      [`${provider}Ref`]: reference,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // First-funding referral bonus, matching the existing client logic.
    if (!userData.hasFundedFirst && userData.referredBy) {
      const rewardsSnap = await tx.get(db.collection('settings').doc('rewards'));
      const rCfg = rewardsSnap.exists ? rewardsSnap.data() : {};
      if (rCfg.referralEnabled !== false) {
        const rAmt = rCfg.referralAmt || 100;
        tx.update(db.collection('users').doc(userData.referredBy), {
          balance: admin.firestore.FieldValue.increment(rAmt),
          referralEarned: admin.firestore.FieldValue.increment(rAmt),
        });
      }
    }

    return {alreadyProcessed: false};
  });
}

// ------------------------------------------------------------------
// PAYSTACK
// ------------------------------------------------------------------

/**
 * Callable from the app right after Paystack's inline checkout
 * callback fires. Re-verifies the transaction server-side with
 * Paystack before crediting the wallet — the client can no longer
 * credit itself just by calling the JS callback.
 */
exports.verifyPaystackTransaction = onCall(
  {region: REGION, secrets: [PAYSTACK_SECRET_KEY]},
  async (request) => {
    if (!request.auth) throw new HttpsError('unauthenticated', 'Please sign in.');
    const {reference, expectedAmount} = request.data || {};
    if (!reference) throw new HttpsError('invalid-argument', 'Missing reference.');

    const secretKey = await getPaystackSecretKey();
    const res = await fetch(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
      headers: {Authorization: `Bearer ${secretKey}`},
    });
    const json = await res.json();

    if (!json || !json.status || !json.data || json.data.status !== 'success') {
      logger.warn('Paystack verification failed', {reference, json});
      return {success: false, reason: 'not_successful'};
    }

    const paidAmount = json.data.amount / 100; // kobo -> naira
    if (expectedAmount && Math.abs(paidAmount - Number(expectedAmount)) > 0.5) {
      logger.warn('Paystack amount mismatch', {reference, paidAmount, expectedAmount});
      return {success: false, reason: 'amount_mismatch'};
    }

    const metaUid = json.data.metadata && json.data.metadata.userId;
    const uid = metaUid || request.auth.uid;
    if (uid !== request.auth.uid) {
      throw new HttpsError('permission-denied', 'Transaction does not belong to this user.');
    }

    const result = await creditWalletOnce({
      uid,
      amount: paidAmount,
      provider: 'paystack',
      reference,
      description: `Wallet Funded via Paystack (Ref: ${reference})`,
    });

    return {success: true, alreadyProcessed: !!result.alreadyProcessed};
  },
);

/**
 * Paystack webhook — a safety net so a payment still gets credited
 * even if the user closes the browser before the callback/verify
 * round-trip above completes. Configure this URL in the Paystack
 * Dashboard → Settings → API Keys & Webhooks.
 */
exports.paystackWebhook = onRequest(
  {region: REGION, secrets: [PAYSTACK_SECRET_KEY]},
  async (req, res) => {
    try {
      const secretKey = await getPaystackSecretKey();
      const signature = req.headers['x-paystack-signature'];
      const expectedHash = crypto
        .createHmac('sha512', secretKey)
        .update(req.rawBody)
        .digest('hex');

      if (!signature || signature !== expectedHash) {
        logger.warn('Paystack webhook: invalid signature');
        res.status(401).send('Invalid signature');
        return;
      }

      const event = req.body;
      if (event.event === 'charge.success') {
        const data = event.data;
        const reference = data.reference;
        const amount = data.amount / 100;
        const uid = data.metadata && data.metadata.userId;
        if (uid) {
          await creditWalletOnce({
            uid,
            amount,
            provider: 'paystack',
            reference,
            description: `Wallet Funded via Paystack (Ref: ${reference})`,
          });
        } else {
          logger.warn('Paystack webhook: charge.success with no userId in metadata', {reference});
        }
      }
      res.status(200).send('ok');
    } catch (e) {
      logger.error('paystackWebhook error', e);
      res.status(500).send('error');
    }
  },
);

/**
 * Bank list for the "Other Bank" transfer tab — avoids exposing the
 * secret key to the browser just to fetch Paystack's bank list.
 */
exports.paystackListBanks = onCall(
  {region: REGION, secrets: [PAYSTACK_SECRET_KEY]},
  async (request) => {
    if (!request.auth) throw new HttpsError('unauthenticated', 'Please sign in.');
    const secretKey = await getPaystackSecretKey();
    const res = await fetch('https://api.paystack.co/bank?currency=NGN&perPage=100', {
      headers: {Authorization: `Bearer ${secretKey}`},
    });
    const json = await res.json();
    if (!json || !json.status || !json.data) {
      throw new HttpsError('internal', 'Could not load bank list from Paystack.');
    }
    return {banks: json.data.map((b) => ({code: b.code, name: b.name}))};
  },
);

/** Resolves an account number + bank code to an account name. */
exports.paystackResolveAccount = onCall(
  {region: REGION, secrets: [PAYSTACK_SECRET_KEY]},
  async (request) => {
    if (!request.auth) throw new HttpsError('unauthenticated', 'Please sign in.');
    const {accountNumber, bankCode} = request.data || {};
    if (!accountNumber || !/^\d{10}$/.test(accountNumber)) {
      throw new HttpsError('invalid-argument', 'Account number must be exactly 10 digits.');
    }
    if (!bankCode) throw new HttpsError('invalid-argument', 'Missing bankCode.');

    const secretKey = await getPaystackSecretKey();
    const res = await fetch(
      `https://api.paystack.co/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`,
      {headers: {Authorization: `Bearer ${secretKey}`}},
    );
    const json = await res.json();
    if (json && json.status && json.data && json.data.account_name) {
      return {success: true, accountName: json.data.account_name};
    }
    return {success: false, message: (json && json.message) || 'Could not verify account.'};
  },
);

/**
 * Executes an "Other Bank" transfer end-to-end on the server: debits
 * the wallet inside a Firestore transaction (re-checking balance and
 * the current transfer fee from settings/paystack, never trusting
 * client-supplied numbers), creates the Paystack transfer recipient,
 * initiates the transfer, records the transaction, and refunds the
 * wallet automatically if either Paystack call fails.
 */
exports.paystackInitiateTransfer = onCall(
  {region: REGION, secrets: [PAYSTACK_SECRET_KEY]},
  async (request) => {
    if (!request.auth) throw new HttpsError('unauthenticated', 'Please sign in.');
    const uid = request.auth.uid;
    const {accountNumber, bankCode, bankName, accountName, amount, narration} = request.data || {};

    if (!accountNumber || !/^\d{10}$/.test(accountNumber)) {
      throw new HttpsError('invalid-argument', 'Account number must be exactly 10 digits.');
    }
    if (!bankCode) throw new HttpsError('invalid-argument', 'Missing bankCode.');
    if (!accountName) throw new HttpsError('invalid-argument', 'Account must be resolved/verified first.');
    const amt = Number(amount);
    if (!amt || amt < 100) throw new HttpsError('invalid-argument', 'Minimum transfer is NGN 100.');

    const psSettingsSnap = await db.collection('settings').doc('paystack').get();
    const psSettings = psSettingsSnap.exists ? psSettingsSnap.data() : {};
    if (psSettings.bankTransferEnabled !== true) {
      throw new HttpsError('failed-precondition', 'Bank transfers are currently not available.');
    }
    const fee = Number(psSettings.bankTransferFee !== undefined ? psSettings.bankTransferFee : 50);
    const total = amt + fee;

    const userRef = db.collection('users').doc(uid);
    const txDocRef = db.collection('transactions').doc();
    const txRef = 'OBTR' + Date.now();

    // 1) Debit the wallet atomically, re-checking balance server-side.
    await db.runTransaction(async (tx) => {
      const userSnap = await tx.get(userRef);
      if (!userSnap.exists) throw new HttpsError('not-found', 'User not found.');
      const balance = userSnap.data().balance || 0;
      if (balance < total) {
        throw new HttpsError('failed-precondition', `Insufficient balance. You need NGN ${total.toFixed(2)} (including NGN ${fee.toFixed(2)} fee).`);
      }
      tx.update(userRef, {balance: admin.firestore.FieldValue.increment(-total)});
    });

    const refund = async (reason) => {
      await userRef.update({balance: admin.firestore.FieldValue.increment(total)});
      logger.warn('paystackInitiateTransfer refunded', {uid, reason});
    };

    try {
      const secretKey = await getPaystackSecretKey();

      // 2) Create the transfer recipient.
      const rRes = await fetch('https://api.paystack.co/transferrecipient', {
        method: 'POST',
        headers: {Authorization: `Bearer ${secretKey}`, 'Content-Type': 'application/json'},
        body: JSON.stringify({
          type: 'nuban', name: accountName, account_number: accountNumber,
          bank_code: bankCode, currency: 'NGN',
        }),
      });
      const rData = await rRes.json();
      if (!rData.status) {
        await refund('recipient_creation_failed');
        return {success: false, message: rData.message || 'Transfer setup failed.'};
      }
      const recipientCode = rData.data.recipient_code;

      // 3) Initiate the transfer.
      const tRes = await fetch('https://api.paystack.co/transfer', {
        method: 'POST',
        headers: {Authorization: `Bearer ${secretKey}`, 'Content-Type': 'application/json'},
        body: JSON.stringify({
          source: 'balance', amount: Math.round(amt * 100), recipient: recipientCode,
          reason: narration || 'Bank Transfer', currency: 'NGN',
        }),
      });
      const tData = await tRes.json();
      const txStatus = tData.status ? 'pending' : 'failed';

      if (!tData.status) {
        await refund('transfer_initiation_failed');
        await txDocRef.set({
          userId: uid, type: 'bank_transfer', amount: amt, fee, total,
          description: `Bank Transfer to ${accountName} | ${bankName || ''} | ${accountNumber}`,
          narration: narration || 'Bank Transfer',
          toBankName: bankName || '', toBankCode: bankCode,
          toAccNumber: accountNumber, toAccName: accountName,
          paystackRef: txRef, status: 'failed',
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        return {success: false, message: tData.message || 'Transfer failed.'};
      }

      // 4) Record the (pending) transaction.
      await txDocRef.set({
        userId: uid, type: 'bank_transfer', amount: amt, fee, total,
        description: `Bank Transfer to ${accountName} | ${bankName || ''} | ${accountNumber}`,
        narration: narration || 'Bank Transfer',
        toBankName: bankName || '', toBankCode: bankCode,
        toAccNumber: accountNumber, toAccName: accountName,
        paystackRef: tData.data && tData.data.reference || txRef,
        paystackTransferCode: (tData.data && tData.data.transfer_code) || '',
        status: txStatus,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return {success: true, status: txStatus, reference: (tData.data && tData.data.reference) || txRef};
    } catch (e) {
      await refund('unexpected_error: ' + e.message);
      logger.error('paystackInitiateTransfer error', e);
      return {success: false, message: 'Transfer failed due to a server error. Your wallet has been refunded.'};
    }
  },
);

// ------------------------------------------------------------------
// FLUTTERWAVE
// ------------------------------------------------------------------

exports.verifyFlutterwaveTransaction = onCall(
  {region: REGION, secrets: [FLUTTERWAVE_SECRET_KEY]},
  async (request) => {
    if (!request.auth) throw new HttpsError('unauthenticated', 'Please sign in.');
    const {transaction_id: transactionId, tx_ref: txRef, expectedAmount} = request.data || {};
    if (!transactionId) throw new HttpsError('invalid-argument', 'Missing transaction_id.');

    const secretKey = await getFlutterwaveSecretKey();
    const res = await fetch(`https://api.flutterwave.com/v3/transactions/${transactionId}/verify`, {
      headers: {Authorization: `Bearer ${secretKey}`},
    });
    const json = await res.json();

    if (!json || json.status !== 'success' || !json.data || json.data.status !== 'successful') {
      logger.warn('Flutterwave verification failed', {transactionId, json});
      return {success: false, reason: 'not_successful'};
    }

    if (txRef && json.data.tx_ref !== txRef) {
      return {success: false, reason: 'tx_ref_mismatch'};
    }

    const paidAmount = json.data.amount;
    if (expectedAmount && Math.abs(paidAmount - Number(expectedAmount)) > 0.5) {
      logger.warn('Flutterwave amount mismatch', {transactionId, paidAmount, expectedAmount});
      return {success: false, reason: 'amount_mismatch'};
    }

    const metaUid = json.data.meta && json.data.meta.userId;
    const uid = metaUid || request.auth.uid;
    if (uid !== request.auth.uid) {
      throw new HttpsError('permission-denied', 'Transaction does not belong to this user.');
    }

    const result = await creditWalletOnce({
      uid,
      amount: paidAmount,
      provider: 'flutterwave',
      reference: json.data.tx_ref,
      description: `Wallet Funded via Flutterwave (Ref: ${json.data.tx_ref})`,
    });

    return {success: true, alreadyProcessed: !!result.alreadyProcessed};
  },
);

/** Lets the admin panel's "Test Secret Key" button confirm a key actually works. */
exports.testFlutterwaveSecret = onCall(
  {region: REGION, secrets: [FLUTTERWAVE_SECRET_KEY]},
  async (request) => {
    if (!request.auth) throw new HttpsError('unauthenticated', 'Please sign in.');
    const secretKey = await getFlutterwaveSecretKey();
    const res = await fetch('https://api.flutterwave.com/v3/balances', {
      headers: {Authorization: `Bearer ${secretKey}`},
    });
    const json = await res.json();
    if (res.status === 200 && json.status === 'success') {
      return {valid: true};
    }
    return {valid: false, message: json.message || 'Key rejected by Flutterwave.'};
  },
);

/**
 * Flutterwave webhook — safety net matching paystackWebhook above.
 * Configure this URL + the Secret Hash in the Flutterwave Dashboard
 * → Settings → Webhooks.
 */
exports.flutterwaveWebhook = onRequest(
  {region: REGION, secrets: [FLUTTERWAVE_WEBHOOK_SECRET]},
  async (req, res) => {
    try {
      const expectedSecret = await getFlutterwaveWebhookSecret();
      const signature = req.headers['verif-hash'];
      if (!expectedSecret || !signature || signature !== expectedSecret) {
        logger.warn('Flutterwave webhook: invalid signature');
        res.status(401).send('Invalid signature');
        return;
      }

      const event = req.body;
      if (event.event === 'charge.completed' && event.data && event.data.status === 'successful') {
        const data = event.data;
        const uid = data.meta && data.meta.userId;
        if (uid) {
          await creditWalletOnce({
            uid,
            amount: data.amount,
            provider: 'flutterwave',
            reference: data.tx_ref,
            description: `Wallet Funded via Flutterwave (Ref: ${data.tx_ref})`,
          });
        } else {
          logger.warn('Flutterwave webhook: no userId in meta', {txRef: data.tx_ref});
        }
      }
      res.status(200).send('ok');
    } catch (e) {
      logger.error('flutterwaveWebhook error', e);
      res.status(500).send('error');
    }
  },
);

/**
 * Optional redirect target if you set Flutterwave's `redirect_url`
 * to this endpoint instead of handling everything inline in-app.
 * Just bounces the user back into the app; verification still goes
 * through verifyFlutterwaveTransaction / the webhook above.
 */
exports.flutterwaveCallback = onRequest({region: REGION}, (req, res) => {
  const appUrl = process.env.APP_URL || '/';
  res.redirect(`${appUrl}?fw_status=${encodeURIComponent(req.query.status || 'unknown')}`);
});

// ------------------------------------------------------------------
// ADMIN UTILITIES
// ------------------------------------------------------------------

const SUPER_ADMIN_EMAIL = 'oladejiridwanopeyemi@gmail.com';

exports.adminDeleteUser = onCall({region: REGION}, async (request) => {
  if (!request.auth || (request.auth.token.email || '').toLowerCase() !== SUPER_ADMIN_EMAIL) {
    throw new HttpsError('permission-denied', 'Only the Super Admin can delete users.');
  }
  const {uid} = request.data || {};
  if (!uid) throw new HttpsError('invalid-argument', 'Missing uid.');

  await admin.auth().deleteUser(uid).catch((e) => {
    logger.warn('adminDeleteUser: auth delete failed (continuing to wipe Firestore)', e.message);
  });
  await db.collection('users').doc(uid).delete();

  return {success: true};
});

