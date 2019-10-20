// See LICENSE folder for this sample’s licensing information.

const ECKey      = require('ec-key');
const bodyParser = require('body-parser');
const crypto     = require('crypto');
const express    = require('express');
const secp256k1  = require('secp256k1');
const uuidv4     = require('uuid/v4');

// The key ID is for the key generated in App Store Connect that is associated with your account.
// For information on how to generate a key ID and key, see:
// "Generate keys for auto-renewable subscriptions" https://help.apple.com/app-store-connect/#/dev689c93225
const keyID = process.env.SUBSCRIPTION_OFFERS_KEY_ID;

// Get the PEM-formatted private key string associated with the Key ID.
const keyString = process.env.SUBSCRIPTION_OFFERS_PRIVATE_KEY;

// Main handler for HTTP requests to the server for generating subscription offer signatures.
const router = express.Router();
router.post('/offer', function(req, res) {

  console.log('POST /offer');
  const appBundleID = req.body.appBundleID;
  const productIdentifier = req.body.productID;
  const subscriptionOfferID = req.body.offerID;
  const applicationUsername = req.body.applicationUsername;
  if (!appBundleID || !productIdentifier || !subscriptionOfferID || !applicationUsername) {
    console.log('Missing argument.');
    res.setHeader('Content-Type', 'application/json');
    res.json({ error: 'BadRequest', code: 400, message: 'Missing data' });
    return;
  }

  // The nonce is a lowercase random UUID string that ensures the payload is unique.
  // The App Store checks the nonce when your app starts a transaction with SKPaymentQueue,
  // to prevent replay attacks.
  const nonce = uuidv4();

  // Get the current time and create a UNIX epoch timestamp in milliseconds.
  // The timestamp ensures the signature was generated recently.
  // The App Store also uses this information help prevent replay attacks.
  const timestamp = new Date().getTime();
  console.log('Request', { appBundleID, productIdentifier, subscriptionOfferID, applicationUsername, });

  // Combine the parameters into the payload string to be signed. These are the same parameters you provide
  // in SKPaymentDiscount.
  const payload = [
    appBundleID, keyID, productIdentifier, subscriptionOfferID,
    applicationUsername, '' + nonce, '' + timestamp
  ].join('\u2063');

  // Create an Elliptic Curve Digital Signature Algorithm (ECDSA) object using the private key.
  const key = new ECKey(keyString, 'pem');

  // Set up the cryptographic format used to sign the key with the SHA-256 hashing algorithm.
  const cryptoSign = key.createSign('SHA256');

  // Add the payload string to sign.
  cryptoSign.update(payload);

  // The Node.js crypto library creates a DER-formatted binary value signature,
  // and then base-64 encodes it to create the string that you will use in StoreKit.
  const signature = cryptoSign.sign('base64');

  // Check that the signature passes verification by using the ec-key library.
  // The verification process is similar to creating the signature, except it uses 'createVerify'
  // instead of 'createSign', and after updating it with the payload, it uses `verify` to pass in
  // the signature and encoding, instead of `sign` to get the signature.
  //
  // This step is not required, but it's useful to check when implementing your signature code.
  // This helps debug issues with signing before sending transactions to Apple.
  // If verification succeeds, the next recommended testing step is attempting a purchase
  // in the Sandbox environment.
  if (process.env.NODE_ENV !== 'production') {
    const verificationResult = key.createVerify('SHA256').update(payload).verify(signature, 'base64');
    console.log("Verification result: " + verificationResult)
  }

  // Send the response.
  res.setHeader('Content-Type', 'application/json');
  res.json({ keyID, nonce, timestamp, signature });

  console.log('Response', { keyID, nonce, timestamp, signature });
});	

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/', router);
module.exports = app;
