# Generating a Subscription Offer Signature Using Node.js

> Generate a signature using your private key and lightweight cryptography libraries.

**Changes in this fork:**

 - cleanup and refactoring
 - fix mistakes in the documentation
 - add documentation about usage with [the cordova in-app purchase plugin](https://github.com/j3k0/nodejs-suboffer-signature-server).

## Overview

- Note: This sample code project is associated with WWDC 2019 session [305:
  Subscription Offers Best Practices](https://developer.apple.com/videos/play/wwdc19/305/).

This sample code is a simple server written using JavaScript and Node.js. It
demonstrates how to generate a signature for subscription offers.  The sample
demonstrates:

* Receiving a request. 
* Generating a cryptographic signature using your private key.
* Sending back a response with the signature.

All of the work is done in `app.js`. You set up environment variables for your
key ID and your private key in the `start-server` file.

## Configure the Sample Code Project

1. Install Node.js version 10
2. Open the Terminal and navigate to the sample code directory.
3. Run `npm install` from the command line, and make sure it completes
   successfully.
4. The `start-server` file contains a key ID and private key PEM string. The
   values provided in the sample are for example purposes only and will not
   generate signatures that are valid for your apps.  You can optionally open
   `start-server` with a text editor and replace the example key ID and private
   key PEM string with your own key ID and private key PEM string that you
   received from App Store Connect. 

## Run a Test on Your Local Server

To test the code on your local machine, from the command line:

* Navigate to the sample code source folder and run `./start-server` from the
  command line. The server is now running locally and is ready to accept
  connections on port 3000.
* Open another terminal window and use the `curl` command to send a request.
  This example command uses the same data listed in the JSON example below: 

```
curl -X POST -H "Content-type: application/json" -d '{"appBundleID": "com.example.yourapp", "productIdentifier": "com.example.yoursubscription", "offerID": "your_offer_id", "applicationUsername": "8E3DC5F16E13537ADB45FB0F980ACDB6B55839870DBCE7E346E1826F5B0296CA"}' http://127.0.0.1:3000/offer
```

You will get a response that includes the signature.

## Send a Request

To run this sample code, send a request to this URL: `POST
http://<yourdomain>/offer`, where `<yourdomain>` is the domain name or IP
address of the server this sample code is running on.

The request must have a `Content-type` header of `application/json`, and JSON
body data with the following format:

```
{
    "appBundleID": "com.example.yourapp",
    "productIdentifier": "com.example.yoursubscription",
    "offerID": "your_offer_id",
    "applicationUsername": "8E3DC5F16E13537ADB45FB0F980ACDB6B55839870DBCE7E346E1826F5B0296CA"
}
```

## Usage with Cordova In-App Purchase plugin

Discount offers are supported by the [cordova in-app purchase
plugin](https://github.com/j3k0/nodejs-suboffer-signature-server). When placing
an order that includes a discount identifier, you can use a method like below:

```js
function orderDiscount(productId, discountId) {
  const product = store.get(productId);
  if (!store.get(store.APPLICATION)) {
    alert('Please use "store.verifyPurchases()" before ordering a discount.');
    return;
  }
  if (!store.getApplicationUsername(product)) {
    alert('Please make sure "store.applicationUsername" is set before ordering a discount.');
    return;
  }
  const request = {
    appBundleID: store.get(store.APPLICATION).id,
    productID: productId,
    offerID: discountId,
    applicationUsername: store.utils.md5(store.getApplicationUsername()),
  };
  store.utils.ajax({
    url: 'http://localhost:3000/offer',
    method: 'POST',
    data: request,
    success: function(data) {
      if (data && data.error) {
        // errorHandler(data);
        return;
      }
      // Example response data: {
      //   "keyID": "XYZ123456A",
      //   "nonce": "ffffffff-50b6-4444-b008-888888888888",
      //   "timestamp": 1568976952688,
      //   "signature": "...Eowdil0Ve+Ta1Mkz+o+soU2YCL..."
      // }         
      const orderData = {
        applicationUsername: store.getApplicationUsername(),
        discount: {
          id: discountId,
          key: data.keyID,
          nonce: data.nonce,
          timestamp: data.timestamp,
          signature: data.signature,
        },
      };
      store.order(productId, orderData);
    },
    error: function(status, message, data) {
      console.log('error: ' + JSON.stringify({status: status, message: message, data: data}));
      // errorHandler(data);
    },
  });
}
```

Notice that discount offers require you to set the `applicationUsername`.
Please refer to the plugin's documentation for more information.

Calling `store.verifyPurchases()` is required if your receipt validation server
doesn't already handle discount eligibility (or to figure out your bundle ID,
but this you can hard-code). Remember that discounts are only available to
users that are active or lapsed subscribers.

Lastly, Apple's own recommendation: you should consider using a discount
eligibility endpoint that creates signatures for eligible discounts before
showing the "Order" button in your application. This way, the discount
signature is available right away on the device when the user decides to place
an order and he/she doesn't have to wait for the server.

