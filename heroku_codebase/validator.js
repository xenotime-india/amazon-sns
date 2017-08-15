import url from 'url';
import https from 'https';
import crypto from 'crypto';


var defaultEncoding = 'utf8';
var defaultHostPattern = /^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/;
var certCache = {};
var subscriptionControlKeys = ['SubscribeURL', 'Token'];

var subscriptionControlMessageTypes = [
  'SubscriptionConfirmation',
  'UnsubscribeConfirmation'
];

var requiredKeys = [
  'Message',
  'MessageId',
  'Timestamp',
  'TopicArn',
  'Type',
  'Signature',
  'SigningCertURL',
  'SignatureVersion'
];

var signableKeysForNotification = [
  'Message',
  'MessageId',
  'Subject',
  'SubscribeURL',
  'Timestamp',
  'TopicArn',
  'Type'
];

var signableKeysForSubscription = [
  'Message',
  'MessageId',
  'Subject',
  'SubscribeURL',
  'Timestamp',
  'Token',
  'TopicArn',
  'Type'
];

var lambdaMessageKeys = {
  'SigningCertUrl': 'SigningCertURL',
  'UnsubscribeUrl': 'UnsubscribeURL'
};

var hashHasKeys = (hash, keys) => {
  for (let i = 0; i < keys.length; i++) {
    if (!(keys[i] in hash)) {
      return false;
    }
  }

  return true;
};

var indexOf = (array, value) => {
  for (let i = 0; i < array.length; i++) {
    if (value === array[i]) {
      return i;
    }
  }

  return -1;
};

function convertLambdaMessage(message) {
  for (var key in lambdaMessageKeys) {
    if (key in message) {
      message[lambdaMessageKeys[key]] = message[key];
    }
  }

  if ('Subject' in message && message.Subject === null) {
    delete message.Subject;
  }

  return message;
}

var validateMessageStructure = message => {
  let valid = hashHasKeys(message, requiredKeys);

  if (indexOf(subscriptionControlMessageTypes, message['Type']) > -1) {
    valid = valid && hashHasKeys(message, subscriptionControlKeys);
  }

  return valid;
};

var validateUrl = (urlToValidate, hostPattern) => {
  var parsed = url.parse(urlToValidate);

  return parsed.protocol === 'https:'
    && parsed.path.substr(-4) === '.pem'
    && hostPattern.test(parsed.host);
};

var getCertificate = (certUrl, cb) => {
  console.log(certCache);
  console.log(certUrl);
  if (certCache.hasOwnProperty(certUrl)) {
    cb(null, certCache[certUrl]);
    return;
  }

  https.get(certUrl, res => {
    var chunks = [];

    if(res.statusCode !== 200){
      return cb(new Error('Certificate could not be retrieved'));
    }
    res
      .on('data', data => {
        console.log(data);
        chunks.push(data.toString());
      })
      .on('end', () => {
        certCache[certUrl] = chunks.join('');
        cb(null, certCache[certUrl]);
      });
  }).on('error', cb)
};

var validateSignature = (message, cb, encoding) => {
  if (message['SignatureVersion'] !== '1') {
    cb(new Error(`The signature version ${message['SignatureVersion']} is not supported.`));
    return;
  }

  let signableKeys = [];
  if (message.Type === 'SubscriptionConfirmation') {
    signableKeys = signableKeysForSubscription.slice(0);
  } else {
    signableKeys = signableKeysForNotification.slice(0);
  }

  var verifier = crypto.createVerify('RSA-SHA1');
  for (let i = 0; i < signableKeys.length; i++) {
    if (signableKeys[i] in message) {
      verifier.update(`${signableKeys[i]}\n${message[signableKeys[i]]}\n`, encoding);
    }
  }

  getCertificate(message['SigningCertURL'], (err, certificate) => {
    console.log(certificate);
    console.log(message['Signature']);
    if (err) {
      cb(err);
      return;
    }
    try {
      //console.log(verifier.verify(certificate, message['Signature'], 'base64'));
      if (verifier.verify(certificate, message['Signature'], 'base64')) {
        console.log('OK');
        cb(null, message);
      } else {
        cb(new Error('The message signature is invalid.'));
      }
    } catch (e) {
      cb(e);
    }
  });
};

/**
 * A validator for inbound HTTP(S) SNS messages.
 *
 * @constructor
 * @param {RegExp} [hostPattern=/^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/] - A pattern used to validate that a message's certificate originates from a trusted domain.
 * @param {String} [encoding='utf8'] - The encoding of the messages being signed.
 */
function validate(hash, cb) {
  var hostPattern = defaultHostPattern;
  var encoding = defaultEncoding;

  var hostPattern = this.hostPattern;
  hash = convertLambdaMessage(hash);

  if (!validateMessageStructure(hash)) {
    cb(new Error('Message missing required keys.'));
    return;
  }

  if (!validateUrl(hash['SigningCertURL'], hostPattern)) {
    cb(new Error('The certificate is located on an invalid domain.'));
    return;
  }

  validateSignature(hash, cb, this.encoding);

}