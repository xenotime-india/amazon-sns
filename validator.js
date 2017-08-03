import url from 'url';
import https from 'https';
import crypto from 'crypto';

const defaultEncoding = 'utf8';
const defaultHostPattern = /^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/;
const certCache = {};
const subscriptionControlKeys = ['SubscribeURL', 'Token'];

const subscriptionControlMessageTypes = [
  'SubscriptionConfirmation',
  'UnsubscribeConfirmation'
];

const requiredKeys = [
  'Message',
  'MessageId',
  'Timestamp',
  'TopicArn',
  'Type',
  'Signature',
  'SigningCertURL',
  'SignatureVersion'
];

const signableKeysForNotification = [
  'Message',
  'MessageId',
  'Subject',
  'SubscribeURL',
  'Timestamp',
  'TopicArn',
  'Type'
];

const signableKeysForSubscription = [
  'Message',
  'MessageId',
  'Subject',
  'SubscribeURL',
  'Timestamp',
  'Token',
  'TopicArn',
  'Type'
];

const lambdaMessageKeys = {
  'SigningCertUrl': 'SigningCertURL',
  'UnsubscribeUrl': 'UnsubscribeURL'
};

const hashHasKeys = (hash, keys) => {
  for (let i = 0; i < keys.length; i++) {
    if (!(keys[i] in hash)) {
      return false;
    }
  }

  return true;
};

const indexOf = (array, value) => {
  for (let i = 0; i < array.length; i++) {
    if (value === array[i]) {
      return i;
    }
  }

  return -1;
};

function convertLambdaMessage(message) {
  for (const key in lambdaMessageKeys) {
    if (key in message) {
      message[lambdaMessageKeys[key]] = message[key];
    }
  }

  if ('Subject' in message && message.Subject === null) {
    delete message.Subject;
  }

  return message;
}

const validateMessageStructure = message => {
  let valid = hashHasKeys(message, requiredKeys);

  if (indexOf(subscriptionControlMessageTypes, message['Type']) > -1) {
    valid = valid && hashHasKeys(message, subscriptionControlKeys);
  }

  return valid;
};

const validateUrl = (urlToValidate, hostPattern) => {
  const parsed = url.parse(urlToValidate);

  return parsed.protocol === 'https:'
    && parsed.path.substr(-4) === '.pem'
    && hostPattern.test(parsed.host);
};

const getCertificate = (certUrl, cb) => {
  console.log(certCache);
  console.log(certUrl);
  if (certCache.hasOwnProperty(certUrl)) {
    cb(null, certCache[certUrl]);
    return;
  }

  https.get(certUrl, res => {
    const chunks = [];

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

const validateSignature = (message, cb, encoding) => {
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

  const verifier = crypto.createVerify('RSA-SHA1');
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
class MessageValidator {
  constructor(hostPattern, encoding) {
    this.hostPattern = hostPattern || defaultHostPattern;
    this.encoding = encoding || defaultEncoding;
  }

  /**
   * A callback to be called by the validator once it has verified a message's
   * signature.
   *
   * @callback validationCallback
   * @param {Error} error - Any error encountered attempting to validate a
   *                          message's signature.
   * @param {Object} message - The validated inbound SNS message.
   */

  /**
   * Validates a message's signature and passes it to the provided callback.
   *
   * @param {Object} hash
   * @param {validationCallback} cb
   */
  validate(hash, cb) {
    const hostPattern = this.hostPattern;
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
}

export default MessageValidator;
