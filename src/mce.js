const mce = require('mastercard-client-encryption');
const { validateEnv } = require('./util');

function mastercardEncryption(pm) {
  validateEnv(
    [
      'pathToRawData',
      'pathToEncryptedData',
      'ivFieldName',
      'dataEncoding',
      'encryptionCert',
      'publicKeyFingerprint',
      'resourcePath',
    ],
    pm.environment,
  );
  const encryptionPathIn = pm.environment.get('pathToRawData');
  const encryptionPathOut = pm.environment.get('pathToEncryptedData');
  const encryptedValueFieldName = pm.environment.get('encryptedValueFieldName') ?? 'encryptedData';
  const ivFieldName = pm.environment.get('ivFieldName');
  const dataEncoding = pm.environment.get('dataEncoding');
  const encryptionCertificate = pm.environment.get('encryptionCert');
  const publicKeyFingerprint = pm.environment.get('publicKeyFingerprint');
  const resourcePath = pm.environment.get('resourcePath');
  const requestBody = JSON.parse(pm.request.body.raw);

  const config = {
    paths: [
      {
        path: '/',
        toEncrypt: [
          {
            /* path to element to be encrypted in request json body */
            element: encryptionPathIn,
            /* path to object where to store encryption fields in request json body */
            obj: encryptionPathOut,
          },
        ],
        toDecrypt: [
          {
            /* path to element where to store decrypted fields in response object */
            element: '$',
            /* path to object with encryption fields */
            obj: '$',
          },
        ],
      },
    ],
    ivFieldName,
    encryptedKeyFieldName: 'encryptedKey',
    encryptedValueFieldName,
    dataEncoding,
    encryptionCertificate,
    oaepPaddingDigestAlgorithm: 'SHA-256',
    oaepHashingAlgorithmFieldName: 'oaepHashingAlgorithm',
    useCertificateContent: true,
    publicKeyFingerprintFieldName: 'publicKeyFingerprint',
    publicKeyFingerprint,
  };
  const fle = new mce.FieldLevelEncryption(config);
  const encryptedRequestPayload = fle.encrypt(resourcePath, null, requestBody);

  return encryptedRequestPayload.body;
}

module.exports = {
  mastercardEncryption,
};
