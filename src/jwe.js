const jose = require('node-jose');
const { validateEnv } = require('./util');
const { EncryptionUtils } = require('mastercard-client-encryption');

function jweEncryption(pm) {
  validateEnv(['pathToRawData', 'pathToEncryptedData', 'publicKeyFingerprint', 'encryptionCert'], pm.environment);

  return new Promise((resolve) => {
    const reqBody = JSON.parse(pm.request.body.raw);
    const pathToRawData = pm.environment.get('pathToRawData');
    const pathToEncryptedData = pm.environment.get('pathToEncryptedData');
    const encryptedValueFieldName = pm.environment.get('encryptedValueFieldName') ?? 'encryptedData';
    const publicKeyFingerprint = pm.environment.get('publicKeyFingerprint');
    const encryptionCertificate = pm.environment.get('encryptionCert');

    const encryptionTarget = EncryptionUtils.elemFromPath(pathToRawData, reqBody);
    if (!encryptionTarget || !encryptionTarget.node) {
      return resolve(reqBody);
    }

    const keystore = jose.JWK.createKeyStore();
    return (
      keystore
        .add(encryptionCertificate, 'pem', { kid: publicKeyFingerprint })

        // Encrypt payload and attach to request body
        .then((publicKey) => {
          const buffer = Buffer.from(JSON.stringify(encryptionTarget.node));
          return jose.JWE.createEncrypt(
            {
              format: 'compact',
              contentAlg: 'A256GCM',
              fields: { alg: 'RSA-OAEP-256', kid: publicKeyFingerprint, cty: 'application/json' },
            },
            publicKey,
          )
            .update(buffer)
            .final();
        })
        .then((encrypted) => {
          // mirror what the mastercard encryption lib does
          const encryptedReqBody = EncryptionUtils.addEncryptedDataToBody(
            { [encryptedValueFieldName]: encrypted },
            { element: pathToRawData, obj: pathToEncryptedData },
            encryptedValueFieldName,
            reqBody,
          );
          resolve(encryptedReqBody);
        })
    );
  });
}

module.exports = {
  jweEncryption,
};
