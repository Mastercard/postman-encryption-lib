const { jweEncryption } = require('../src/jwe');
const fs = require('fs');
const path = require('path');
const EncryptionUtils = require('mastercard-client-encryption').EncryptionUtils;

describe(`Tests for ${jweEncryption.name}()`, () => {
  // the postman object
  const pm = {};
  const encryptionCert = fs.readFileSync(path.resolve(__dirname, './res/encryption_cert_pubic_key.pem'));
  beforeEach(() => {
    jest.restoreAllMocks();

    const environment = {
      pathToRawData: '$',
      pathToEncryptedData: '$',
      encryptedValueFieldName: 'encryptedData',
      encryptionCert,
      publicKeyFingerprint: 'abcdef',
    };

    pm.environment = new Map(Object.entries(environment));
    pm.request = { method: 'post', body: {} };
  });

  test(`Returns unencrypted object if finding the element to be encrypted fails`, async () => {
    pm.environment.set('pathToRawData', '$');
    pm.environment.set('pathToEncryptedData', '$');

    const requestBody = {
      a: 'b',
      c: 'd',
    };
    pm.request.body.raw = JSON.stringify(requestBody);

    jest.spyOn(EncryptionUtils, 'elemFromPath').mockReturnValue(null);

    const encryptionResult = await jweEncryption(pm);

    expect(encryptionResult).toEqual(requestBody);
  });

  test('Encrypts a request object when the encryption path is the root of the request object', async () => {
    pm.environment.set('pathToRawData', '$');
    pm.environment.set('pathToEncryptedData', '$');

    pm.request.body.raw = JSON.stringify({
      a: 'b',
      c: 'd',
    });

    const expectedBodyFormat = {
      encryptedData: 'the encrypted request body',
    };

    const actualEncryptedBody = await jweEncryption(pm);

    expect(Object.keys(actualEncryptedBody)).toEqual(Object.keys(expectedBodyFormat));
    expect(actualEncryptedBody.encryptedData).not.toBe(undefined);
    expect(actualEncryptedBody.encryptedData).not.toBe(null);
  });

  test('Encrypts a request object when the encryption path is nested in the request object', async () => {
    pm.request.body.raw = JSON.stringify({
      irrelevantProperty: 'this should be preserved',
      path: {
        to: {
          foo: {
            sensitive: 'this is a secret!',
            sensitive2: 'this is a super-secret!',
          },
        },
      },
    });

    pm.environment.set('pathToRawData', 'path.to.foo');
    pm.environment.set('pathToEncryptedData', 'path.to.encryptedFoo');

    const expectedBodyFormat = {
      irrelevantProperty: 'this should be preserved',
      path: {
        to: {
          encryptedFoo: 'the encrypted request body',
        },
      },
    };

    const actualEncryptedBody = await jweEncryption(pm);

    expect(actualEncryptedBody.path.to.encryptedFoo).not.toBe(undefined);
    expect(actualEncryptedBody.path.to.encryptedFoo).not.toBe(null);
    expect(Object.keys(actualEncryptedBody).sort()).toEqual(Object.keys(expectedBodyFormat).sort());
  });
});
