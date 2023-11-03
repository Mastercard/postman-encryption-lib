const { jweEncryption } = require('../src/jwe');
const fs = require('fs');
const path = require('path');

describe(`Tests for ${jweEncryption.name}()`, () => {
  // the postman object
  const pm = {};
  const encryptionCert = fs.readFileSync(path.resolve(__dirname, './res/encryption_cert_pubic_key.pem'));
  beforeEach(() => {
    const environment = {
      pathToRawData: '$',
      pathToEncryptedData: '$',
      encryptedProperty: 'encryptedData',
      encryptionCert,
      publicKeyFingerprint: 'abcdef',
    };

    pm.environment = new Map(Object.entries(environment));
    pm.request = { method: 'post', body: {} };
  });

  test('Encrypts a request object when the encryption path is the root of the request object', async () => {
    pm.environment.set('pathToRawData', '$');
    pm.environment.set('pathToEncryptedData', '$');

    pm.request.body.raw = JSON.stringify({
      a: 'b',
      c: 'd',
    });

    const mockUpdateFn = jest.fn();
    pm.request.body.update = mockUpdateFn;

    const expectedBodyFormat = {
      encryptedData: 'the encrypted request body',
    };

    const actualEncryptedBody = await jweEncryption(pm);

    expect(Object.keys(actualEncryptedBody)).toEqual(Object.keys(expectedBodyFormat));
  });

  test('Encrypts a request object when the encryption path is nested in the request object', async () => {
    pm.request.body.raw = JSON.stringify({
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

    const mockUpdateFn = jest.fn();
    pm.request.body.update = mockUpdateFn;

    const expectedBodyFormat = {
      encryptedData: 'the encrypted request body',
    };

    const actualEncryptedBody = await jweEncryption(pm);

    expect(actualEncryptedBody.path.to.encryptedFoo).not.toBe(undefined);
    expect(actualEncryptedBody.path.to.encryptedFoo).not.toBe(null);
    expect(Object.keys(actualEncryptedBody.path.to.encryptedFoo).sort()).toEqual(
      Object.keys(expectedBodyFormat).sort(),
    );
  });
});
