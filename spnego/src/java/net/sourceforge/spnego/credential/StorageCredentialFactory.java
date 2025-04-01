package net.sourceforge.spnego.credential;

import java.nio.file.Paths;

import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.model.StoredCredential;
import com.otoil.credentialstorage.keystore.SecretKeyBackedCredentialStore;

interface StorageCredentialFactory
{
    String PROPERTYKEY_LOCATION = "application.secure.keyStore";
    String PROPERTYKEY_SECUREKEY = "application.secure.keyStoreSecureKey";

    static StorageCredentialFactory getInstance()
    {
        return () -> {

            String location = System.getProperty(PROPERTYKEY_LOCATION);
            if (location == null)
            {
                // default location
                location = Paths.get(System.getProperty("java.io.tmpdir"),
                    "credential.keystore").toString();
            }
            if (System.getProperty(PROPERTYKEY_SECUREKEY) == null)
            {
                // delete location and change secure key
                System.setProperty(PROPERTYKEY_SECUREKEY, "changeitnow");
            }

            SecretKeyBackedCredentialStore storage = new SecretKeyBackedCredentialStore(
                location, true);

            return new SecretStore<StoredCredential>()
            {
                @Override
                public boolean add(String key, StoredCredential secret)
                {
                    throw new UnsupportedOperationException();
                }

                @Override
                public boolean delete(String key)
                {
                    throw new UnsupportedOperationException();
                }

                @Override
                public StoredCredential get(String key)
                {
                    return storage.withKeyStorePassword(
                        System.getProperty(PROPERTYKEY_SECUREKEY)).get(key);
                }

                @Override
                public boolean isSecure()
                {
                    return storage.isSecure();
                }
            };

        };
    }

    SecretStore<StoredCredential> createStorage();
}
