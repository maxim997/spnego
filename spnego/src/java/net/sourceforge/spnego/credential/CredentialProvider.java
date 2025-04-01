package net.sourceforge.spnego.credential;

import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.microsoft.credentialstorage.SecretStore;
import com.microsoft.credentialstorage.model.StoredCredential;

public class CredentialProvider {

    public static final String USER_NAME_KEY = "userName";
    public static final String PASSWORD_KEY = "password";

    private static final SecretStore<StoredCredential> credentialStorage = StorageCredentialFactory
	    .getInstance().createStorage();

    public static Optional<Properties> getProperties(String credential,
	    Logger logger) {

	logger.fine("retrieving credential for " + credential);

	StoredCredential storedCredential = null;
	Properties value = null;
	if (credential != null && !credential.isEmpty()) {
	    try {
		storedCredential = credentialStorage.get(credential);
	    } catch (Exception e) {
		logger.log(Level.SEVERE, "error while retrieving credential",
			e);
	    }
	}

	if (storedCredential != null) {
	    value = new Properties();
	    value.put(USER_NAME_KEY, storedCredential.getUsername());
	    value.put(PASSWORD_KEY,
		    String.valueOf(storedCredential.getPassword()));
	    storedCredential.clear();
	}
	return Optional.ofNullable(value);
    }
}
