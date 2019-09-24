package org.pdelbello.troubleshooting;

import java.util.HashMap;
import java.util.Map;

import org.jboss.security.vault.SecurityVault;
import org.jboss.security.vault.SecurityVaultException;
import org.picketbox.plugins.vault.PicketBoxSecurityVault;

public class Main {
	private static final String ENC_FILE_DIR = "/path/to/enc/dir";
	private static final String KEYSTORE_URL = "/path/to/enc/dir/vault.keystore";
	private static final String ITERATION_COUNT = "50";
	private static final String SALT = "1234abc";
	private static final String KEYSTORE_ALIAS = "vault";
	private static final String KEYSTORE_PASSWORD = "MASK-xxxxx";

	public static String getVaultedString(String s) throws SecurityVaultException {
		// create vault instance
		SecurityVault vault = new PicketBoxSecurityVault();

		// initialize vault
		Map<String, Object> options = new HashMap<String, Object>();
		options.put(PicketBoxSecurityVault.ENC_FILE_DIR, ENC_FILE_DIR);
		options.put(PicketBoxSecurityVault.KEYSTORE_URL, KEYSTORE_URL);
		options.put(PicketBoxSecurityVault.ITERATION_COUNT, ITERATION_COUNT);
		options.put(PicketBoxSecurityVault.SALT, SALT);
		options.put(PicketBoxSecurityVault.KEYSTORE_ALIAS, KEYSTORE_ALIAS);
		options.put(PicketBoxSecurityVault.KEYSTORE_PASSWORD, KEYSTORE_PASSWORD);
		vault.init(options);

		String[] token = s.split("::");
		char[] pass = vault.retrieve(token[1], // vault block
				token[2], // attribute name
				token[3].getBytes() // shared key
		);
		return new String(pass);
	}

	public static void main(String[] args) {
		String value = "";
		try {
			value = getVaultedString("VAULT::block::attribute::1");
		} catch (SecurityVaultException ex) {
			System.err.println(ex.toString());
		}
		System.out.println(value);
	}
}
