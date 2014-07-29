/**
 * This file is part of Everit - Password Encryptor PBKDF2.
 *
 * Everit - Password Encryptor PBKDF2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - Password Encryptor PBKDF2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - Password Encryptor PBKDF2.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.password.encryptor.pbkdf2.internal;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.credential.encryptor.CredentialEncryptor;
import org.everit.osgi.credential.encryptor.CredentialMatcher;
import org.everit.osgi.password.encryptor.pbkdf2.PBKDF2PasswordEncryptorConstants;
import org.osgi.service.log.LogService;

@Component(name = PBKDF2PasswordEncryptorConstants.SERVICE_FACTORYPID_CREDENTIAL_ENCRYPTOR, metatype = true,
        configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = PBKDF2PasswordEncryptorConstants.PROP_LOG_SERVICE_TARGET)
})
@Service
public class PBKDF2PasswordEncryptorComponent implements CredentialEncryptor, CredentialMatcher {

    /**
     * Start separator character for the encrypted parts of the credential.
     */
    private static final String SEPARATOR_START = "{";

    /**
     * End separator character for the encrypted parts of the credential.
     */
    private static final String SEPARATOR_END = "}";

    /**
     * The algorithm used to generate random salt.
     */
    private static final String SALT_ALGORITHM = "SHA1PRNG";

    /**
     * PBKDF2 with SHA-1 as the hashing algorithm. Note that the NIST specifically names SHA-1 as an acceptable hashing
     * algorithm for PBKDF2
     */
    private static final String SECURE_ALGORITHM = "PBKDF2WithHmacSHA1";

    /**
     * SHA-1 generates 160 bit hashes, so that's what makes sense here.
     * */
    private static final int DERIVED_KEY_LENGTH = 160;

    /**
     * Pick an iteration count that works for you. The NIST recommends at least 1,000 iterations:
     * http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf iOS 4.x reportedly uses 10,000:
     * http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/
     */
    private static final int ITERATIONS = 20000;

    /**
     * The {@link LogService}.
     */
    @Reference(bind = "setLogService")
    private LogService logService;

    @Override
    public String encrypt(final String plainPassword) {
        Objects.requireNonNull(plainPassword, "plainPassword cannot be null");
        try {
            byte[] salt = generateSalt();
            return encryptSecure(salt, plainPassword);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to encrypt password", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to encrypt password", e);
        }
    }

    private String encryptSecure(final byte[] salt, final String plainPassword)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(plainPassword.toCharArray(), salt, ITERATIONS, DERIVED_KEY_LENGTH);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(SECURE_ALGORITHM);
        byte[] passwordDigest = secretKeyFactory.generateSecret(spec).getEncoded();
        byte[] passwordDigestBase64 = Base64.encodeBase64(passwordDigest);
        String passwordDigestBase64StringUTF8 = StringUtils.newStringUtf8(passwordDigestBase64);
        byte[] saltBase64 = Base64.encodeBase64(salt);
        String saltBase64StringUTF8 = StringUtils.newStringUtf8(saltBase64);
        return SEPARATOR_START + SECURE_ALGORITHM + SEPARATOR_END
                + SEPARATOR_START + saltBase64StringUTF8 + SEPARATOR_END
                + passwordDigestBase64StringUTF8;
    }

    private byte[] generateSalt() throws NoSuchAlgorithmException {
        // VERY important to use SecureRandom instead of just Random
        SecureRandom random;
        random = SecureRandom.getInstance(SALT_ALGORITHM);
        // Generate a 8 byte (64 bit) salt as recommended by RSA PKCS5
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }

    private String getAlgorithmFromEncryptedCredential(final String encryptedPassword) {
        int beginIndex = encryptedPassword.indexOf(SEPARATOR_START);
        int endIndex = encryptedPassword.indexOf(SEPARATOR_END);
        return encryptedPassword.substring(beginIndex + 1, endIndex);
    }

    private String getSaltFromEncryptedCredential(final String encryptedPassword) {
        int beginIndex = encryptedPassword.lastIndexOf(SEPARATOR_START);
        int endIndex = encryptedPassword.lastIndexOf(SEPARATOR_END);
        return encryptedPassword.substring(beginIndex + 1, endIndex);
    }

    @Override
    public boolean match(final String plainPassword, final String encryptedPassword) {
        if ((plainPassword == null) || (encryptedPassword == null)) {
            return false;
        }
        String encryptedAttemptedCredential = null;
        try {
            String algorithm = getAlgorithmFromEncryptedCredential(encryptedPassword);
            if (SECURE_ALGORITHM.equals(algorithm)) {
                String saltBase64 = getSaltFromEncryptedCredential(encryptedPassword);
                byte[] salt = Base64.decodeBase64(saltBase64);
                encryptedAttemptedCredential = encryptSecure(salt, plainPassword);
            } else {
                return false;
            }
        } catch (Exception e) {
            logService.log(LogService.LOG_ERROR, "Credential check failed", e);
            return false;
        }
        return encryptedPassword.equals(encryptedAttemptedCredential);
    }

    public void setLogService(final LogService logService) {
        this.logService = logService;
    }

}
