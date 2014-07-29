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
import java.util.Map;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.PropertyOption;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.credential.encryptor.CredentialEncryptor;
import org.everit.osgi.credential.encryptor.CredentialMatcher;
import org.everit.osgi.password.encryptor.pbkdf2.PBKDF2PasswordEncryptorConstants;
import org.osgi.framework.BundleContext;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.log.LogService;

@Component(name = PBKDF2PasswordEncryptorConstants.SERVICE_FACTORYPID_CREDENTIAL_ENCRYPTOR, metatype = true,
        configurationFactory = true, policy = ConfigurationPolicy.REQUIRE)
@Properties({
        @Property(name = PBKDF2PasswordEncryptorConstants.PROP_ALGORITHM,
                value = PBKDF2PasswordEncryptorConstants.DEFAULT_ALGORITHM,
                options = {
                        @PropertyOption(
                                value = PBKDF2PasswordEncryptorConstants.PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA1,
                                name = PBKDF2PasswordEncryptorConstants.OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA1),
                        @PropertyOption(
                                value = PBKDF2PasswordEncryptorConstants.PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA224,
                                name = PBKDF2PasswordEncryptorConstants.OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA224),
                        @PropertyOption(
                                value = PBKDF2PasswordEncryptorConstants.PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA256,
                                name = PBKDF2PasswordEncryptorConstants.OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA256),
                        @PropertyOption(
                                value = PBKDF2PasswordEncryptorConstants.PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA384,
                                name = PBKDF2PasswordEncryptorConstants.OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA384),
                        @PropertyOption(
                                value = PBKDF2PasswordEncryptorConstants.PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA512,
                                name = PBKDF2PasswordEncryptorConstants.OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA512)
                }),
        @Property(name = PBKDF2PasswordEncryptorConstants.PROP_ITERATION_COUNT,
                intValue = PBKDF2PasswordEncryptorConstants.DEFAULT_ITERATION_COUNT),
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
     * Pick an iteration count that works for you. The NIST recommends at least 1,000 iterations:
     * http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf iOS 4.x reportedly uses 10,000:
     * http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/
     */
    private int iterationCount;

    private String algorithm;

    /**
     * The {@link LogService}.
     */
    @Reference(bind = "setLogService")
    private LogService logService;

    @Activate
    public void activate(final BundleContext context, final Map<String, Object> componentProperties)
            throws Exception {
        iterationCount = getIntProperty(componentProperties,
                PBKDF2PasswordEncryptorConstants.PROP_ITERATION_COUNT, 1, Integer.MAX_VALUE);
        algorithm = getStringProperty(componentProperties,
                PBKDF2PasswordEncryptorConstants.PROP_ALGORITHM);
        if (!PBKDF2PasswordEncryptorConstants.SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS
                .containsKey(algorithm)) {
            throw new ConfigurationException(PBKDF2PasswordEncryptorConstants.PROP_ALGORITHM,
                    "value [" + algorithm + "] is not supported, supported values are "
                            + PBKDF2PasswordEncryptorConstants.SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS.keySet().toString()
                            + "");
        }
    }

    @Override
    public String encrypt(final String plainPassword) {
        Objects.requireNonNull(plainPassword, "plainPassword cannot be null");
        try {
            byte[] salt = generateSalt();
            return encryptSecure(salt, plainPassword, algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to encrypt password", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to encrypt password", e);
        }
    }

    private String encryptSecure(final byte[] salt, final String plainPassword, final String algorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        int deriverdKeyLenght = PBKDF2PasswordEncryptorConstants.SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS.get(algorithm);
        KeySpec spec = new PBEKeySpec(plainPassword.toCharArray(), salt, iterationCount, deriverdKeyLenght);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
        byte[] passwordDigest = secretKeyFactory.generateSecret(spec).getEncoded();
        byte[] passwordDigestBase64 = Base64.encodeBase64(passwordDigest);
        String passwordDigestBase64StringUTF8 = StringUtils.newStringUtf8(passwordDigestBase64);
        byte[] saltBase64 = Base64.encodeBase64(salt);
        String saltBase64StringUTF8 = StringUtils.newStringUtf8(saltBase64);
        return SEPARATOR_START + algorithm + SEPARATOR_END
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

    private int getIntProperty(final Map<String, Object> componentProperties, final String propertyName,
            final int minValue, final int maxValue)
            throws ConfigurationException {
        Object value = componentProperties.get(propertyName);
        if ((value == null) || !(value instanceof Integer)) {
            throw new ConfigurationException(propertyName, "property not defined or not an integer");
        }
        int intValue = ((Integer) value).intValue();
        if ((intValue < minValue) || (intValue > maxValue)) {
            throw new ConfigurationException(propertyName, "property value [" + intValue + "] must be between ["
                    + minValue + "," + maxValue + "]");
        }
        return intValue;
    }

    private String getSaltFromEncryptedCredential(final String encryptedPassword) {
        int beginIndex = encryptedPassword.lastIndexOf(SEPARATOR_START);
        int endIndex = encryptedPassword.lastIndexOf(SEPARATOR_END);
        return encryptedPassword.substring(beginIndex + 1, endIndex);
    }

    private String getStringProperty(final Map<String, Object> componentProperties, final String propertyName)
            throws ConfigurationException {
        Object value = componentProperties.get(propertyName);
        if (value == null) {
            throw new ConfigurationException(propertyName, "property not defined");
        }
        return String.valueOf(value);
    }

    @Override
    public boolean match(final String plainPassword, final String encryptedPassword) {
        if ((plainPassword == null) || (encryptedPassword == null)) {
            return false;
        }
        String encryptedAttemptedCredential = null;
        try {
            String algorithm = getAlgorithmFromEncryptedCredential(encryptedPassword);
            String saltBase64 = getSaltFromEncryptedCredential(encryptedPassword);
            byte[] salt = Base64.decodeBase64(saltBase64);
            encryptedAttemptedCredential = encryptSecure(salt, plainPassword, algorithm);
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
