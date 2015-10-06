/*
 * Copyright (C) 2011 Everit Kft. (http://www.everit.biz)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.everit.osgi.password.encryptor.pbkdf2;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.everit.credential.encryptor.CredentialEncryptor;
import org.everit.credential.encryptor.CredentialMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link CredentialEncryptor} and {@link CredentialMatcher}.
 */
public class PBKDF2PasswordEncryptorImpl implements CredentialEncryptor, CredentialMatcher {

  private static final int ITERATION_COUNT_MIN_VALUE = 1;

  private static final Logger LOGGER = LoggerFactory.getLogger(PBKDF2PasswordEncryptorImpl.class);

  /**
   * The algorithm used to generate random salt.
   */
  private static final String SALT_ALGORITHM = "SHA1PRNG";

  private static final int SALT_BYTE = 8;

  /**
   * End separator character for the encrypted parts of the credential.
   */
  private static final String SEPARATOR_END = "}";

  /**
   * Start separator character for the encrypted parts of the credential.
   */
  private static final String SEPARATOR_START = "{";

  private String algorithm;

  /**
   * Pick an iteration count that works for you. The NIST recommends at least 1,000 iterations:
   * http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf iOS 4.x reportedly uses
   * 10,000: http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-
   * passwords/
   */
  private int iterationCount;

  /**
   * Constructor.
   *
   * @param algorithm
   *          The secure algorithm used to encrypt the passwords.
   * @param iterationCount
   *          the iteration count number. The NIST recommends at least 1,000 iterations:
   *          http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf iOS 4.x
   *          reportedly uses 10,000:
   *          http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-
   *          passwords/
   *
   * @throws NullPointerException
   *           if algorithm is <code>null</code>.
   * @throws IllegalArgumentException
   *           if iterationCount is not between
   *           {@link PBKDF2PasswordEncryptorImpl#ITERATION_COUNT_MIN_VALUE} and
   *           {@link Integer#MAX_VALUE} value. Or the algorithm is not supported.
   */
  public PBKDF2PasswordEncryptorImpl(final String algorithm, final int iterationCount) {
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm cannot be null");
    if (!Algorithm.SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS.containsKey(algorithm)) {
      throw new IllegalArgumentException("algorithm value [" + algorithm + "] is not supported, "
          + "supported values are "
          + Algorithm.SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS.keySet().toString() + ".");
    }

    if ((iterationCount < ITERATION_COUNT_MIN_VALUE)) {
      throw new IllegalArgumentException("iterationCount value [" + iterationCount + "] must be "
          + "between [" + ITERATION_COUNT_MIN_VALUE + "," + Integer.MAX_VALUE + "]");
    }
    this.iterationCount = iterationCount;
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

  private String encryptSecure(final byte[] salt, final String plainPassword,
      final String algorithm)
          throws NoSuchAlgorithmException, InvalidKeySpecException {
    int deriverdKeyLenght = Algorithm.SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS.get(algorithm);
    KeySpec spec =
        new PBEKeySpec(plainPassword.toCharArray(), salt, iterationCount, deriverdKeyLenght);
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
    byte[] salt = new byte[SALT_BYTE];
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
      String saltBase64 = getSaltFromEncryptedCredential(encryptedPassword);
      byte[] salt = Base64.decodeBase64(saltBase64);
      encryptedAttemptedCredential = encryptSecure(salt, plainPassword, algorithm);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      LOGGER.error("Credential check failed", e);
      return false;
    }
    return encryptedPassword.equals(encryptedAttemptedCredential);
  }

}
