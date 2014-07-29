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
package org.everit.osgi.password.encryptor.pbkdf2;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Constants of the PBKDF2 Password Encryptor component.
 */
public final class PBKDF2PasswordEncryptorConstants {

    /**
     * The service factory PID of the PBKDF2 Password Encryptor component.
     */
    public static final String SERVICE_FACTORYPID_CREDENTIAL_ENCRYPTOR = "org.everit.osgi.password.encryptor.pbkdf2.PBKDF2PasswordEncryptor";

    /**
     * The property name of the OSGi filter expression defining which LogService should be used by the PBKDF2 Password
     * Encryptor component.
     */
    public static final String PROP_LOG_SERVICE_TARGET = "logService.target";

    public static final String PROP_ITERATION_COUNT = "iteration.count";

    public static final String PROP_ALGORITHM = "algorithm";

    public static final String PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA1 = "%prop.option.algorithm.PBKDF2WithHmacSHA1";
    public static final String PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA224 = "%prop.option.algorithm.PBKDF2WithHmacSHA224";
    public static final String PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA256 = "%prop.option.algorithm.PBKDF2WithHmacSHA256";
    public static final String PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA384 = "%prop.option.algorithm.PBKDF2WithHmacSHA384";
    public static final String PROP_OPTION_ALGORITHM_PBKDF2_HMAC_SHA512 = "%prop.option.algorithm.PBKDF2WithHmacSHA512";

    public static final String OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
    public static final String OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA224 = "PBKDF2WithHmacSHA224";
    public static final String OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA256 = "PBKDF2WithHmacSHA256";
    public static final String OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA384 = "PBKDF2WithHmacSHA384";
    public static final String OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA512 = "PBKDF2WithHmacSHA512";

    public static final Map<String, Integer> SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS;

    static {
        Map<String, Integer> algorithms = new HashMap<String, Integer>();
        algorithms.put(OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA1, 160);
        algorithms.put(OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA224, 224);
        algorithms.put(OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA256, 256);
        algorithms.put(OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA384, 384);
        algorithms.put(OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA512, 512);
        SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS = Collections.unmodifiableMap(algorithms);
    };

    public static final int DEFAULT_ITERATION_COUNT = 100;

    public static final String DEFAULT_ALGORITHM = OPTION_VALUE_ALGORITHM_PBKDF2_HMAC_SHA256;

    private PBKDF2PasswordEncryptorConstants() {
    }

}
