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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Supported Algorithm to PBKDF2PasswordEncryptor.
 */
public final class Algorithm {

  private static final int KEY_LENGTH_160 = 160;

  private static final int KEY_LENGTH_224 = 224;

  private static final int KEY_LENGTH_256 = 256;

  private static final int KEY_LENGTH_384 = 384;

  private static final int KEY_LENGTH_512 = 512;

  public static final String PBKDF2_HMAC_SHA1 = "PBKDF2WithHmacSHA1";

  public static final String PBKDF2_HMAC_SHA224 = "PBKDF2WithHmacSHA224";

  public static final String PBKDF2_HMAC_SHA256 = "PBKDF2WithHmacSHA256";

  public static final String PBKDF2_HMAC_SHA384 = "PBKDF2WithHmacSHA384";

  public static final String PBKDF2_HMAC_SHA512 = "PBKDF2WithHmacSHA512";

  public static final Map<String, Integer> SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS;

  static {
    Map<String, Integer> algorithms = new HashMap<String, Integer>();
    algorithms.put(Algorithm.PBKDF2_HMAC_SHA1, KEY_LENGTH_160);
    algorithms.put(Algorithm.PBKDF2_HMAC_SHA224, KEY_LENGTH_224);
    algorithms.put(Algorithm.PBKDF2_HMAC_SHA256, KEY_LENGTH_256);
    algorithms.put(Algorithm.PBKDF2_HMAC_SHA384, KEY_LENGTH_384);
    algorithms.put(Algorithm.PBKDF2_HMAC_SHA512, KEY_LENGTH_512);
    SUPPORTED_ALGORITHMS_AND_KEY_LENGTHS = Collections.unmodifiableMap(algorithms);
  }

  private Algorithm() {
  }
}
