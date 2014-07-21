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

    private PBKDF2PasswordEncryptorConstants() {
    }

}
