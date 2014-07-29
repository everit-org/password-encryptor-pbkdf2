/**
 * This file is part of Everit - Password Encryptor PBKDF2 Tests.
 *
 * Everit - Password Encryptor PBKDF2 Tests is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Everit - Password Encryptor PBKDF2 Tests is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Everit - Password Encryptor PBKDF2 Tests.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.everit.osgi.password.encryptor.pbkdf2.tests;

import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.everit.osgi.credential.encryptor.CredentialEncryptor;
import org.everit.osgi.credential.encryptor.CredentialMatcher;
import org.everit.osgi.dev.testrunner.TestRunnerConstants;
import org.junit.Assert;
import org.junit.Test;

@Component(name = "PBKDF2PasswordEncryptorTest", immediate = true, configurationFactory = false,
        policy = ConfigurationPolicy.OPTIONAL)
@Properties({
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TESTRUNNER_ENGINE_TYPE, value = "junit4"),
        @Property(name = TestRunnerConstants.SERVICE_PROPERTY_TEST_ID, value = "PBKDF2PasswordEncryptorTest"),
        @Property(name = "credentialEncryptor.target"),
        @Property(name = "credentialMatcher.target")
})
@Service(value = PBKDF2PasswordEncryptorTestComponent.class)
public class PBKDF2PasswordEncryptorTestComponent {

    @Reference(bind = "setCredentialEncryptor")
    private CredentialEncryptor credentialEncryptor;

    @Reference(bind = "setCredentialMatcher")
    private CredentialMatcher credentialMatcher;

    public void setCredentialEncryptor(final CredentialEncryptor credentialEncryptor) {
        this.credentialEncryptor = credentialEncryptor;
    }

    public void setCredentialMatcher(final CredentialMatcher credentialMatcher) {
        this.credentialMatcher = credentialMatcher;
    }

    @Test
    public void testArgumentValidations() {
        try {
            credentialEncryptor.encrypt(null);
            Assert.fail();
        } catch (NullPointerException e) {
            Assert.assertEquals("plainPassword cannot be null", e.getMessage());
        }
        Assert.assertFalse(credentialMatcher.match(null, null));
        Assert.assertFalse(credentialMatcher.match("", null));
    }

    @Test
    public void testCredentialEncryptionAndValidation() {
        String encryptedCredential = credentialEncryptor.encrypt("foo");
        Assert.assertNotNull(encryptedCredential);
        Assert.assertTrue(credentialMatcher.match("foo", encryptedCredential));
        Assert.assertFalse(credentialMatcher.match("bar", encryptedCredential));
    }

}
