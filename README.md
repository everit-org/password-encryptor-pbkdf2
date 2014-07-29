password-encryptor-pbkdf2
=========================

PBKDF2 based implementation of the Password Encryptor API.

# Performance

The performance tests were run on Java 8, Windows 8.1 64 bit, Intel Core i5-3210M @ 2.5GHz, 12GB RAM

Algorithm|Iteration|Encryption time
---|---:|---:
PBKDF2WithHmacSHA1|1000|1.5 ms
PBKDF2WithHmacSHA1|10000|15 ms
PBKDF2WithHmacSHA1|20000|30 ms
PBKDF2WithHmacSHA256|1000|2.1ms
PBKDF2WithHmacSHA256|10000|21 ms
PBKDF2WithHmacSHA256|20000|42 ms
PBKDF2WithHmacSHA512|1000|3.2ms
PBKDF2WithHmacSHA512|10000|32ms
PBKDF2WithHmacSHA512|20000|64ms

## Default configuration
The default and recommended setting for encryption is PBKDF2WithHmacSHA256 with 100 iterations. This will be secure enough (SHA-250) and fast enough (iteration 100) to store and match passwords. The authentication process can be kept under 1 ms with this configuration.
