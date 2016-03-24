/*
 * Copyright 2016 CloudBans (https://cloudbans.xyz)
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

package xyz.cloudbans.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

/**
 * A class for generating Time-based One-time Password Algorithm.
 */
public class Totp {

    private final long timeStep;
    private final int digits;
    private final TotpAlgorithm algorithm;

    /**
     * Constructor. Initialize default values (30 seconds interval, 6 digits length, SHA1 algorithm). Compatible with
     * Google Authenticator app.
     */
    public Totp() {
        this(TimeUnit.SECONDS.toMillis(30), 6, TotpAlgorithm.SHA1);
    }

    /**
     * Constructor.
     *
     * @param timeStep The timeStep in milliseconds
     * @param digits The number of digits (6 or 8)
     * @param algorithm The algorithm
     */
    public Totp(long timeStep, int digits, TotpAlgorithm algorithm) {
        this.timeStep = timeStep;
        this.digits = TotpValidator.checkDigits(digits);
        this.algorithm = algorithm;
    }

    /**
     * Returns the timeStep.
     *
     * @return The timeStep
     */
    public long getTimeStep() {
        return timeStep;
    }

    /**
     * Returns the number of digits.
     *
     * @return The number of digits
     */
    public int getDigits() {
        return digits;
    }

    /**
     * Returns the used {@link TotpAlgorithm}.
     *
     * @return The used {@link TotpAlgorithm}
     */
    public TotpAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Generates the current otp for the given {@code key}.
     *
     * @param key The {@code key}
     * @return The current otp
     */
    public String generateNow(byte[] key) {
        return generate(key, System.currentTimeMillis());
    }

    /**
     * Generates the otp for the given {@code key} and {@code time}.
     *
     * @param key The {@code key}
     * @param millis The timestamp in milliseconds
     * @return The otp
     */
    public String generate(byte[] key, long millis) {
        return generate(getTimeStep(), key, millis, getDigits(), getAlgorithm());
    }

    /**
     * Generates a otp for the given parameters.
     *
     * @param timeStep The timeStep in milliseconds
     * @param key The key
     * @param millis The time int milliseconds
     * @param digits The number of digits
     * @param algorithm The used {@link TotpAlgorithm}
     * @return The otp
     */
    public static String generate(long timeStep, byte[] key, long millis, int digits, TotpAlgorithm algorithm) {
        TotpValidator.checkDigits(digits);

        byte[] timeCounter = longToBytes(millis / timeStep);
        byte[] hash = hash(algorithm, key, timeCounter);

        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);
        int otp = binary % ((int) Math.pow(10, digits));
        return String.format("%0" + digits + "d", otp);
    }

    private static byte[] hash(TotpAlgorithm algorithm, byte[] key, byte[] content) {
        Mac mac;
        try {
            mac = algorithm.getInstance();
            mac.init(new SecretKeySpec(key, "RAW"));
        } catch (NoSuchAlgorithmException e) {
            throw new TotpException("Algorithm not found.", e);
        } catch (InvalidKeyException e) {
            throw new TotpException("Invalid key specified.", e);
        }
        return mac.doFinal(content);
    }

    private static byte[] longToBytes(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
        buffer.putLong(value);
        return buffer.array();
    }
}
