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

import org.apache.commons.codec.binary.Base32;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.concurrent.TimeUnit;

/**
 * A helper class for building totp urls according to
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
 */
public class TotpUriBuilder {

    private static final String QR_CODE_URL = "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=%s";
    private static final String PREFIX = "otpauth://totp/";
    private static final Base32 BASE_32 = new Base32();

    private final String label;
    private final String secret;
    private String issuer;
    private TotpAlgorithm algorithm;
    private Integer digits;
    private Long period;

    private TotpUriBuilder(String label, String secret) {
        this.label = label;
        this.secret = secret;
    }

    /**
     * Takes properties of {@link Totp} and inserts them into this {@link TotpUriBuilder}.
     *
     * @param totp The {@link Totp} instance
     * @return The {@link TotpUriBuilder} instance
     */
    public TotpUriBuilder configure(Totp totp) {
        return setPeriod(TimeUnit.MILLISECONDS.toSeconds(totp.getTimeStep()))
                .setDigits(totp.getDigits())
                .setAlgorithm(totp.getAlgorithm());
    }

    /**
     * Sets the issuer, a string which indicating the provider or service for this otp. Should be equal to the label
     * prefix.
     * <p>
     * Warning: {@code algorithm} is ignored by older versions of Google Authenticator and will rely upon the prefix of
     * the label.
     *
     * @param issuer The issuer
     * @return The {@link TotpUriBuilder} instance
     */
    public TotpUriBuilder setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Sets the algorithm which is used for this otp. This is an optional parameter.
     * <p>
     * Warning: {@code algorithm} is ignored by Google Authenticator.
     *
     * @param algorithm The algorithm
     * @return The {@link TotpUriBuilder} instance
     */
    public TotpUriBuilder setAlgorithm(TotpAlgorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Set the number of digits a otp has. Allowed values: 6, 8. This is an optional parameter.
     * <p>
     * Warning: {@code digits} is ignored by Google Authenticator.
     *
     * @param digits The number of digits
     * @throws IllegalArgumentException Will be thrown, if {@code digits} is not {@code null}, 6 or 8
     * @return The {@link TotpUriBuilder} instance
     */
    public TotpUriBuilder setDigits(Integer digits) {
        if (digits != null && !TotpValidator.isValidForDigits(digits))
            throw new IllegalArgumentException("digits must be 6 or 8.");

        this.digits = digits;
        return this;
    }

    /**
     * Set the period which defines how many seconds a TOTP code will be valid. This is an optional parameter.
     * <p>
     * Warning: {@code period} is ignored by Google Authenticator.
     *
     * @param period The period in seconds
     * @throws IllegalArgumentException Will be thrown, if period is not positive
     * @return The {@link TotpUriBuilder} instance
     */
    public TotpUriBuilder setPeriod(Long period) {
        if (period != null && period <= 0)
            throw new IllegalArgumentException("period must be positive.");

        this.period = period;
        return this;
    }

    /**
     * Constructs a uri from the given data.
     *
     * @throws UnsupportedOperationException Will be thrown if {@code UTF-8} is not supported. After it is thrown,
     *                                       please prepare yourself for the end of the world you know and love.
     * @return A constructed uri
     */
    public String build() {
        StringBuilder sb = new StringBuilder(PREFIX)
                .append(label)
                .append("?secret=")
                .append(encode(secret));
        if (issuer != null)
            sb.append("&issuer=").append(encode(issuer));
        if (algorithm != null)
            sb.append("&algorithm=").append(encode(algorithm.name()));
        if (digits != null)
            sb.append("&digits=").append(digits);
        if (period != null)
            sb.append("&period=").append(period);
        return sb.toString();
    }

    public String buildQrCodeUrl() {
        return createQrCodeUrl(build());
    }

    /**
     * Create a new builder with the required {@code label} and {@code secret} parameter.
     *
     * @param label The label. It should consist of an prefix and an account identifier, delimited by a {@code :}. Must
     *              not be null.
     * @param secret The raw secret. Must not be null.
     * @throws IllegalArgumentException Will be thrown if {@code label} or {@code secret} is {@code null}
     * @return A new {@link TotpUriBuilder}
     */
    public static TotpUriBuilder builder(String label, byte[] secret) {
        if (secret == null)
            throw new IllegalArgumentException("secret must be not null.");

        return builder(label, BASE_32.encodeAsString(secret));
    }

    /**
     * Create a new builder with the required {@code label} and {@code secret} parameter.
     *
     * @param label The label. It should consist of an prefix and an account identifier, delimited by a {@code :}. Must
     *              not be null.
     * @param secret The base16-encoded secret. Must not be null.
     * @throws IllegalArgumentException Will be thrown if {@code label} or {@code secret} is {@code null}
     * @return A new {@link TotpUriBuilder}
     */
    public static TotpUriBuilder builder(String label, String secret) {
        if (label == null)
            throw new IllegalArgumentException("label must be not null.");
        if (secret == null)
            throw new IllegalArgumentException("secret must be not null.");

        TotpUriBuilder builder = new TotpUriBuilder(label, secret);

        // According to https://github.com/google/google-authenticator/wiki/Key-Uri-Format#issuer
        int labelPrefixDelimiter = label.indexOf(':');
        if (labelPrefixDelimiter >= 0)
            builder.setIssuer(label.substring(0, labelPrefixDelimiter));

        return builder;
    }

    public static String createQrCodeUrl(String uri) {
        return String.format(QR_CODE_URL, encode(uri));
    }

    private static String encode(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedOperationException("UTF-8 is not supported. The world is lost.", e);
        }
    }
}
