/*
 * (C) Copyright 2016 Identity+ (https://identity.plus) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This code is part of the identity+ API Wrapper suite and it is meant to facilitate
 * access to the identity + ReST Service. While the ReST service is not dependent 
 * upon this code, this code shortens implementation time because it wraps regular
 * ReST calls into a more developer friendly package.
 * 
 * You are free to make changes to this code to better suite your particular
 * implementation and keep it closed source, however, if you consider the changes are relevant to the
 * the identity + community, please consider donating your changes back to the community.
 * 
 * You are permitted to use the identity.plus package names in your fork as long as the 
 * code can be used exclusively to connect to the Identity + ReST API services.
 * 
 * Please submit bugs or improvement requests at https://identity.plus/
 *
 * Contributors:
 *     Stefan Harsan Farr
 */
package identity.plus.api.communication;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;
import identity.plus.api.json.Secrets;

/**
 * Discloses the use of personal information about a user, identified either by the local user
 * name bound to the service, or by a hashed email or phone number anchor.
 *
 * At least one of {@code local_user_name}, {@code email_sha_anchor} or {@code phone_number_sha_anchor}
 * must be given. Use {@link #email_anchor(String)} and {@link #phone_number_anchor(String)} to compute
 * the anchors, so normalization is consistent across services.
 *
 * @param local_user_name          the local user name bound to the identity + account, if any
 * @param email_sha_anchor         SHA-512 of the normalized email address; use when there is no local user name
 * @param phone_number_sha_anchor  SHA-512 of the normalized phone number; use when there is no local user
 *                                 name or email
 * @param pii_type                 the kind of data point, in simple English: first name, last name, email address,
 *                                 phone number, picture, date of birth, IP address, address, etc.
 * @param sha_512                  SHA-512 of the normalized data point, for data that is comparable in hashed form.
 *                                 Normalize first: lowercase unless case matters, trim, punctuation to spaces unless
 *                                 the format is strict (e.g. IP addresses), no double spaces. Suggested formats:
 *                                 phone +12123123456, IP 123.123.123.123, email username@example.com,
 *                                 dates yyyymmdd, postal addresses as separate country / region / city / street /
 *                                 postal code entries. Do not hash passwords, already hashed or encrypted data,
 *                                 time series, images or biometrics.
 * @param sample_count             number of samples held for the data point; meaningful for data that is not hashed
 * @param custom                   additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Personal_Data_Disclosure_Request(
        String local_user_name,
        byte[] email_sha_anchor,
        byte[] phone_number_sha_anchor,
        String pii_type,
        byte[] sha_512,
        BigInteger sample_count,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Personal_Data_Disclosure_Request.class);

    public Personal_Data_Disclosure_Request {
        email_sha_anchor        = copy(email_sha_anchor);
        phone_number_sha_anchor = copy(phone_number_sha_anchor);
        sha_512                 = copy(sha_512);
        sample_count            = sample_count == null ? BigInteger.ZERO : sample_count;
        custom                  = API_Object.custom_of(custom);
    }

    public Personal_Data_Disclosure_Request(String local_user_name, byte[] email_sha_anchor, byte[] phone_number_sha_anchor,
                                            String pii_type, byte[] sha_512, BigInteger sample_count) {
        this(require(local_user_name, email_sha_anchor, phone_number_sha_anchor), email_sha_anchor,
             phone_number_sha_anchor, pii_type, sha_512, sample_count, null);
    }

    public static Personal_Data_Disclosure_Request from_json(JsonObject object) {
        return Json_Codec.decode(Personal_Data_Disclosure_Request.class, object);
    }

    // --- anchor helpers: one normalization for every integrator ---

    /** SHA-512 of the email address, trimmed and lowercased. */
    public static byte[] email_anchor(String email) {
        return sha_512_of(email.strip().toLowerCase(Locale.ROOT));
    }

    /** SHA-512 of the phone number in +CCNUMBER form: a leading 00 becomes +, everything but digits is removed. */
    public static byte[] phone_number_anchor(String phone) {
        String p = phone.strip();
        if (p.startsWith("00")) p = "+" + p.substring(2);
        String digits = p.replaceAll("[^0-9]", "");
        return sha_512_of((p.startsWith("+") ? "+" : "") + digits);
    }

    /** SHA-512 of an already normalized data point. */
    public static byte[] sha_512_of(String normalized) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(normalized.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 is required by every Java platform", e);
        }
    }

    // --- record plumbing for the byte[] components ---

    @Override public byte[] email_sha_anchor()        { return copy(email_sha_anchor); }
    @Override public byte[] phone_number_sha_anchor() { return copy(phone_number_sha_anchor); }
    @Override public byte[] sha_512()                 { return copy(sha_512); }

    @Override
    public boolean equals(Object o) {
        return o instanceof Personal_Data_Disclosure_Request r
            && Objects.equals(local_user_name, r.local_user_name)
            && Arrays.equals(email_sha_anchor, r.email_sha_anchor)
            && Arrays.equals(phone_number_sha_anchor, r.phone_number_sha_anchor)
            && Objects.equals(pii_type, r.pii_type)
            && Arrays.equals(sha_512, r.sha_512)
            && sample_count.equals(r.sample_count)
            && custom.equals(r.custom);
    }

    @Override
    public int hashCode() {
        return Objects.hash(local_user_name, pii_type, sample_count, custom,
                            Arrays.hashCode(email_sha_anchor), Arrays.hashCode(phone_number_sha_anchor),
                            Arrays.hashCode(sha_512));
    }

    @Override
    public String toString() {
        return "Personal_Data_Disclosure_Request[local_user_name=" + local_user_name
             + ", email_anchor=" + Secrets.redacted(email_sha_anchor)
             + ", phone_anchor=" + Secrets.redacted(phone_number_sha_anchor)
             + ", pii_type=" + pii_type
             + ", sha_512=" + Secrets.redacted(sha_512)
             + ", sample_count=" + sample_count + "]";
    }

    private static byte[] copy(byte[] b) { return b == null ? null : b.clone(); }

    private static String require(String local_user_name, byte[] email_anchor, byte[] phone_anchor) {
        if (local_user_name == null && email_anchor == null && phone_anchor == null)
            throw new NullPointerException("Either local_user_name, email_sha_anchor or phone_number_sha_anchor must be specified");
        return local_user_name;
    }
}