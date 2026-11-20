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

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Response;
import identity.plus.api.json.Json_Codec;
import identity.plus.api.json.Secrets;

/**
 * A service identity issued by identity +: the certificate and private key, both
 * PEM encoded, plus the same identity as a password-protected PKCS#12 bundle.
 *
 * Contains secret material. {@link #toString()} redacts it; arrays are copied on
 * the way in and on the way out, so the record stays immutable.
 *
 * @param outcome      the outcome of the call
 * @param p12          the identity in PKCS#12 format
 * @param password     password for the PKCS#12 bundle
 * @param certificate  PEM encoded certificate
 * @param private_key  PEM encoded private key
 * @param custom       unrecognized fields, preserved for round-trips
 *
 * @author Stefan Harsan Farr
 */
public record Service_Identity(
        Outcome outcome,
        byte[] p12,
        String password,
        byte[] certificate,
        byte[] private_key,
        Map<String, String> custom
) implements API_Response {

    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Service_Identity.class);

    public Service_Identity {
        p12         = Secrets.copy(p12);
        certificate = Secrets.copy(certificate);
        private_key = Secrets.copy(private_key);
        custom = custom == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(custom));
    }

    public Service_Identity(Outcome outcome, byte[] p12, String password, byte[] certificate, byte[] private_key) {
        this(outcome, p12, password, certificate, private_key, null);
    }

    public static Service_Identity from_json(JsonObject object) {
        return Json_Codec.decode(Service_Identity.class, object);
    }

    @Override public byte[] p12()         { return Secrets.copy(p12); }
    @Override public byte[] certificate() { return Secrets.copy(certificate); }
    @Override public byte[] private_key() { return Secrets.copy(private_key); }

    @Override
    public boolean equals(Object o) {
        return o instanceof Service_Identity s
            && outcome == s.outcome
            && custom.equals(s.custom)
            && Secrets.same(p12, password, certificate, private_key, s.p12, s.password, s.certificate, s.private_key);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(outcome, custom) + Secrets.hash(p12, password, certificate, private_key);
    }

    @Override
    public String toString() {
        return Secrets.describe("Service_Identity", outcome, p12, password, certificate, private_key);
    }
}