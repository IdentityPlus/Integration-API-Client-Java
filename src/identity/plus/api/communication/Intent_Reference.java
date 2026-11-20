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

/**
 * The Intent_Reference response is needed to reference the intended operation & context
 * when redirecting the user to Identity Plus.
 *
 * @param outcome    the outcome of the call
 * @param value      the intent to refer
 * @param subdomain  the subdomain the intent refers to
 * @param challenge  the challenge associated with the intent
 * @param custom     unrecognized fields, preserved for round-trips
 *
 * @since v2
 * @author Stefan Harsan Farr
 */
public record Intent_Reference(
        Outcome outcome,
        String value,
        String subdomain,
        String challenge,
        Map<String, String> custom
) implements API_Response {

    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Intent_Reference.class);

    public Intent_Reference {
        custom = custom == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(custom));
    }

    /**
     * Creates an acknowledged intent reference. The second argument is written to both
     * {@code subdomain} and {@code challenge}, as before.
     */
    public Intent_Reference(String value, String challenge_or_subdomain) {
        this(Outcome.OK_0000_Acknowledged,
             Objects.requireNonNull(value, "Intent reference must be specified"),
             challenge_or_subdomain,
             challenge_or_subdomain,
             null);
    }

    public static Intent_Reference from_json(JsonObject object) {
        return Json_Codec.decode(Intent_Reference.class, object);
    }
}