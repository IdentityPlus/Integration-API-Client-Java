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
 * The Anonymous_ID is part of the Legacy HTTP call assembly.
 * This response comes URL encoded as part of the redirect when the
 * identity + service is used to read the client certificate from the user browser.
 *
 * This object is only needed by implementations that use the identity + service over
 * http or do not have access to reading the SSL client certificate for other reasons.
 *
 * This object will always come encrypted with the API Client's public key.
 *
 * @param outcome        the outcome of the call
 * @param anonymous_id   the anonymous id as identified by the identity+ api
 * @param serial_number  the serial number of the certificate as identified by the identity+ api
 * @param salt           random text with no meaning in the identity + process; it only exists so
 *                       that responses with the same values encrypt to different outputs.
 *                       Can be discarded.
 * @param custom         unrecognized fields, preserved for round-trips
 *
 * @author Stefan Harsan Farr
 */
public record Anonymous_ID(
        Outcome outcome,
        String anonymous_id,
        String serial_number,
        String salt,
        Map<String, String> custom
) implements API_Response{

    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Anonymous_ID.class);

    public Anonymous_ID {
        Objects.requireNonNull(anonymous_id, "anonymous_id cannot be null");
        Objects.requireNonNull(serial_number, "serial_number cannot be null");
        custom = custom == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(custom));
    }

    /**
     * Creates a new Anonymous_ID with a freshly generated 16 character salt.
     */
    public Anonymous_ID(Outcome outcome, String anonymous_id, String serial_number) {
        this(outcome, anonymous_id, serial_number, Identity_Plus_Utils.random_text(16), null);
    }

    public static Anonymous_ID from_json(JsonObject object) {
        return Json_Codec.decode(Anonymous_ID.class, object);
    }
}