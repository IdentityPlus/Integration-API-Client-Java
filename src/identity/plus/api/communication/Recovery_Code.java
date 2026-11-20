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
import java.util.TreeMap;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Response;
import identity.plus.api.json.Json_Codec;
import identity.plus.api.json.Secrets;

/**
 * The ID of an out of band authorization that can be used to issue an mTLS ID.
 *
 * The value is a credential. {@link #toString()} redacts it.
 *
 * @param outcome  the outcome of the call
 * @param value    the recovery code
 * @param custom   unrecognized fields, preserved for round-trips
 *
 * @author Stefan Harsan Farr
 */
public record Recovery_Code(
        Outcome outcome,
        String value,
        Map<String, String> custom
) implements API_Response {

    /**
     * The JSON Name of this response object as returned by the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Recovery_Code.class);

    public Recovery_Code {
        custom = custom == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(custom));
    }

    public Recovery_Code(Outcome outcome, String value) {
        this(outcome, value, null);
    }

    public static Recovery_Code from_json(JsonObject object) {
        return Json_Codec.decode(Recovery_Code.class, object);
    }

    @Override
    public String toString() {
        return "Recovery_Code[outcome=" + outcome + ", value=" + Secrets.redacted(value) + "]";
    }
}