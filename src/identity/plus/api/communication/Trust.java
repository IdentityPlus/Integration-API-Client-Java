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

import java.util.Map;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.Object_Of_Trust;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;

/**
 * The Trust request deposits trust with a user, within the context of the client making the request.
 * This trust is visible to any client requesting the profile of the user.
 *
 * At least one of {@code local_user_name} or {@code anonymous_id} must be given.
 *
 * @param local_user_name  the local user name to refer to; only meaningful within the context of the
 *                         requesting API client, which bound the user in the first place
 * @param serial_number    the certificate serial number, a string-encoded positive integer.
 *                         As of version 2, this is the primary way clients are identified.
 * @param anonymous_id     the anonymous id to refer to; used when the identity + account is not bound
 *                         to a local user
 * @param trust_type       the kind of trust being deposited; null defaults to {@code random}
 * @param custom           additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Trust(
        String local_user_name,
        String serial_number,
        String anonymous_id,
        Object_Of_Trust trust_type,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Trust.class);

    public Trust {
        trust_type = trust_type == null ? Object_Of_Trust.random : trust_type;
        custom     = API_Object.custom_of(custom);
    }

    public Trust(String local_user_name, String serial_number, String anonymous_id, Object_Of_Trust trust_type) {
        this(require(local_user_name, anonymous_id), serial_number, anonymous_id, trust_type, null);
    }

    public static Trust from_json(JsonObject object) {
        return Json_Codec.decode(Trust.class, object);
    }

    private static String require(String local_user_name, String anonymous_id) {
        if (local_user_name == null && anonymous_id == null)
            throw new NullPointerException("Local user name or anonymous id must be specified");
        return local_user_name;
    }
}