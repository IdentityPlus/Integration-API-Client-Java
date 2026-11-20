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
import java.util.Objects;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;
import identity.plus.api.json.Secrets;

/**
 * The User_Secret request deposits a secret string associated with the user within
 * the context of the client that makes the request. The secret is only available to the
 * client that deposited it.
 *
 * The secret is a credential. {@link #toString()} redacts it.
 *
 * @param local_user_name  the local user name to refer to; only meaningful within the context of the
 *                         requesting API client, which bound the user in the first place
 * @param secret           the secret to associate: a password, an encryption key, etc.
 * @param custom           additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record User_Secret(
        String local_user_name,
        String secret,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(User_Secret.class);

    public User_Secret {
        custom = API_Object.custom_of(custom);
    }

    public User_Secret(String local_user_name, String secret) {
        this(Objects.requireNonNull(local_user_name, "User name must be specified"),
             secret == null ? "" : secret,
             null);
    }

    public static User_Secret from_json(JsonObject object) {
        return Json_Codec.decode(User_Secret.class, object);
    }

    @Override
    public String toString() {
        return "User_Secret[local_user_name=" + local_user_name
             + ", secret=" + Secrets.redacted(secret) + "]";
    }
}