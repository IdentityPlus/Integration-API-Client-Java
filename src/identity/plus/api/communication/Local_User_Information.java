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
import java.util.Map;

import javax.json.JsonObject;

import identity.plus.api.Identity_Assurance;
import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;

/**
 * The Local_User_Information request deposits the details of a user local to the client service,
 * within the context of the client that makes the request. This can only be done once for a user.
 *
 * At least one of {@code serial_number} or {@code anonymous_id} must be given, as well as
 * {@code local_user_name}.
 *
 * @param anonymous_id        the anonymous id extracted from the visitor's identity + certificate. At this
 *                            stage identity + is not yet aware of the association, so it cannot look up
 *                            the user name.
 * @param serial_number       the certificate serial number, a string-encoded positive integer.
 *                            As of version 2, this is the primary way clients are identified.
 * @param local_user_name     a unique identifier binding the local user to the identity. Prefer a random
 *                            identifier such as a user id over the actual user name; either way, it is
 *                            only accessible to the binding service.
 * @param local_user_age      how long, in days, the user has been a member of the requesting service
 * @param tokens_of_trust     initial trust tokens to associate. 10 are associated automatically on binding;
 *                            one service can associate at most 10000 with an identity.
 * @param identity_assurance  the level of assurance the service can provide for this user;
 *                            null defaults to {@code none}
 * @param custom              additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Local_User_Information(
        String anonymous_id,
        String serial_number,
        String local_user_name,
        BigInteger local_user_age,
        BigInteger tokens_of_trust,
        Identity_Assurance identity_assurance,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Local_User_Information.class);

    public Local_User_Information {
        tokens_of_trust    = tokens_of_trust == null ? BigInteger.ZERO : tokens_of_trust;
        identity_assurance = identity_assurance == null ? Identity_Assurance.none : identity_assurance;
        custom             = API_Object.custom_of(custom);
    }

    public Local_User_Information(String anonymous_id, String serial_number, String local_user_name,
                                  BigInteger local_user_age, BigInteger tokens_of_trust) {
        this(anonymous_id, serial_number, local_user_name, local_user_age, tokens_of_trust, null);
    }

    public Local_User_Information(String anonymous_id, String serial_number, String local_user_name,
                                  BigInteger local_user_age, BigInteger tokens_of_trust, Identity_Assurance assurance) {
        this(require(anonymous_id, serial_number, local_user_name), serial_number, local_user_name,
             local_user_age, tokens_of_trust, assurance, null);
    }

    public static Local_User_Information from_json(JsonObject object) {
        return Json_Codec.decode(Local_User_Information.class, object);
    }

    private static String require(String anonymous_id, String serial_number, String local_user_name) {
        if (anonymous_id == null && serial_number == null)
            throw new NullPointerException("Either serial_number or anonymous_id must be specified");
        if (local_user_name == null)
            throw new NullPointerException("local_user_name must be specified");
        return anonymous_id;
    }
}