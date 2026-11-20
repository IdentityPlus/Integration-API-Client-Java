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

/**
 * The Device Authorization Request creates an authorization token which allows the user to jump
 * directly to the device authorization step. It provides sufficient proof of identity for
 * identity + to skip further verification steps. In other words, it allows a third party to vouch
 * for the identity of its user, so that the user can recover their identity + account if they are
 * left with no certified devices and no other access to their account.
 *
 * There are prerequisites for this action to be successful:
 * - A service can only provide authorization requests for its own users
 * - These users must have their identity + accounts bound to their local service accounts
 * - The user must authorize the service to perform this action in their identity + profile
 * - Only organizations that can provide either KYC or in-person identity assurance for their
 *   clients can perform this operation
 *
 * @param local_user_name  the local user name the identity + account is bound to
 * @param custom           additional fields, sent as-is
 *
 * @author Stefan Harsan Farr
 */
public record Device_Authorization_Request(
        String local_user_name,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Device_Authorization_Request.class);

    public Device_Authorization_Request {
        custom = API_Object.custom_of(custom);
    }

    public Device_Authorization_Request(String local_user_name) {
        this(Objects.requireNonNull(local_user_name, "Local user name must be specified"), null);
    }

    public static Device_Authorization_Request from_json(JsonObject object) {
        return Json_Codec.decode(Device_Authorization_Request.class, object);
    }
}