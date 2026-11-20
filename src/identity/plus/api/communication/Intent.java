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

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Object;
import identity.plus.api.json.API_Request;
import identity.plus.api.json.Json_Codec;

/**
 * The Intent request initiates an out of band operation with identity +. A context is created
 * and the user is redirected to identity + to handle the operation.
 * On the server side, intents are very short lived: they must be followed through within 30s,
 * otherwise they expire.
 *
 * @param type             one of {discover, register, bind}; null defaults to discover
 * @param service_name     the service the intent refers to, if any
 * @param local_user_name  the local user name to refer to, if any
 * @param name             the name of the local user (information sharing scenario)
 * @param email_address    the email address of the local user (information sharing scenario)
 * @param phone_number     the phone number of the local user (information sharing scenario)
 * @param local_user_age   how long, in days, the user has been a member of the requesting service
 * @param return_url       the URL to return to after the intent completes. The page must accept the
 *                         encrypted Identity_Profile response. If empty, identity + defaults to the
 *                         landing page of the domain the API is authenticating into.
 * @param strict_massl     if true, identity + will not include an intent reference in the return URL;
 *                         the requesting server is assumed to use strict mutually authenticated SSL and
 *                         to reach the user's session through the client certificate and the back-end API
 * @param custom           additional fields, sent as-is
 *
 * @since v2
 * @author Stefan Harsan Farr
 */
public record Intent(
        Intent_Type type,
        String service_name,
        String local_user_name,
        String name,
        String email_address,
        String phone_number,
        BigInteger local_user_age,
        String return_url,
        Boolean strict_massl,
        Map<String, String> custom
) implements API_Request {

    /**
     * The JSON Name of this request object as sent to the ReST API
     */
    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Intent.class);

    public Intent {
        type            = type == null ? Intent_Type.discover : type;
        service_name    = blank(service_name);
        local_user_name = blank(local_user_name);
        name            = blank(name);
        email_address   = blank(email_address);
        phone_number    = blank(phone_number);
        return_url      = blank(return_url);
        local_user_age  = local_user_age == null ? BigInteger.ZERO : local_user_age;
        custom          = API_Object.custom_of(custom);
    }

    public Intent(Intent_Type type) {
        this(type, null, null, null, null, null, null, null, true, null);
    }

    public Intent(Intent_Type type, String local_user_name, String name, String email_address,
                  String phone_number, String return_url, boolean strict_massl) {
        this(type, null, local_user_name, name, email_address, phone_number, null, return_url, strict_massl, null);
    }

    public Intent(Intent_Type type, String local_user_name, String name, String email_address,
                  String phone_number, BigInteger local_user_age, String return_url, boolean strict_massl) {
        this(type, null, local_user_name, name, email_address, phone_number, local_user_age, return_url, strict_massl, null);
    }

    public Intent(Intent_Type type, String service, String local_user_name, String name, String email_address,
                  String phone_number, BigInteger local_user_age, String return_url, boolean strict_massl) {
        this(type, service, local_user_name, name, email_address, phone_number, local_user_age, return_url, strict_massl, null);
    }

    public static Intent from_json(JsonObject object) {
        return Json_Codec.decode(Intent.class, object);
    }

    private static String blank(String s) { return s == null ? "" : s; }
}