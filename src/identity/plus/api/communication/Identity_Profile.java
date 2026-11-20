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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import javax.json.JsonObject;

import identity.plus.api.Identity_Plus_Utils;
import identity.plus.api.json.API_Response;
import identity.plus.api.json.Json_Codec;

public record Identity_Profile(
                Outcome outcome,
                String local_user_name,
                String local_user_id,
                String organizational_reference,
                String organizational_name,
                String organizational_email,
                List<String> service_roles,
                String user_secret,
                List<String> trust_sponsors,
                BigInteger sites_frequented,
                BigInteger average_identity_age,
                BigInteger max_identity_age,
                BigInteger authorizing_certificate,
                BigDecimal trust_score,
                BigInteger local_trust,
                BigInteger local_intrusions,
                List<String> your_guarantees,
                List<String> community_guarantees,
                Map<String, String> custom
        ) implements API_Response {

    public static final String JSON_NAME = Identity_Plus_Utils.json_name(Identity_Profile.class);

    public static Identity_Profile from_json(JsonObject o) { return Json_Codec.decode(Identity_Profile.class, o); }
}