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

import static identity.plus.api.API_Action.Ask;
import static identity.plus.api.API_Action.Evasive_Maneuver;
import static identity.plus.api.API_Action.Fix_API_Problem;
import static identity.plus.api.API_Action.None;
import static identity.plus.api.API_Action.Proceed;
import static identity.plus.api.API_Action.Redirect;

import java.util.NoSuchElementException;

import identity.plus.api.API_Action;

public enum Outcome {
    OK_0000_Acknowledged("OK_0000", Proceed),
    OK_0001_Subject_anonymous_certificate_valid("OK_0001", Proceed),
    OK_0002_Subject_anonymous_certificate_valid_and_user_uid_associated("OK_0002", Proceed),
    
    OK_0100_Subject_user_successfully_associated_to_Identity_Plus_identity("OK_0100", Proceed),
    OK_0101_Subject_user_disassociated("OK_0101", Proceed),
    OK_0102_Subject_user_updated("OK_0102", Proceed),
    OK_0103_Identity_Plus_certificate_found_via_legacy_method("OK_0103", Proceed),

    PB_0000_No_Identity_Plus_anonymous_certificate("PB_0000", Ask),
    PB_0001_No_Identity_Plus_certificate_found_via_legacy_method("PB_0001", Ask),
    PB_0002_Expired_Identity_Plus_anonymous_certificate("PB_0002", Redirect),
    PB_0003_Identity_Plus_anonymous_certificate_needs_validation("PB_0003", Redirect),

    PB_0004_Revoked_Identity_Plus_anonymous_certificate("PB_0004", Evasive_Maneuver),
    PB_0005_Intruder_Certificate("PB_0005", Evasive_Maneuver),
    PB_0006_Unknown_Identity_Plus_anonymous_certificate("PB_0006", Evasive_Maneuver),
    PB_0007_Crypto_Failure_package_was_tempered_with("PB_0007", Evasive_Maneuver),

    ER_0000_Undetermined_error("ER_0000", None),
    ER_0001_Unknown_request_error("ER_0001", None),
    ER_0002_No_such_operation_for_object("ER_0002", None),
    ER_0003_Subject_user_name_is_already_associated("ER_0003", None),
    ER_0004_Subject_user_name_is_already_associated_to_a_different_identity("ER_0004", None),
    ER_0005_Subject_user_name_was_never_associated("ER_0005", None),
    ER_0006_Return_URL_is_too_long("ER_0006", None),
    ER_0007_An_intrusion_was_already_reported_on_this_certificate("ER_0007", None),
    ER_0008_Error_Parsing_Request("ER_0008", None),
    ER_0009_Request_Denied("ER_0009", None),
    ER_0010_Insufficient_Reference_Information("ER_0010", None),
    ER_0011_Incomplete_Message_Error("ER_0011", None),

    ER_1100_No_Identity_Plus_API_certificate_presented("ER_1100", Fix_API_Problem),
    ER_1101_Unknown_Identity_Plus_API_certificate("ER_1101", Evasive_Maneuver),
    ER_1102_Expired_Identity_Plus_API_certificate("ER_1102", Fix_API_Problem),
    ER_1103_Revoked_Identity_Plus_API_certificate("ER_1103", Fix_API_Problem),
    ER_1104_Number_of_connectable_identities_exceeded("ER_1104", Fix_API_Problem),
    ER_1105_Suspended_Identity_Plus_API_certificate("ER_1105", Fix_API_Problem),
    ER_1106_General_Identity_Plus_API_Problem("ER_1106", Fix_API_Problem);

    public final String code;
    public final API_Action action;
    
    private Outcome(String code, API_Action action) {
        this.code = code;
        this.action = action;
    }
    
    public static Outcome for_code(String code){
        for(Outcome ipr : values()) if(ipr.code.equals(code)) return ipr;
        throw new NoSuchElementException(code);
    }
    
    public boolean is_error(){
        return name().startsWith("ERR");
    }

    public boolean is_ok(){
        return code.startsWith("OK");
    }
}
