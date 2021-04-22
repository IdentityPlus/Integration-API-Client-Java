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
package identity.plus.api;

import java.util.NoSuchElementException;
/**
 * The severity of the intrusions as suggested by Identity+.
 * Number of intrusion points are associated 
 * 
 * @author Stefan Harsan Farr
 */
public enum Object_Of_Intrusion {
    mistake(0), policy_violation(1), intrusive(2), fraud(3), material_damage(4), inappropriate_content(5), false_information(6), harassment(7);
    
    public final int code;

    private Object_Of_Intrusion(int code) {
        this.code = code;
    }
    
    public static Object_Of_Intrusion valueOf(int code){
        for(Object_Of_Intrusion s : values()) if(s.code == code) return s;
        throw new NoSuchElementException();
    }
}
