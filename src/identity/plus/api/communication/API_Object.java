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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;
import javax.json.JsonWriter;

import identity.plus.api.Identity_Plus_Utils;

public abstract class API_Object implements Serializable{
    private static final long serialVersionUID = 1L;

    protected final void restore_object(JsonObject object){
        try{
            for(Field f : getClass().getFields()){
                f.setAccessible(true);
                int modifiers = f.getModifiers();
                
                // skip the static fields
                if(Modifier.isStatic(modifiers)) continue;
                                
                String name = f.getName().replace('_', '-');
                
                if(!object.containsKey(name)) continue;
                else if(List.class.isAssignableFrom(f.getType())){
                    JsonArray tss = object.getJsonArray(name);
                    ArrayList<String> tss_list = new ArrayList<String>();
                    for(int i = 0; i < tss.size(); i++) tss_list.add(tss.getString(i));
                    f.set(this, Collections.unmodifiableList(tss_list));
                }
                else{
                    JsonValue value = object.get(name);

                    String string_value = null;
                    if(value.getValueType() == ValueType.TRUE) string_value = "true";
                    else if(value.getValueType() == ValueType.FALSE) string_value = "false";
                    else if(value.getValueType() == ValueType.NULL) string_value = null;
                    else if(value.getValueType() == ValueType.STRING) string_value = object.getString(name);
                    else string_value = value.toString();
                    
                    if(f.getType() == String.class)  f.set(this, string_value);
                    else if(f.getType() == Date.class) f.set(this, new Date(Long.parseLong(string_value)));
                    else if(f.getType() == BigInteger.class) f.set(this, new BigInteger(string_value == null || string_value.length() == 0 ? "0" : string_value));
                    else if(f.getType() == BigDecimal.class) f.set(this, new BigDecimal(string_value == null || string_value.length() == 0 ? "0" : string_value));
                    else if(f.getType() == Boolean.class) f.set(this, Boolean.valueOf(string_value == null || string_value.length() == 0 ? "false" : string_value));
                    else if(f.getType() == byte[].class) f.set(this, string_value == null ? null : Base64.getDecoder().decode(string_value));
                    else if(Enum.class.isAssignableFrom(f.getType())) f.set(this, Enum.valueOf(f.getType().asSubclass(Enum.class), string_value.replace(' ', '_').replace('-', '_')));
                }
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
    
    public final JsonObjectBuilder json_build(){
        JsonObjectBuilder b = Json.createObjectBuilder();
        
        try{
            for(Field f : getClass().getFields()){
                // skip the static fields
                if(Modifier.isStatic(f.getModifiers())) continue;

                Object val = f.get(this);
                String name = f.getName().replace('_', '-');
                
                if(val == null) continue;
                else if(val instanceof String) {
                        if(((String)val).length() > 0) b.add(name, (String)val);
                }
                else if(val instanceof BigInteger) {
                        if(((BigInteger)val).intValue() != 0) b.add(name, (BigInteger)val);
                }
                else if(val instanceof BigDecimal) {
                        if(((BigDecimal)val).doubleValue() != 0) b.add(name, (BigDecimal)val);
                }
                else if(val instanceof Boolean) {
                        if(!((Boolean)val).booleanValue()) b.add(name, (Boolean)val);
                }
                else if(val instanceof Date) b.add(name, ((Date)val).getTime());
                else if(val instanceof byte[]) {
                        if(((byte[])val).length > 0) b.add(name, Base64.getEncoder().encodeToString((byte[])val));
                }
                else if(val instanceof Enum) b.add(name, ((Enum<?>)val).name().replace('_', ' '));
                else if(val instanceof List){
                        if(((List)val).size() > 0) {
                                JsonArrayBuilder array_b = Json.createArrayBuilder();
                                for(Object ts : (List<?>)val) array_b.add(ts.toString());
                                
                                b.add(name, array_b);
                        }
                }
                else throw new RuntimeException("Unsupported type: " + val.getClass() + ", for field: " + name);
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }
        
        return b;
    }

    public final String to_json(){
        try{
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            to_json(bos);
            bos.close();

            return new String(bos.toByteArray(), "UTF-8");
        }
        catch(IOException e){
            throw new RuntimeException();
        }
    }
    
    public final void to_json(OutputStream os){
        JsonObjectBuilder b = Json.createObjectBuilder();
        b.add(Identity_Plus_Utils.json_name(getClass()), json_build());
        JsonWriter writer = Json.createWriter(os);
        writer.writeObject(b.build());
    }
    
    @Override
    public String toString() {
        return to_json();
    }
}
