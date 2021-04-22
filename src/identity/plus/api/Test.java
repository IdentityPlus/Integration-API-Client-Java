package identity.plus.api;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import identity.plus.api.communication.Simple_Response;

public class Test {
    
    public Test() {
    }
    
    public static void main(String[] args) throws UnsupportedEncodingException {
        
        JsonReader reader = Json.createReader(new InputStreamReader(new ByteArrayInputStream("{\"message\":\"123\", \"outcome\":\"ER_0004_Subject_user_name_is_already_associated_to_a_different_identity\"}".getBytes("UTF-8")), "UTF-8"));
        JsonObject jsso = reader.readObject();
        Simple_Response sr = new Simple_Response(jsso);
        System.out.print(sr.to_json());
    }
}
