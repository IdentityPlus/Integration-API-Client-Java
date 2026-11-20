package identity.plus.api.json;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonWriter;

import identity.plus.api.Identity_Plus_Utils;

public interface API_Object extends Serializable {

    /** Fields the codec did not recognize, preserved for round-trips. Never null. */
    Map<String, String> custom();

    /** The object's fields as JSON, without the root name. */
    default JsonObject json_object() {
        return Json_Codec.encode(this);
    }

    /** Same as {@link #json_object()}, as a builder, for callers that add to it. */
    default JsonObjectBuilder json_build() {
        return Json.createObjectBuilder(json_object());
    }

    /** The full wire form: {@code {"Type-Name": { ...fields... }}}. */
    default JsonObject json_root() {
        return Json.createObjectBuilder()
                .add(Identity_Plus_Utils.json_name(getClass()), json_object())
                .build();
    }

    default String to_json() {
        return json_root().toString();
    }

    default void to_json(OutputStream os) {
        try (JsonWriter writer = Json.createWriter(os)) {
            writer.writeObject(json_root());
        }
    }

    /** Normalizes the custom map for record compact constructors. */
    static Map<String, String> custom_of(Map<String, String> custom) {
        return custom == null || custom.isEmpty() ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(custom));
    }
}
