package identity.plus.api.json;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;

public final class Json_Codec {
    private Json_Codec() {}

    private record Property(String json_name, int slot, Method accessor, Class<?> type) {}
    private record Schema(Constructor<?> ctor, List<Property> properties, Map<String, Property> by_name, int custom_slot) {}

    private static final ClassValue<Schema> SCHEMAS = new ClassValue<>() {
        @Override protected Schema computeValue(Class<?> type) {
            RecordComponent[] rc = type.getRecordComponents();
            if (rc == null) throw new IllegalArgumentException(type + " is not a record");
            Class<?>[] sig = new Class<?>[rc.length];
            List<Property> props = new ArrayList<>();
            Map<String, Property> by_name = new HashMap<>();
            int custom_slot = -1;
            
            for (int i = 0; i < rc.length; i++) {
                sig[i] = rc[i].getType();
                if (rc[i].getName().equals("custom")) { custom_slot = i; continue; }
                if (sig[i].isPrimitive()) throw new IllegalStateException(type.getSimpleName() + "." + rc[i].getName() + ": use boxed types");
                Property p = new Property(rc[i].getName().replace('_', '-'), i, rc[i].getAccessor(), sig[i]);
                props.add(p);
                by_name.put(p.json_name(), p);
            }
            try {
                return new Schema(type.getDeclaredConstructor(sig), List.copyOf(props), Map.copyOf(by_name), custom_slot);
            } 
            catch (NoSuchMethodException e) { throw new IllegalStateException(e); }
        }
    };

    public static <T extends Record> T decode(Class<T> type, JsonObject json) {
        Schema s = SCHEMAS.get(type);
        Object[] args = new Object[s.ctor().getParameterCount()];
        Map<String, String> custom = new TreeMap<>();
        json.forEach((key, value) -> {
            Property p = s.by_name().get(key);
            if (p == null) custom.put(key, text(value));
            else args[p.slot()] = read(p, value);
        });
       
        if (s.custom_slot() >= 0) args[s.custom_slot()] = custom;
        
        try {
            return type.cast(s.ctor().newInstance(args));
        } 
        catch (InvocationTargetException e) {
            throw new IllegalArgumentException("Invalid " + type.getSimpleName(), e.getCause());
        } 
        catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    public static JsonObject encode(Object o) {
        Schema s = SCHEMAS.get(o.getClass());
        JsonObjectBuilder b = Json.createObjectBuilder();
        
        try {
            for (Property p : s.properties()) {
                Object v = p.accessor().invoke(o);
                if (!omit(v)) b.add(p.json_name(), write(v));
            }
        } 
        catch (ReflectiveOperationException e) { throw new IllegalStateException(e); }
        
        if (o instanceof API_Object a) a.custom().forEach((k, v) -> { if (v != null) b.add(k, v); });
        return b.build();
    }

    private static Object read(Property p, JsonValue v) {
        if (v.getValueType() == ValueType.NULL) return null;
        Class<?> t = p.type();
        try {
            if (t == List.class)       return v.asJsonArray().stream().map(Json_Codec::text).toList();
            String s = text(v);
            if (t == String.class)     return s;
            if (t == BigInteger.class) return s.isEmpty() ? BigInteger.ZERO : new BigInteger(s);
            if (t == BigDecimal.class) return s.isEmpty() ? BigDecimal.ZERO : new BigDecimal(s);
            if (t == Boolean.class)    return Boolean.valueOf(s);
            if (t == Date.class)       return new Date(Long.parseLong(s));
            if (t == byte[].class)     return Base64.getDecoder().decode(s);
            if (t.isEnum())            return enum_value(t, s.replace(' ', '_').replace('-', '_'));
        } 
        catch (RuntimeException e) {
            throw new IllegalArgumentException("Cannot map '" + p.json_name() + "' = " + v, e);
        }
        
        throw new IllegalStateException("Unsupported type " + t + " for " + p.json_name());
    }

    private static JsonValue write(Object v) {
        if (v instanceof String s)     return Json.createValue(s);
        if (v instanceof BigInteger n) return Json.createValue(n);
        if (v instanceof BigDecimal n) return Json.createValue(n);
        if (v instanceof Boolean f)    return f ? JsonValue.TRUE : JsonValue.FALSE;
        if (v instanceof Date d)       return Json.createValue(d.getTime());
        if (v instanceof byte[] b)     return Json.createValue(Base64.getEncoder().encodeToString(b));
        if (v instanceof Enum<?> e)    return Json.createValue(e.name().replace('_', ' '));
        if (v instanceof List<?> l) {
            JsonArrayBuilder a = Json.createArrayBuilder();
            l.forEach(x -> a.add(String.valueOf(x)));
            return a.build();
        }
        
        throw new IllegalStateException("Unsupported type: " + v.getClass());
    }

    // Same wire behaviour as before: null, empty and zero values are left out. Booleans are always sent.
    private static boolean omit(Object v) {
        return v == null
            || v instanceof String s && s.isEmpty()
            || v instanceof BigInteger n && n.signum() == 0
            || v instanceof BigDecimal n && n.signum() == 0
            || v instanceof byte[] b && b.length == 0
            || v instanceof List<?> l && l.isEmpty();
    }

    private static String text(JsonValue v) {
        return switch (v.getValueType()) {
            case STRING -> ((JsonString) v).getString();
            case NULL   -> null;
            default     -> v.toString();   // numbers, true/false, nested values
        };
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Object enum_value(Class<?> t, String s) { return Enum.valueOf((Class) t, s); }
}