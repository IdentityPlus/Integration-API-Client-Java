package identity.plus.api.util;

import java.util.ArrayList;
import java.util.Map.Entry;
import java.util.TreeMap;

public class Memory_Ephemeral_KV_Storage {
    private static final TreeMap<String, Memory_Ephemeral_KV_Storage> sessions = new TreeMap<>();

    public static Memory_Ephemeral_KV_Storage find(String id){
        Memory_Ephemeral_KV_Storage s = sessions.get(id);
        
        if(s == null){
                synchronized(sessions){
                        garbage_collect();
                        s = new Memory_Ephemeral_KV_Storage();
                        sessions.put(id, s);
                }
        }
        
        return s;
    }
    
    private static void garbage_collect(){
            ArrayList<String> ids = new ArrayList<>();
            for(Entry<String, Memory_Ephemeral_KV_Storage> e : sessions.entrySet()) if(e.getValue().age() > 120) ids.add(e.getKey());
            for(String key : ids) sessions.remove(key);
    }
    
    private final TreeMap<String, Object> map = new TreeMap<>();
    private long last_accessed = 0;
    
    private Memory_Ephemeral_KV_Storage(){
        last_accessed = System.currentTimeMillis();
    }
    
    private long age(){
        return (System.currentTimeMillis() - last_accessed)/60000;
    }
    
    public void put(String name, Object value){
        last_accessed = System.currentTimeMillis();
        map.put(name, value);
    }
    
    public <T> T remove(String name){
        last_accessed = System.currentTimeMillis();
        return (T)map.remove(name);
    }
    
    public <T> T get(String name){
        last_accessed = System.currentTimeMillis();
        return (T)map.get(name);
    }
}
