package CipherStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

public class UserRoleList {
	private static Map<Element,List<Element>> list;
	static{
		list = new HashMap<Element,List<Element>>();
		
	}
	
	private UserRoleList(){
		if(list==null){
			list = new HashMap<Element,List<Element>>();
		}
	}
	
	public static List<Element> getURL(Element IDu){
		return list.get(IDu);
	}
	
	public static boolean contains(Element IDu){
		return list.containsKey(IDu);
	}
	
	public static void initList(Element IDu, Element start){
		if(!list.containsKey(IDu)){
			List<Element> item = new ArrayList<Element>();
			if(start!=null){
			item.add(start);
			}
			list.put(IDu, item);
		}else{
			list.get(IDu).add(start);
		}
	}
}
