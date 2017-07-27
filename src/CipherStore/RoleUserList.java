package CipherStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

public class RoleUserList {
	private static Map<Element,List<Element>> list;
	static{
		list = new HashMap<Element,List<Element>>();
		
	}
	
	private RoleUserList(){
		if(list==null){
			list = new HashMap<Element,List<Element>>();
		}
	}
	
	public static List<Element> getRUL(Element IDr){
		return list.get(IDr);
	}
	
	public static boolean contains(Element IDr){
		return list.containsKey(IDr);
	}
	
	public static void initList(Element IDr, Element start){
		if(!list.containsKey(IDr)){
			List<Element> item = new ArrayList<Element>();
			if(start!=null){
			item.add(start);
			}
			list.put(IDr, item);
		}
		else{
			list.get(IDr).add(start);
		}
	}
}
