package CipherStore;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

public class FileRoleList {
	private static Map<Element,List<Element>> list;
	static{
		list = new HashMap<Element,List<Element>>();
		
	}
	
	private FileRoleList(){
		if(list==null){
			list = new HashMap<Element,List<Element>>();
		}
	}
	
	public static List<Element> getFRL(Element IDf){
		return list.get(IDf);
	}
	
	public static boolean contains(Element IDf){
		return list.containsKey(IDf);
	}
	
	public static void initList(Element IDf, Element start){
		if(!list.containsKey(IDf)){
			List<Element> item = new ArrayList<Element>();
			if(start!=null){
			item.add(start);
			}
			list.put(IDf, item);
		}
	}



}
