package CipherStore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

public class BaseList {
	private static Map<Element,List<Element>> list;
	static{
		list = new HashMap<Element,List<Element>>();
		
	}
	
	private  BaseList() {
		if(list==null){
			list = new HashMap<Element,List<Element>>();
		}
	}
	
	public static List<Element> getList(Element IDr){
		return list.get(IDr);
	}
	
	public boolean contains(Element Key){
		return list.containsKey(Key);
	}


}
