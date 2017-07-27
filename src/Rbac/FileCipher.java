package Rbac;

import java.util.HashMap;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;

public class FileCipher {
	
	private Element c3;
	
	private Element c4;
	
	private Element c5;
	
	private Map<Element,Element> CT_rf;
	
	private Element Sf;
	
	

	public Element getSf() {
		return Sf;
	}

	public void setSf(Element sf) {
		Sf = sf;
	}

	public Element getC3() {
		return c3;
	}

	public void setC3(Element c3) {
		this.c3 = c3;
	}

	public Element getC4() {
		return c4;
	}

	public void setC4(Element c4) {
		this.c4 = c4;
	}

	public Element getC5() {
		return c5;
	}

	public void setC5(Element c5) {
		this.c5 = c5;
	}

	public Element getCT_rf(Element IDr) {
		return CT_rf.get(IDr);
	}
	
	public Map<Element,Element> getCTMap(){
		return CT_rf;
	}

	public void setCT_rf(Element IDr,Element cT_rf) {
		if(CT_rf==null){
			CT_rf = new HashMap<Element,Element>();
		}
		CT_rf.put(IDr, cT_rf);
	}

	public void union(FileCipher cT2) {
		// TODO Auto-generated method stub
		for(Element e : cT2.getCTMap().keySet()){
			if(!this.CT_rf.containsKey(e)){
				this.CT_rf.put(e, cT2.getCTMap().get(e));
			}
			
		}
		
	}

	@Override
	public String toString() {
		return "FileCipher [c3=" + c3 + ", c4=" + c4 + ", c5=" + c5 + ", CT_rf=" + CT_rf + ", Sf=" + Sf + ", getSf()="
				+ getSf() + ", getC3()=" + getC3() + ", getC4()=" + getC4() + ", getC5()=" + getC5() + ", getCTMap()="
				+ getCTMap() + "]";
	}
	
	
	
	

}
