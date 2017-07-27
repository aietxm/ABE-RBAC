package Rbac;

import java.util.ArrayList;
import java.util.List;

import CipherStore.Pair;
import it.unisa.dia.gas.jpbc.Element;

public class RoleCipher {
	
	private Element c1;
	
	private Element c2;
	
	private Element c;
	
	private Element c0;
	
	//private Element c0_1;
	
	//private Element c0_2;
	
	private List<Pair<Element, Element>> CR_2;
	
	private Element Vr;
	
	

	public Element getVr() {
		return Vr;
	}

	public void setVr(Element vr) {
		Vr = vr;
	}

	public Element getC1() {
		return c1;
	}

	public void setC1(Element c1) {
		this.c1 = c1;
	}

	public Element getC2() {
		return c2;
	}

	public void setC2(Element c2) {
		this.c2 = c2;
	}

	public Element getC() {
		return c;
	}

	public void setC(Element c) {
		this.c = c;
	}

	public Element getC0() {
		return c0;
	}

	public void setC0(Element c0) {
		this.c0 = c0;
	}
	
	public void setCR_2(Element cn_1, Element cn_2){
		if(CR_2==null){
			CR_2 = new ArrayList<>();
		}
		CR_2.add(new Pair<Element, Element>(cn_1, cn_2));
	}
	
	public Pair<Element,Element> getCR_2(int index){
		return CR_2.get(index);
		
	}

	@Override
	public String toString() {
		return "RoleCipher [c1=" + c1 + ", c2=" + c2 + ", c=" + c + ", c0=" + c0 
				+ ", CR_2=" + CR_2 + ", Vr=" + Vr + "]";
	}
	
	
	

}
