package Rbac;

import it.unisa.dia.gas.jpbc.Element;

public class UserSecret {
	
	private Element d0;
	
	private Element d1;
	private Element d2;
	public Element getD0() {
		return d0;
	}
	public void setD0(Element d0) {
		this.d0 = d0;
	}
	public Element getD1() {
		return d1;
	}
	public void setD1(Element d1) {
		this.d1 = d1;
	}
	public Element getD2() {
		return d2;
	}
	public void setD2(Element d2) {
		this.d2 = d2;
	}
	
	public UserSecret(Element d0, Element d1, Element d2){
		this.d0=d0;
		this.d1 = d1;
		this.d2 = d2;
	}
	@Override
	public String toString() {
		return "UserSecret [d0=" + d0 + ", d1=" + d1 + ", d2=" + d2 + "]";
	}
	
	
	
	

}
