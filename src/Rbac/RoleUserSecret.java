package Rbac;

import it.unisa.dia.gas.jpbc.Element;

public class RoleUserSecret {
	private Element d3;
	
	private Element d_r;
	
	private Element d_r_1;

	private int Version;
	
	public int getVersion() {
		return Version;
	}

	public void setVersion(int version) {
		Version = version;
	}

	public Element getD3() {
		return d3;
	}

	public void setD3(Element d3) {
		this.d3 = d3;
	}

	public Element getD_r() {
		return d_r;
	}

	public void setD_r(Element d_r) {
		this.d_r = d_r;
	}

	public Element getD_r_1() {
		return d_r_1;
	}

	public void setD_r_1(Element d_r_1) {
		this.d_r_1 = d_r_1;
	}
	
	public RoleUserSecret(Element d3, Element d_r, Element d_r_1, int Version){
		this.d3 = d3;
		this.d_r = d_r;
		this.d_r_1 = d_r_1;
		this.Version = Version;
	}

	public RoleUserSecret(){

	}

	@Override
	public String toString() {
		return "RoleUserSecret [d3=" + d3 + ", d_r=" + d_r + ", d_r_1=" + d_r_1 + ", Version=" + Version + "]";
	}
	
	
	
}
