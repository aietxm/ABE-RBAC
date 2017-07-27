package Utils;

import Rbac.RbacMainSecretKey;
import Rbac.RbacPublicKey;
import it.unisa.dia.gas.jpbc.Element;

public class DataValid {
	
	private RbacPublicKey pk;
	
	private RbacMainSecretKey mk;
	
	private Element t;
	
	private Element Vr;
	
	private Element IDu;
	
	private Element IDr;
	
	private Element IDf;
	private Element IDu0;
	
	
	
	
	
	

	public Element getIDu0() {
		return IDu0;
	}

	public void setIDu0(Element iDu0) {
		IDu0 = iDu0;
	}

	public Element getIDu() {
		return IDu;
	}

	public void setIDu(Element iDu) {
		IDu = iDu;
	}

	public Element getIDr() {
		return IDr;
	}

	public void setIDr(Element iDr) {
		IDr = iDr;
	}

	public Element getIDf() {
		return IDf;
	}

	public void setIDf(Element iDf) {
		IDf = iDf;
	}

	public RbacPublicKey getPk() {
		return pk;
	}

	public void setPk(RbacPublicKey pk) {
		this.pk = pk;
	}

	public RbacMainSecretKey getMk() {
		return mk;
	}

	public void setMk(RbacMainSecretKey mk) {
		this.mk = mk;
	}

	public Element getT() {
		return t;
	}

	public void setT(Element t) {
		this.t = t;
	}

	public Element getVr() {
		return Vr;
	}

	public void setVr(Element vr) {
		Vr = vr;
	}
	
	public Element ProcessD1(Element in){
		Element p = pk.getG_beta().duplicate().powZn(IDu).mul(pk.getH());
		Element re = p.duplicate().powZn(t);
		if(in!=null)
		System.out.println("ProcessD1:"+in.equals(re));
		return re;
		
	}
	
	public Element ProcessD2(Element in){
		Element re = pk.getG().duplicate().powZn(t.duplicate().negate());
		if(in!=null)
		System.out.println("ProcessD2:"+in.equals(re));
		return re;
	}
	
	public void ProcessC0_1(Element in){
		Element re = pk.getG_beta().duplicate().powZn(Vr);
		System.out.println("ProcessC0_1:"+in.equals(re));
	}
	
	public void ProcessC0_2(Element in){
		Element p = pk.getG_beta_dup().duplicate().powZn(Vr).powZn(IDu0);
		Element h = pk.getH_beta().duplicate().powZn(Vr);
		Element re = p.mul(h);
		System.out.println("ProcessC0_2:"+in.equals(re));
	}
	public  Element ProcessD_down(Element in){
		Element p = mk.getBeta().duplicate().powZn(mk.getBeta()).mul(Vr).mul(t);
		Element g = pk.getG().duplicate();
		Element re = pk.getP().pairing(g,g).duplicate().powZn(p);
		if(in!= null)
		System.out.println("ProcessD_down:"+in.equals(re));
		return re;
		
		
	}
	
	public void ProcessPK(RbacPublicKey pk2){
		System.out.println("ProcessPK:"+this.pk.equals(pk2));
	}
	
	public void ProcessC0(Element in){
		Element re = pk.getG().duplicate().powZn(Vr);
		System.out.println("ProcessC0:"+in.equals(re));
		
	}
	
	public void ProcessD0(Element in){
		Element p1 = pk.getG_beta_dup().duplicate().powZn(t);
		Element re = p1.duplicate().mul(mk.getG_alpha());
		System.out.println("ProcessD0:"+in.equals(re));
	}
	
	public Element ProcessA(Element in){
		Element c0_1 = pk.getG_beta().duplicate().powZn(Vr);
		Element p = IDu.duplicate().add(IDu0.duplicate().negate());
		Element temp1 = c0_1.duplicate().powZn(p.duplicate().invert());
		Element re = pk.getP().pairing(ProcessD1(null), temp1);
		if(in!=null)
		System.out.println("ProcessA:"+in.equals(re));
		return re;
	}
	
	public Element ProcessB(Element in){
		Element p = pk.getG_beta_dup().duplicate().powZn(Vr).powZn(IDu0);
		Element h = pk.getH_beta().duplicate().powZn(Vr);
		Element c0_2 = p.mul(h);
		Element p2 = IDu.duplicate().add(IDu0.duplicate().negate());
		Element temp2 = c0_2.duplicate().powZn(p2.duplicate().invert());
		Element re =  pk.getP().pairing(ProcessD2(null), temp2);
		if(in!=null)
		System.out.println("ProcessB:"+in.equals(re));
		return re;
	}
	
	public Element ProcessC(Element in){
		Element re = ProcessA(null).duplicate().mul(ProcessB(null));
		if(in!=null)
			System.out.println("ProcessC:"+ProcessD_down(null).equals(re));
		return re;
	}
	
	

}
