package Rbac;

import it.unisa.dia.gas.jpbc.Element;

/**
 * 系统主密钥
 * @author cirnotxm
 *
 */
public class RbacMainSecretKey {
	
	private Element alpha;
	private Element beta;
	private Element g_alpha;
	private RbacPublicKey publicKey;
	public Element getAlpha() {
		return alpha;
	}
	public void setAlpha(Element alpha) {
		this.alpha = alpha;
	}
	public Element getBeta() {
		return beta;
	}
	public void setBeta(Element beta) {
		this.beta = beta;
	}
	public Element getG_alpha() {
		return g_alpha;
	}
	public void setG_alpha(Element g_alpha) {
		this.g_alpha = g_alpha;
	}
	
	public RbacPublicKey getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(RbacPublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	
	
	public  RbacMainSecretKey(Element alpha, Element beta, Element g_alpha, RbacPublicKey publicKey){
		this.alpha = alpha;
		this.beta = beta;
		this.g_alpha = g_alpha;
		this.publicKey = publicKey;
		
		
	}
	@Override
	public String toString() {
		return "RbacMainSecretKey [alpha=" + alpha + ", beta=" + beta + ", g_alpha=" + g_alpha 
				+ ", publicKey=" + publicKey + "]";
	}
	
	
	
	
}
