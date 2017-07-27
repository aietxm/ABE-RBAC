package Rbac;

import java.io.ByteArrayInputStream;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;


/**
 * 系统公钥
 * @author cirnotxm
 *
 */
public class RbacPublicKey {
	
	private Element g; //G0
	
	private Element h;

	private Element h_beta; //G0
	
	private Element g_beta; 
	
	private Element g_beta_dup;
	
	private Element e_g_g_hat_alpha; //GT
	
	private Pairing p;
	 
	private String PairingDesc; // CurveDesc
	
	

	public Element getH() {
		return h;
	}

	public void setH(Element h) {
		this.h = h;
	}

	public Element getG() {
		return g;
	}

	public void setG(Element g) {
		this.g = g;
	}

	public Element getE_g_g_hat_alpha() {
		return e_g_g_hat_alpha;
	}

	public void setE_g_g_hat_alpha(Element e_g_g_hat_alpha) {
		this.e_g_g_hat_alpha = e_g_g_hat_alpha;
	}

	public Pairing getP() {
		if(p==null){
			PairingParameters params = new PropertiesParameters().load(new ByteArrayInputStream(PairingDesc.getBytes()));
            p = PairingFactory.getPairing(params);
		}
		return p;
	}

	public void setP(Pairing p) {
		this.p = p;
	}

	public String getPairingDesc() {
		return PairingDesc;
	}

	public void setPairingDesc(String pairigDesc) {
		PairingDesc = pairigDesc;
	}
	
	
	
	public Element getH_beta() {
		return h_beta;
	}

	public void setH_beta(Element h_beta) {
		this.h_beta = h_beta;
	}

	public Element getG_beta() {
		return g_beta;
	}

	public void setG_beta(Element g_beta) {
		this.g_beta = g_beta;
	}

	public Element getG_beta_dup() {
		return g_beta_dup;
	}

	public void setG_beta_dup(Element g_beta_dup) {
		this.g_beta_dup = g_beta_dup;
	}

	private RbacPublicKey(){
		
	}
	
	public static RbacPublicKey getInstance(String PairingDesc){
		RbacPublicKey instance = new RbacPublicKey();
		instance.setPairingDesc(PairingDesc);
		return instance;
		
	}

	@Override
	public String toString() {
		return "RbacPublicKey [g=" + g + ", h_beta=" + h_beta + ", g_beta=" + g_beta + ", g_beta_dup=" + g_beta_dup
				+ ", e_g_g_hat_alpha=" + e_g_g_hat_alpha + ", p=" + p + ", PairingDesc=" + PairingDesc + "]";
	}
	
	
	
	

	
}
