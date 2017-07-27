package Rbac;

import javax.crypto.CipherInputStream;

import it.unisa.dia.gas.jpbc.Element;

public class SourceFileCipher {
	
	private Element Kf;
	
	private CipherInputStream CTsf;

	public Element getKf() {
		return Kf;
	}

	public void setKf(Element kf) {
		Kf = kf;
	}

	public CipherInputStream getCTsf() {
		return CTsf;
	}

	public void setCTsf(CipherInputStream cTsf) {
		CTsf = cTsf;
	}

	@Override
	public String toString() {
		return "SourceFileCipher [Kf=" + Kf + ", CTsf=" + CTsf + "]";
	}
	
	
	

}
