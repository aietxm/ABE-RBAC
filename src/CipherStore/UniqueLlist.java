package CipherStore;

import java.util.ArrayList;

public class UniqueLlist<E> extends ArrayList<E>{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@Override
	public boolean add(E e){
		if(super.contains(e)) return true;
		
		return super.add(e);
		//return true;
		
	}

}
