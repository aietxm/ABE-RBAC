package Utils;

import CipherStore.*;
import Rbac.*;
import it.unisa.dia.gas.jpbc.Element;

public class TestCase {

	private static boolean debug=false;
	public static void main(String[] args) {


		//用户-角色-权限正常访问
		test1();
		//发生用户-角色撤销
		test2();
		//发生角色权限撤销
		test3();

	}

	private static void test1(){

		RbacAbe abe = new RbacAbe();
		RbacMainSecretKey msk = abe.setup();

		Element IDr = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		Element IDu = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		Element IDf = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");

		abe.addRole(msk, IDr);

		abe.addPermission(IDf, true, msk);

		abe.grantPermission(IDr, IDf, msk);

		UserSecret userSecret = abe.addUser(IDu, msk);

		abe.assignUser(IDu, IDr, msk);

		System.out.println("###Test1：");

		if (abe.checkAccess(IDu, IDf, msk, userSecret)) {
			System.out.println("You can Access this file!");
		}




		if (debug) {
			System.out.println("IDr=" + IDr);
			System.out.println("IDu=" + IDu);
			System.out.println("IDf=" + IDf);
//            System.out.println(roleCipher);
//            System.out.println(sourceFileCipher);
//            System.out.println(fileCipher);
//            System.out.println(userSecret);
//            System.out.println(roleUserSecret);
			System.out.println("RUL=" + RoleUserList.getRUL(IDr));
			System.out.println("URL=" + UserRoleList.getURL(IDu));
			System.out.println("RFL=" + RoleFileList.getRFL(IDr));
			System.out.println("FRL=" + FileRoleList.getFRL(IDf));
			System.out.println("RURL=" + RevokeUserRoleList.getRURL(IDr));
		}


	}

	private static void test2(){
		RbacAbe abe = new RbacAbe();
		RbacMainSecretKey msk = abe.setup();

		Element IDr1 = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		//Element IDr2 = RbacUtils.GenerateID(msk.getPublicKey().getP(),"ZR");
		Element IDu1 = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		Element IDu2 = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		Element IDf = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");

		RoleCipher roleCipher1 = abe.addRole(msk, IDr1);
		//RoleCipher roleCipher2 = abe.addRole(msk,IDr2);

		SourceFileCipher sourceFileCipher = abe.addPermission(IDf, true, msk);
		RbacUtils.SourceFileCipherSave(IDf,sourceFileCipher);

		FileCipher fileCipher1 = abe.grantPermission(IDr1, IDf, msk);
		RbacUtils.fileCipherSave(IDf,fileCipher1);
		// FileCipher fileCipher2 = abe.grantPermission(IDr2, IDf, msk, sourceFileCipher);
		// RbacUtils.fileCipherSave(IDf,fileCipher2);


		UserSecret userSecret1 = abe.addUser(IDu1, msk);
		UserSecret userSecret2 = abe.addUser(IDu2, msk);

		RoleUserSecret roleUserSecret1 = abe.assignUser(IDu1, IDr1, msk);
		RbacUtils.RoleUserSecretSave(IDu1,IDr1,roleUserSecret1);
		RoleUserSecret roleUserSecret2 = abe.assignUser(IDu2, IDr1, msk);
		RbacUtils.RoleUserSecretSave(IDu2,IDr1,roleUserSecret2);

		System.out.println("###Test2：");

		if (abe.checkAccess(IDu1, IDf, msk, userSecret1)) {
			System.out.println("IDu1 can Access IDf!");
		}
		if (abe.checkAccess(IDu2, IDf, msk, userSecret2)) {
			System.out.println("IDu2 can Access IDf!");
		}

		abe.deAssignUser(IDu2,IDr1,msk);

		if (abe.checkAccess(IDu1, IDf, msk, userSecret1)) {
			System.out.println("IDu1 can Access IDf!");
		}

		if (abe.checkAccess(IDu2, IDf, msk, userSecret2)) {
			System.out.println("IDu2 can Access IDf!");
		}
	}

	private static void test3(){
		RbacAbe abe = new RbacAbe();
		RbacMainSecretKey msk = abe.setup();

		Element IDr1 = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		Element IDr2 = RbacUtils.GenerateID(msk.getPublicKey().getP(),"ZR");
		Element IDu1 = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		Element IDu2 = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
		Element IDf = RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");

		long  start = System.currentTimeMillis();
		abe.addRole(msk, IDr1);
		long end = System.currentTimeMillis();
		abe.addRole(msk,IDr2);

		SourceFileCipher sourceFileCipher = abe.addPermission(IDf, true, msk);
		RbacUtils.SourceFileCipherSave(IDf,sourceFileCipher);
		start = System.currentTimeMillis();
		FileCipher fileCipher1 = abe.grantPermission(IDr1, IDf, msk);
		end = System.currentTimeMillis();
		RbacUtils.fileCipherSave(IDf,fileCipher1);
		FileCipher fileCipher2 = abe.grantPermission(IDr2, IDf, msk);
		RbacUtils.fileCipherSave(IDf,fileCipher2);

		start = System.currentTimeMillis();
		UserSecret userSecret1 = abe.addUser(IDu1, msk);
		end = System.currentTimeMillis();
		UserSecret userSecret2 = abe.addUser(IDu2, msk);

		start = System.currentTimeMillis();
		RoleUserSecret roleUserSecret1 = abe.assignUser(IDu1, IDr1, msk);
		end = System.currentTimeMillis();
		RbacUtils.RoleUserSecretSave(IDu1,IDr1,roleUserSecret1);
		RoleUserSecret roleUserSecret2 = abe.assignUser(IDu2, IDr2, msk);
		RbacUtils.RoleUserSecretSave(IDu1,IDr2,roleUserSecret2);

		System.out.println("###Test3：");


		if (abe.checkAccess(IDu1, IDf, msk, userSecret1)) {
			System.out.println("IDr1 can Access IDf!");
		}
		if (abe.checkAccess(IDu1, IDf, msk, userSecret1)) {
			System.out.println("IDr2 can Access IDf!");
		}

		FileCipher newFileC =  abe.revokePermission(IDr2,IDf,msk);


		if (abe.checkAccess(IDu1, IDf, msk, userSecret1)) {
			System.out.println("IDu1 can Access IDf!");
		}

		if (abe.checkAccess(IDu2, IDf, msk, userSecret2)) {
			System.out.println("IDu2 can Access IDf!");
		}

	}

	public void test4(int num_user, int num_role,int num_file){
		Element[] ID_u = new Element[num_user];
		Element[] ID_r =  new Element[num_role];
		Element[] ID_f =  new Element[num_file];
		RbacAbe abe = new RbacAbe();
		RbacMainSecretKey msk = abe.setup();
		UserSecret user0 = null;
		for(int i=0;i<num_user;i++){
			Element ID=RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
			if(i==0) user0 = abe.addUser(ID,msk);
			ID_u[i]=ID;
		}

		for(int j=0;j<num_role;j++){
			Element ID=RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
			abe.addRole(msk,ID);
			ID_r[j]=ID;
			for(int in=0;in<(num_user/num_role);in++){
				abe.assignUser(ID_u[in],ID,msk);
			}
		}
		for(int x=0;x<num_file;x++){
			Element ID=RbacUtils.GenerateID(msk.getPublicKey().getP(), "ZR");
			abe.addPermission(ID,true,msk);
			ID_f[x]=ID;
			for(int in=0;in<(num_role/2);in++){
				abe.grantPermission(ID_r[in],ID,msk);
			}
		}

		long start = System.currentTimeMillis();
		abe.deAssignUser(ID_u[0], ID_r[0], msk);
		long end = System.currentTimeMillis();
		System.out.println("deAssignUser cost:"+(end-start)+"ms");

		start = System.currentTimeMillis();
		if (abe.checkAccess(ID_u[0], ID_f[0], msk, user0)) {
			System.out.println("IDr1 can Access IDf!");
		}
		end = System.currentTimeMillis();
		System.out.println("checkAccess cost:"+(end-start)+"ms");



	}


	

}
