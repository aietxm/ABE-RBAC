package Rbac;

import java.security.SecureRandom;
import java.util.List;
import javax.crypto.CipherInputStream;

import AesEncrypt.AesEncryption;
import CipherStore.*;
import Utils.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;


/**
 * ABE 实现 RBAC
 *
 * @author cirnotxm
 */
public class RbacAbe implements RBACModel {

    static boolean debug = false;

    DataValid datavalid = new DataValid();


    public RbacMainSecretKey setup() {

        RbacPublicKey publicKey = RbacPublicKey.getInstance(AbeSettings.curveParams);
        Pairing pairing = publicKey.getP();

        // 配置公钥参数
        Element g = pairing.getG1().newRandomElement();
        Element h = pairing.getG1().newRandomElement();
        Element alpha = pairing.getZr().newRandomElement();
        Element beta = pairing.getZr().newRandomElement();

        publicKey.setG(g);
        publicKey.setH(h);
        Element g_beta = g.duplicate().powZn(beta); // g**beta
        publicKey.setG_beta(g_beta);
        publicKey.setG_beta_dup(g_beta.duplicate().powZn(beta)); // g**beta2
        publicKey.setH_beta(h.duplicate().powZn(beta)); // h**beta
        Element g_g = pairing.pairing(g, g); // e(g,g)
        Element g_alpha = g.duplicate().powZn(alpha);// g**alpha
        publicKey.setE_g_g_hat_alpha(g_g.duplicate().powZn(alpha));// e(g,g)**alpha

        // 配置系统主密钥
        RbacMainSecretKey msk = new RbacMainSecretKey(alpha, beta, g_alpha, publicKey);

        return msk;

    }

    /**
     * 创建角色
     *
     * @param msk
     * @return
     */
    public RoleCipher addRole(RbacMainSecretKey msk, Element IDr) {
        RoleCipher roleCipher = new RoleCipher();
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();
        // 初始化列表
        Element IDu0 = RbacUtils.GenerateID(pairing, "ZR");
        RevokeUserRoleList.initList(IDr, IDu0);
        RoleFileList.initList(IDr, null);

        Element Vr = RbacUtils.GenerateID(pairing, "ZR");
        Element Kr = RbacUtils.GenerateID(pairing, "GT");


        Element hashKr = RbacUtils.elementZRFromString(Kr.toBytes(), pairing);
        // 计算密文
        Element Kr_inv = hashKr.duplicate().invert(); // 1/Kr
        roleCipher.setC1(publicKey.getG().duplicate().powZn(Kr_inv)); // g**1/Kr
        Element IDr2 = RbacUtils.elementG2FromString(IDr.toBytes(), pairing); // H(IDr)
        roleCipher.setC2(IDr2.duplicate().powZn(Kr_inv));// H(IDr)**1/Kr
        Element temp = publicKey.getE_g_g_hat_alpha().duplicate().powZn(Vr);// e(g,g)**alpha**Vr
        roleCipher.setC(Kr.duplicate().mul(temp));// Kr*e(g,g)**alpha**Vr
        roleCipher.setC0(publicKey.getG().duplicate().powZn(Vr)); // g**Vr
        // Vr0 = Vr
        roleCipher.setVr(Vr);
        if (debug) {
            datavalid.setVr(Vr);
            datavalid.setIDr(IDr);
            datavalid.setIDu0(IDu0);
            System.out.println("Original Kr=" + Kr);
        }
        Element C0_1 = (publicKey.getG_beta().duplicate().powZn(Vr)); // g**beta**Vr

        Element p1 = publicKey.getG_beta_dup().duplicate().powZn(Vr.duplicate().mul(IDu0)); // g**(beta2*Vr*IDu0)
        Element p2 = publicKey.getH_beta().duplicate().powZn(Vr);// h**beta**Vr
        Element C0_2 = (p1.duplicate().mul(p2));

        roleCipher.setCR_2(C0_1, C0_2);

        RbacUtils.RoleCipherSave(IDr,roleCipher);

        return roleCipher;

        // TODO 保存与IDr相关的Kr，Vr，Vr0保存

    }

    /**
     * 对于资源创建权限
     *
     * @param IDf
     * @param isNew
     * @param msk
     * @return
     */
    public SourceFileCipher addPermission(Element IDf, boolean isNew, RbacMainSecretKey msk) {
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();
        SourceFileCipher sourceFileCipher = new SourceFileCipher();
        Element Kf = RbacUtils.GenerateID(pairing, "GT");
        //System.out.println("Original Kf=" + Kf);
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        CipherInputStream CTsf = null;
        try {
            CTsf = AesEncryption.encrypt(Kf.toBytes(), null, iv, RbacUtils.getFile(IDf));
        } catch (Exception e) {
            // TODO Auto-generated catch block
            System.out.println("AES Error!");
        }
        if (isNew) {
            FileRoleList.initList(IDf, null);

        }
        sourceFileCipher.setCTsf(CTsf);
        sourceFileCipher.setKf(Kf);
        RbacUtils.SourceFileCipherSave(IDf,sourceFileCipher);
        return sourceFileCipher;
    }

    /**
     * 用于角色/权限指派以及撤销时加密
     *
     * @param IDr
     * @param Sf
     * @param Kf
     * @param isNewOeReencrypt
     * @param msk
     * @return
     */
    private FileCipher Encrypt(Element IDr, Element Sf, Element Kf, boolean isNewOeReencrypt, RbacMainSecretKey msk) {
        FileCipher fileCipher = new FileCipher();
        RbacPublicKey publicKey = msk.getPublicKey();
        Element IDr2 = RbacUtils.elementG2FromString(IDr.toBytes(), publicKey.getP());
        Element CT_rf = IDr2.duplicate().powZn(Sf);
        fileCipher.setCT_rf(IDr, CT_rf);
        if (isNewOeReencrypt) {
            Element c3 = publicKey.getG().duplicate().powZn(Sf);
            Element c4 = publicKey.getE_g_g_hat_alpha().duplicate().powZn(Sf).duplicate().mul(Kf);
            Element c5 = publicKey.getG_beta().duplicate().powZn(Sf);
            fileCipher.setC3(c3);
            fileCipher.setC4(c4);
            fileCipher.setC5(c5);
        }
        fileCipher.setSf(Sf);
        return fileCipher;

    }

    /**
     * 角色/权限指派
     *
     * @param IDr
     * @param IDf
     * @param msk
     * @return
     */
    public FileCipher grantPermission(Element IDr, Element IDf, RbacMainSecretKey msk) {
        FileCipher CTf = null;
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();
        // 该资源不是新资源
         SourceFileCipher sourceFileCipher =RbacUtils.getSourceFileCipherByIDf(IDf);
        if (sourceFileCipher == null) {
            sourceFileCipher = addPermission(IDf, true, msk);
        }

        if (FileRoleList.contains(IDf) && FileRoleList.getFRL(IDf).size() > 0) {

            CTf = RbacUtils.getFileCipherByIDf(IDf);
            FileCipher CT2 = Encrypt(IDr, CTf.getSf(), sourceFileCipher.getKf(), false, msk);
            CTf.union(CT2);

        } else {
            Element Sf = RbacUtils.GenerateID(pairing, "ZR");
            CTf = Encrypt(IDr, Sf, sourceFileCipher.getKf(), true, msk);

        }

        RoleFileList.getRFL(IDr).add(IDf);
        FileRoleList.getFRL(IDf).add(IDr);
        RbacUtils.fileCipherSave(IDf,CTf);
        return CTf;

    }

    /**
     * 角色权限撤销
     *
     * @param IDr
     * @param IDf
     * @param msk
     * @return
     */
    public FileCipher revokePermission(Element IDr, Element IDf, RbacMainSecretKey msk) {
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();
        // 更新列表
        FileRoleList.getFRL(IDf).remove(IDr);
        RoleFileList.getRFL(IDr).remove(IDf);

        SourceFileCipher newCT = addPermission(IDf, false, msk);
        Element Kf_1 = newCT.getKf().duplicate();
        FileCipher CT_1 = null;

        List<Element> FRL = FileRoleList.getFRL(IDf);
        System.out.println("FRL size="+ FRL.size());
        if (FRL.size() > 0) {
            Element Sf_1 = RbacUtils.GenerateID(pairing, "ZR");
            CT_1 = Encrypt(FRL.get(0), Sf_1, Kf_1, true, msk);
            for (int i = 1; i < FRL.size(); i++) {
                FileCipher CT_i = Encrypt(FRL.get(i), Sf_1, Kf_1, false, msk);
                CT_1.union(CT_i);
            }

        }

        RbacUtils.fileCipherSave(IDf,CT_1);

        return CT_1;

    }

    /**
     * 创建用户
     *
     * @param IDu
     * @param msk
     * @return
     */
    public UserSecret addUser(Element IDu, RbacMainSecretKey msk) {
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();

        Element t = RbacUtils.GenerateID(pairing, "ZR");
        Element d0 = msk.getG_alpha().duplicate().mul(publicKey.getG_beta_dup().duplicate().powZn(t));
        Element p = publicKey.getG_beta().duplicate().powZn(IDu).mul(publicKey.getH());
        Element d1 = p.duplicate().powZn(t);
        Element d2 = publicKey.getG().duplicate().powZn(t.duplicate().negate());

        UserRoleList.initList(IDu, null);
        return new UserSecret(d0, d1, d2);

    }

    /**
     * 为用户指派角色
     *
     * @param IDu
     * @param IDr
     * @param msk
     * @return
     */
    public RoleUserSecret assignUser(Element IDu, Element IDr, RbacMainSecretKey msk) {
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();
        RoleUserList.initList(IDr, IDu);
        UserRoleList.initList(IDu, IDr);
        RoleCipher roleCipher = RbacUtils.getRoleCipherByIDr(IDr);

        Element r = RbacUtils.GenerateID(pairing, "ZR");
        Element w = RbacUtils.GenerateID(pairing, "ZR");

        Element g_w = publicKey.getG().duplicate().powZn(w);
        Element beta_inv = msk.getBeta().duplicate().invert();
        // Element d3_p =
        // msk.getBeta().duplicate().invert().mulZn(r.duplicate().add(w));
        // Element d3 = publicKey.getG().duplicate().powZn(d3_p.duplicate());
        Element d3 = msk.getG_alpha().duplicate().mul(g_w).powZn(beta_inv);

        Element dr_1 = roleCipher.getC1().duplicate().powZn(w);
        Element dr_2 = roleCipher.getC2().duplicate().powZn(r);
        Element d_r = dr_1.duplicate().mul(dr_2);

        Element d_r_1 = roleCipher.getC1().duplicate().powZn(r);

        int version = 0;
        RoleUserSecret re= new RoleUserSecret(d3, d_r, d_r_1, version);
        RbacUtils.RoleUserSecretSave(IDu,IDr,re);
        return re;
    }

    public void deAssignUser(Element IDu, Element IDr, RbacMainSecretKey msk) {
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();
        int n = RevokeUserRoleList.getRURL(IDr).size();
        RevokeUserRoleList.getRURL(IDr).add(IDu);
        RoleUserList.getRUL(IDr).remove(IDu);
        UserRoleList.getURL(IDu).remove(IDr);
        Element IDu_0 = RevokeUserRoleList.getRURL(IDr).get(0);

        Element Vr_n = RbacUtils.GenerateID(pairing, "ZR");
        Element Kr_n = RbacUtils.GenerateID(pairing, "GT");

       // System.out.println("New Kr="+Kr_n);

        RoleCipher roleCipher = RbacUtils.getRoleCipherByIDr(IDr);

        Element Vr = roleCipher.getVr().duplicate().add(Vr_n);
        Element hashKr = RbacUtils.elementZRFromString(Kr_n.toBytes(),pairing);
        Element Kr_n_inv = hashKr.duplicate().invert();
        Element c1_n = publicKey.getG().duplicate().powZn(Kr_n_inv);
        Element IDr2 = RbacUtils.elementG2FromString(IDr.toBytes(),pairing);
        Element c2_n = IDr2.duplicate().powZn(Kr_n_inv);

        Element c_n = Kr_n.duplicate().mul(publicKey.getE_g_g_hat_alpha().duplicate().powZn(Vr));
        Element c0_n = publicKey.getG().duplicate().powZn(Vr);

        Element cn_1 = publicKey.getG_beta().duplicate().powZn(Vr_n);
        Element cn_2 = publicKey.getG_beta_dup().duplicate().powZn(IDu).mul(publicKey.getH_beta());
        roleCipher.setC1(c1_n);
        roleCipher.setC2(c2_n);
        roleCipher.setC(c_n);
        roleCipher.setC0(c0_n);
        roleCipher.setCR_2(cn_1, cn_2.duplicate().powZn(Vr_n));
        roleCipher.setVr(Vr);

        // 为每个用户重新指派角色
        System.out.println("RUL size="+RoleUserList.getRUL(IDr).size());
        for (Element item : RoleUserList.getRUL(IDr)) {

            RoleUserSecret roleUserSecret = RbacUtils.getRoleUserSecret(item,IDr);
            if(roleUserSecret==null) {
                roleUserSecret = new RoleUserSecret();
            }

            Element r = RbacUtils.GenerateID(pairing, "ZR");
            Element w = RbacUtils.GenerateID(pairing, "ZR");

            Element g_w = publicKey.getG().duplicate().powZn(w);
            Element beta_inv = msk.getBeta().duplicate().invert();
            Element d3 = msk.getG_alpha().duplicate().mul(g_w).powZn(beta_inv);

            Element dr_1 = roleCipher.getC1().duplicate().powZn(w);
            Element dr_2 = roleCipher.getC2().duplicate().powZn(r);
            Element d_r = dr_1.duplicate().mul(dr_2);

            Element d_r_1 = roleCipher.getC1().duplicate().powZn(r);

            roleUserSecret.setD3(d3);
            roleUserSecret.setD_r(d_r);
            roleUserSecret.setD_r_1(d_r_1);
            int version = roleUserSecret.getVersion()+1;
            roleUserSecret.setVersion(version);

            RbacUtils.RoleUserSecretSave(item,IDr,roleUserSecret);

        }

        RbacUtils.RoleCipherSave(IDr,roleCipher);

    }

    /**
     * 删除用户
     *
     * @param IDu
     * @param msk
     */
    public void deleteUser(Element IDu, RbacMainSecretKey msk) {
        for (Element item : UserRoleList.getURL(IDu)) {
            // RbacUtils.getRoleCipherByIDr(item);
            deAssignUser(IDu, item, msk);
        }
    }

    /**
     * 删除角色
     *
     * @param IDr
     * @param msk
     */
    public void deleteRole(Element IDr, RbacMainSecretKey msk) {
        for (Element item : RoleFileList.getRFL(IDr)) {
            revokePermission(IDr, item, msk);
        }
    }

    /**
     * 授权决策
     *
     * @param IDu
     * @param IDf
     * @param msk
     */
    public boolean checkAccess(Element IDu, Element IDf, RbacMainSecretKey msk, UserSecret userSecret) {
        RbacPublicKey publicKey = msk.getPublicKey();
        Pairing pairing = publicKey.getP();
        List<Element> URL = UserRoleList.getURL(IDu);
        List<Element> FRL = FileRoleList.getFRL(IDf);
        URL.retainAll(FRL);
        if (URL == null || URL.size() == 0)
            return false;
        Element IDr = URL.get(0);
        List<Element> RURL = RevokeUserRoleList.getRURL(IDr);
        RoleCipher roleCipher = RbacUtils.getRoleCipherByIDr(IDr);
        SourceFileCipher sourceFileCipher = RbacUtils.getSourceFileCipherByIDf(IDf);
        FileCipher fileCipher = RbacUtils.getFileCipherByIDf(IDf);
        RoleUserSecret roleUserSecret = RbacUtils.getRoleUserSecret(IDu,IDr);

        if (roleCipher == null || sourceFileCipher == null || fileCipher == null)
            return false;

        // 进行计算

        Element temp1 = null;
        Element temp2 = null;
        for (int i = 0; i < RURL.size(); i++) {
            Pair<Element, Element> CR_2 = roleCipher.getCR_2(i);
            if (debug) {
                datavalid.ProcessC0_1(CR_2.getFirst());
                datavalid.ProcessC0_2(CR_2.getSecond());
            }
            Element pa = IDu.duplicate().add(RURL.get(i).duplicate().negate()).invert();
            Element a = CR_2.getFirst().duplicate().powZn(pa);
            Element b = CR_2.getSecond().duplicate().powZn(pa);
            if (i == 0) {
                temp1 = a;
                temp2 = b;
            } else {
               temp1.mul(a);
               temp2.mul(b);
            }
        }
        if (debug) {
            datavalid.ProcessD1(userSecret.getD1());
            datavalid.ProcessD2(userSecret.getD2());
            datavalid.ProcessPK(publicKey);
            datavalid.ProcessC0(roleCipher.getC0());
            datavalid.ProcessD0(userSecret.getD0());
        }

        // D' 计算
        Element down1 = pairing.pairing(userSecret.getD1(), temp1);
        Element down2 = pairing.pairing(temp2, userSecret.getD2());
        Element up = pairing.pairing(roleCipher.getC0(), userSecret.getD0());
        Element down = down1.duplicate().mul(down2);
        if (debug) {
            datavalid.ProcessA(down1);
            datavalid.ProcessB(down2);
            datavalid.ProcessD_down(down);
        }
        Element d_1 = up.duplicate().mul(down.duplicate().invert());


        // Kr 计算
        Element Kr = roleCipher.getC().duplicate().mul(d_1.duplicate().invert());
        //System.out.println("Kr=" + Kr);
        Kr = RbacUtils.elementZRFromString(Kr.toBytes(), pairing);
        // A 计算
        Element up1 = pairing.pairing(roleUserSecret.getD_r().duplicate().powZn(Kr), fileCipher.getC3());
        Element down3 = pairing.pairing(roleUserSecret.getD_r_1().duplicate().powZn(Kr), fileCipher.getCT_rf(IDr));
        Element A = up1.duplicate().mul(down3.duplicate().invert());
        // Kf 计算
        Element down4 = pairing.pairing(fileCipher.getC5(), roleUserSecret.getD3()).mul(A.invert());
        Element Kf = fileCipher.getC4().duplicate().mul(down4.duplicate().invert());
        //System.out.println("Kf=" + Kf);
        if (sourceFileCipher.getKf().equals(Kf)) {
           // System.out.println("Kf is OK!");
            return true;
        }else{
            System.out.println("Kf is error!");
        }
        // try {
        // DataInputStream stream = new
        // DataInputStream(sourceFileCipher.getCTsf());
        // int ivLength = stream.readInt();
        // byte[] iv = new byte[ivLength];
        // stream.readFully(iv);
        // System.out.println( AesEncryption.decrypt(Kf.toBytes(), null, iv,
        // sourceFileCipher.getCTsf()));
        // } catch (Exception e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // return false;
        // }

        return false;

    }




}
