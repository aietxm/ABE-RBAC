package Rbac;

import it.unisa.dia.gas.jpbc.Element;

/**
 * Created by cirnotxm on 2017/6/8.
 */
public interface RBACModel {

    //初始化
    public RbacMainSecretKey setup();

    //创建角色
    public RoleCipher addRole(RbacMainSecretKey msk, Element IDr);

    //创建权限
    public SourceFileCipher addPermission(Element IDf, boolean isNew, RbacMainSecretKey msk);

    //角色权限指派
    public FileCipher grantPermission(Element IDr, Element IDf, RbacMainSecretKey msk);

    //权限撤销
    public FileCipher revokePermission(Element IDr, Element IDf, RbacMainSecretKey msk);

    //创建用户
    public UserSecret addUser(Element IDu, RbacMainSecretKey msk);

    //用户角色指派
    public RoleUserSecret assignUser(Element IDu, Element IDr, RbacMainSecretKey msk);

    //
    public void deAssignUser(Element IDu, Element IDr, RbacMainSecretKey msk);

    public void deleteUser(Element IDu, RbacMainSecretKey msk);

    public void deleteRole(Element IDr, RbacMainSecretKey msk);

    public boolean checkAccess(Element IDu, Element IDf, RbacMainSecretKey msk, UserSecret userSecret);



}
