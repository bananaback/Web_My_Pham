package orishop.models;

public enum RoleEnum {
    USER(1),
    ADMIN(2),
    SELLER(3),
    SHIPPER(4);

    private final int roleId;

    RoleEnum(int roleId) {
        this.roleId = roleId;
    }

    public int getRoleId() {
        return roleId;
    }

    // Method to get RoleEnum from roleId
    public static RoleEnum fromRoleId(int roleId) {
        for (RoleEnum role : RoleEnum.values()) {
            if (role.getRoleId() == roleId) {
                return role;
            }
        }
        return null; // Handle if roleId does not match any RoleEnum
    }
}
