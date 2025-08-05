using Microsoft.EntityFrameworkCore;
using PlatformApi.Models;

namespace PlatformApi.Data.SeedData;

public static class SeedUserServiceData
{
    //create function for each object
    public static void SeedData(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Tenant>().HasData(
            new Tenant { Id = Guid.Parse("baab4de5-fe68-4940-996e-5914f8234863"),Code = "Default", Name = "Test Tenant", SubDomain = "default", CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)}
        );
        
        modelBuilder.Entity<Role>().HasData(
            new Role() { Id = Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE), Name = "SuperAdmin", Scope = RoleScope.Internal, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Role() { Id = Guid.Parse(AuthApiConstants.DEFAULT_USERS), Name = "DefaultUser", Scope = RoleScope.Default, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)}
        );
        
        modelBuilder.Entity<Permission>().HasData(
            new Permission { Code = RolePermissionConstants.DefaultAll, Description = "Default Basic Access Permission", ApplicableScopes = RoleScope.Default, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SysAdminManagePermissions, Description = "SysAdmin Manage Permissions", ApplicableScopes = RoleScope.Internal, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SysAdminManageUsers, Description = "SysAdmin Manage Users", ApplicableScopes = RoleScope.Internal, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SysAdminManageTenants, Description = "SysAdmin Manage Tenants", ApplicableScopes = RoleScope.Internal, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)}
        );
        
        // Add RolePermission data
        // Default role permissions
        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                Id = Guid.Parse("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
                RoleId = Guid.Parse(AuthApiConstants.DEFAULT_USERS), 
                PermissionCode = RolePermissionConstants.DefaultAll,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            }
        );
        
        // SuperAdmin role permissions
        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                Id = Guid.Parse("c08a610d-f07d-436e-839e-31f5b6ffc87d"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.SysAdminManagePermissions,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            }
        );
        
        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                Id = Guid.Parse("7ee43803-5d35-425f-8392-f4de1df37e05"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.SysAdminManageUsers,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            }
        );
        
        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                Id = Guid.Parse("311a22a5-1100-4917-83e6-6bf7994493dd"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.SysAdminManageTenants,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            }
        );
    }
    
}


