using Microsoft.EntityFrameworkCore;
using PlatformStarterCommon.Core.Common.Constants;
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
            new Role() { Id = Guid.Parse(AuthApiConstants.DEFAULT_USERS), Name = "DefaultUser", Scope = RoleScope.Default, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Role() { Id = Guid.Parse(AuthApiConstants.TENANT_ADMIN_ROLE), Name = "TenantAdmin", Scope = RoleScope.Tenant, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Role() { Id = Guid.Parse(AuthApiConstants.SITE_ADMIN_ROLE), Name = "SiteAdmin", Scope = RoleScope.Site, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)}
        );
        
        modelBuilder.Entity<Permission>().HasData(
            new Permission { Code = RolePermissionConstants.DefaultAll, Description = "Default Basic Access Permission", RoleScope = Models.RoleScope.Default, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SysAdminManagePermissions, Description = "SysAdmin Manage Permissions", RoleScope = Models.RoleScope.Internal, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SysAdminManageUsers, Description = "SysAdmin Manage Users", RoleScope = Models.RoleScope.Internal, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SysAdminManageTenants, Description = "SysAdmin Manage Tenants", RoleScope = Models.RoleScope.Internal, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.TenantManageUsers, Description = "Tenant Manage Users", RoleScope = Models.RoleScope.Tenant, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.TenantManageConfig, Description = "Tenant Manage Config", RoleScope = Models.RoleScope.Tenant, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SiteManageConfig, Description = "Site Manage Config", RoleScope = Models.RoleScope.Site, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)},
            new Permission { Code = RolePermissionConstants.SiteManagerUsers, Description = "Site Manage Users", RoleScope = Models.RoleScope.Site, CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)}
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
            },
            new RolePermission
            {
                Id = Guid.Parse("7ee43803-5d35-425f-8392-f4de1df37e05"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.SysAdminManageUsers,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            },
            new RolePermission
            {
                Id = Guid.Parse("311a22a5-1100-4917-83e6-6bf7994493dd"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.SUPERADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.SysAdminManageTenants,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            }
        );
        
        //tenant
        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                Id = Guid.Parse("70a47010-46a0-4a87-9f0e-b0326316e580"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.TENANT_ADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.TenantManageUsers,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            },
            new RolePermission
            {
                Id = Guid.Parse("1237a8e7-96cc-47d4-a2f3-9d66fe3e3f6d"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.TENANT_ADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.TenantManageConfig,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            }
        );
        
        //Site
        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                Id = Guid.Parse("936456cc-8ce2-4bd5-9ba4-1b79d271fe01"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.SITE_ADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.SiteManageConfig,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            },
            new RolePermission
            {
                Id = Guid.Parse("d22bec2f-9a68-4ecf-aa81-c550f57acaa9"), // Unique ID
                RoleId = Guid.Parse(AuthApiConstants.SITE_ADMIN_ROLE), // Matches the seeded role
                PermissionCode = RolePermissionConstants.SiteManagerUsers,
                CreateDate = new DateTime(2024, 11, 21, 0, 0, 0, DateTimeKind.Utc)
            }
        );
    }
    
}


