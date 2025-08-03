using Microsoft.EntityFrameworkCore;
using PlatformApi.Models;

namespace PlatformApi.Data.SeedData;

public static class SeedUserServiceData
{
    //create function for each object
    public static void SeedData(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Tenant>().HasData(
            new Tenant { Id = Guid.Parse("baab4de5-fe68-4940-996e-5914f8234863"),Code = "Default", Name = "Test Tenant", SubDomain = "default", CreateDate = new DateTime(2024, 11, 21)}
        );
        
        modelBuilder.Entity<AuthRole>().HasData(
            new AuthRole() { Id = AuthApiConstants.GUEST_ROLE, Name = "Guest", NormalizedName = "Guest", CreateDate = new DateTime(2024, 11, 21)}
        );
        
        modelBuilder.Entity<Permission>().HasData(
            new Permission { Code = "default:all", Description = "Default Permission", IsDefaultFlg = true, CreateDate = new DateTime(2024, 11, 21)}
        );
        
        // Add RolePermission data
        modelBuilder.Entity<RolePermission>().HasData(
            new RolePermission
            {
                Id = Guid.Parse("d9b1d7aa-c58e-4a9f-9f8e-b25d7d707e44"), // Unique ID
                UserRoleId = AuthApiConstants.GUEST_ROLE, // Matches the seeded role
                PermissionCode = "default:all", // Matches the seeded permission
                CreateDate = new DateTime(2024, 11, 21)
            }
        );
    }
    
}


