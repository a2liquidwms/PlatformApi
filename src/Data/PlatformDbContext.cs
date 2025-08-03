using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Data.SeedData;
using PlatformApi.Models;

namespace PlatformApi.Data;

public class PlatformDbContext : IdentityDbContext<AuthUser, AuthRole, string>
{
    public DbSet<Tenant> Tenants { get; set; }
    
    public DbSet<TenantConfig> TenantConfigs { get; set; }
    public DbSet<UserTenant> UserTenants { get; set; }
    public DbSet<UserTenantRole> UserTenantRoles { get; set; }
    
    public DbSet<Permission> Permissions { get; set; }
    
    public DbSet<RolePermission> RolePermissions { get; set; }
    
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    
    public DbSet<UserInvitation> UserInvitations { get; set; }

    public PlatformDbContext(DbContextOptions<PlatformDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Rename ASP.NET Identity tables to snake_case
        builder.Entity<AuthUser>().ToTable("users");
        builder.Entity<IdentityUserClaim<string>>().ToTable("user_claim");
        builder.Entity<IdentityUserLogin<string>>().ToTable("user_login");
        builder.Entity<IdentityUserToken<string>>().ToTable("user_token");
        builder.Entity<IdentityUserRole<string>>().ToTable("user_admin_role");
        builder.Entity<AuthRole>().ToTable("role");
        
        // Define Tenant/User relationship
        builder.Entity<UserTenant>()
            .HasKey(ut => new { ut.UserId, ut.TenantId });

        builder.Entity<UserTenant>()
            .HasOne(ut => ut.User)
            .WithMany(u => u.UserTenants)
            .HasForeignKey(ut => ut.UserId);
        
        // Define UserTenantRole relationships
        builder.Entity<UserTenantRole>()
            .HasKey(utr => utr.Id);

        builder.Entity<UserTenantRole>()
            .HasOne(utr => utr.UserTenant)
            .WithMany(ut => ut.UserTenantRoles)
            .HasForeignKey(utr => new { utr.UserId, utr.TenantId });

        builder.Entity<UserTenantRole>()
            .HasOne(utr => utr.UserRole)
            .WithMany(r => r.UserTenantRoles)
            .HasForeignKey(utr => utr.UserRoleId);
        
        
        builder.Entity<RefreshToken>()
            .HasOne(rt => rt.User)
            .WithMany(u => u.RefreshTokens)
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // Configure the relationship between AuthRole and RolePermission
        builder.Entity<RolePermission>()
            .HasOne(rp => rp.AuthRole)
            .WithMany(r => r.RolePermissions)
            .HasForeignKey(rp => rp.UserRoleId);
        
        // Also make sure the Permission relationship is properly configured
        builder.Entity<RolePermission>()
            .HasOne(rp => rp.Permission)
            .WithMany(p => p.RolePermissions)
            .HasForeignKey(rp => rp.PermissionCode);
        
        builder.Entity<Tenant>()
            .Property(t => t.Id)
            .HasDefaultValueSql("(UUID())");
        
        // Configure UserInvitation
        builder.Entity<UserInvitation>()
            .Property(ui => ui.Id)
            .HasDefaultValueSql("(UUID())");
        
        builder.Entity<UserInvitation>()
            .HasIndex(ui => ui.InvitationToken)
            .IsUnique();
        
        builder.Entity<UserInvitation>()
            .HasIndex(ui => ui.Email);
        
        
        SeedUserServiceData.SeedData(builder);
        
    }
}


