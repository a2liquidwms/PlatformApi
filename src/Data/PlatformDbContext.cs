using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Data.SeedData;
using PlatformApi.Models;

namespace PlatformApi.Data;

public class PlatformDbContext : IdentityDbContext<AuthUser, IdentityRole<Guid>, Guid>
{
    public DbSet<Tenant> Tenants { get; set; }
    
    public DbSet<TenantConfig> TenantConfigs { get; set; }
    
    public DbSet<Site> Sites { get; set; }
    public new DbSet<UserRoles> UserRoles { get; set; }
    
    public DbSet<Permission> Permissions { get; set; }
    
    public DbSet<RolePermission> RolePermissions { get; set; }
    
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    
    public DbSet<UserInvitation> UserInvitations { get; set; }
    
    // Custom role system (separate from Identity roles)
    public new DbSet<Role> Roles { get; set; }

    public PlatformDbContext(DbContextOptions<PlatformDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Rename ASP.NET Identity tables to snake_case
        builder.Entity<AuthUser>().ToTable("users");
        builder.Entity<IdentityUserClaim<Guid>>().ToTable("user_claims");
        builder.Entity<IdentityUserLogin<Guid>>().ToTable("user_logins");
        builder.Entity<IdentityUserToken<Guid>>().ToTable("user_tokens");
        builder.Entity<IdentityRole<Guid>>().ToTable("asp_identity_roles"); // Identity roles (unused)
        builder.Entity<IdentityUserRole<Guid>>().ToTable("asp_identity_user_roles"); // Identity user roles (unused)
        builder.Entity<IdentityRoleClaim<Guid>>().ToTable("asp_identity_role_claims"); // Identity role claims (unused)
        
        
        
        // Define Site relationships
        builder.Entity<Site>()
            .HasOne(s => s.Tenant)
            .WithMany(t => t.Sites)
            .HasForeignKey(s => s.TenantId);
        

        
        // Define UserRoleAssignment relationships
        builder.Entity<UserRoles>()
            .HasKey(ura => ura.Id);

        builder.Entity<UserRoles>()
            .HasOne(ura => ura.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(ura => ura.UserId);

        builder.Entity<UserRoles>()
            .HasOne(ura => ura.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(ura => ura.RoleId);

        builder.Entity<UserRoles>()
            .HasOne(ura => ura.Tenant)
            .WithMany()
            .HasForeignKey(ura => ura.TenantId);

        builder.Entity<UserRoles>()
            .HasOne(ura => ura.Site)
            .WithMany()
            .HasForeignKey(ura => ura.SiteId);
        
        
        builder.Entity<RefreshToken>()
            .HasOne(rt => rt.User)
            .WithMany(u => u.RefreshTokens)
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        // Configure the relationship between Role and RolePermission
        builder.Entity<RolePermission>()
            .HasOne(rp => rp.Role)
            .WithMany(r => r.RolePermissions)
            .HasForeignKey(rp => rp.RoleId);
        
        // Also make sure the Permission relationship is properly configured
        builder.Entity<RolePermission>()
            .HasOne(rp => rp.Permission)
            .WithMany(p => p.RolePermissions)
            .HasForeignKey(rp => rp.PermissionCode);
        
        
        builder.Entity<UserInvitation>()
            .HasIndex(ui => ui.InvitationToken)
            .IsUnique();
        
        builder.Entity<UserInvitation>()
            .HasIndex(ui => ui.Email);
        
        // Custom role system configuration
        builder.Entity<Role>()
            .Property(r => r.IsSystemRole)
            .HasDefaultValue(false);
        
        SeedUserServiceData.SeedData(builder);
        
    }
}


