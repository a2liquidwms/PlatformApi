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
    
    public DbSet<Site> Sites { get; set; }
    public DbSet<UserSite> UserSites { get; set; }
    public DbSet<UserRoleAssignment> UserRoleAssignments { get; set; }
    
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
        
        // Define Site relationships
        builder.Entity<Site>()
            .HasOne(s => s.Tenant)
            .WithMany(t => t.Sites)
            .HasForeignKey(s => s.TenantId);
        
        // Define UserSite relationships
        builder.Entity<UserSite>()
            .HasKey(us => new { us.UserId, us.SiteId });

        builder.Entity<UserSite>()
            .HasOne(us => us.User)
            .WithMany(u => u.UserSites)
            .HasForeignKey(us => us.UserId);

        builder.Entity<UserSite>()
            .HasOne(us => us.Site)
            .WithMany(s => s.UserSites)
            .HasForeignKey(us => us.SiteId);
        
        // Define UserRoleAssignment relationships
        builder.Entity<UserRoleAssignment>()
            .HasKey(ura => ura.Id);

        builder.Entity<UserRoleAssignment>()
            .HasOne(ura => ura.User)
            .WithMany(u => u.UserRoleAssignments)
            .HasForeignKey(ura => ura.UserId);

        builder.Entity<UserRoleAssignment>()
            .HasOne(ura => ura.Role)
            .WithMany(r => r.UserRoleAssignments)
            .HasForeignKey(ura => ura.RoleId);

        builder.Entity<UserRoleAssignment>()
            .HasOne(ura => ura.Tenant)
            .WithMany()
            .HasForeignKey(ura => ura.TenantId);

        builder.Entity<UserRoleAssignment>()
            .HasOne(ura => ura.Site)
            .WithMany()
            .HasForeignKey(ura => ura.SiteId);
        
        
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
        
        // Configure Site
        builder.Entity<Site>()
            .Property(s => s.Id)
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


