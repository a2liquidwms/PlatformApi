using System.ComponentModel.DataAnnotations;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

public class UserTenant : BaseObject
{
    [StringLength(36)]
    public required string UserId { get; set; }
    public virtual AuthUser? User { get; set; }

    public required Guid TenantId { get; set; }
    public virtual Tenant? Tenant { get; set; }

    public ICollection<UserTenantRole>? UserTenantRoles { get; set; }
}

public class UserTenantRole : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [StringLength(36)]
    public required string UserId { get; set; }
    public required Guid TenantId { get; set; }

    [StringLength(36)]
    public required string UserRoleId { get; set; }
    public virtual AuthRole? UserRole { get; set; }

    public UserTenant? UserTenant { get; set; } // Link back to UserTenant
}

