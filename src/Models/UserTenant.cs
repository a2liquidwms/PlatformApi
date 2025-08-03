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
}

