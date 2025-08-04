using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("user_tenants")]
[Index(nameof(TenantId), Name = "IX_user_tenant_tenant_id")]
[Index(nameof(UserId), Name = "IX_user_tenant_user_id")]
public class UserTenant : BaseObject
{
    public required Guid UserId { get; set; }
    public virtual AuthUser? User { get; set; }

    public required Guid TenantId { get; set; }
    public virtual Tenant? Tenant { get; set; }
}

