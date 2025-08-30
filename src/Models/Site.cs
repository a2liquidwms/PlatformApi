using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using PlatformStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("sites")]
[Index(nameof(TenantId), Name = "IX_site_tenant_id")]
[Index(nameof(Name), nameof(TenantId), Name = "IX_site_name_tenant_unique", IsUnique = true)]
[Index(nameof(Code), nameof(TenantId), Name = "IX_site_code_tenant_unique", IsUnique = true)]
public class Site : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    [StringLength(25)]
    public required string Code { get; set; }
    
    [Required]
    [StringLength(100)]
    public required string Name { get; set; }
    
    [Required]
    public required Guid TenantId { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public virtual Tenant? Tenant { get; set; }
    
}