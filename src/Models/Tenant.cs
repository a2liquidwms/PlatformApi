using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Index(nameof(Code), IsUnique = true)]
[Index(nameof(Name), IsUnique = true)]
[Index(nameof(SubDomain), IsUnique = true)]
public class Tenant : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [StringLength(10)]
    public required string Code { get; set; }
    
    [StringLength(30)]
    public required string Name { get; set; }
    
    [StringLength(50)] 
    public required string SubDomain { get; set; }
    
    [StringLength(2)]
    public string? State { get; set; }
    
    public string? MainAddress { get; set; }
    
    public TenantConfig? TenantConfig { get; set; }
    
    public virtual ICollection<UserTenant>? UserTenants { get; set; }
    
    public virtual ICollection<Site>? Sites { get; set; }
}
