using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using PlatformStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("tenants")]
[Index(nameof(Code), IsUnique = true)]
[Index(nameof(Name), IsUnique = true)]
[Index(nameof(SubDomain), IsUnique = true)]
public class Tenant : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [StringLength(25)]
    public required string Code { get; set; }
    
    [StringLength(50)]
    public required string Name { get; set; }
    
    [StringLength(50)] 
    public required string SubDomain { get; set; }
    
    public TenantConfig? TenantConfig { get; set; }
    
    
    public virtual ICollection<Site>? Sites { get; set; }
}
