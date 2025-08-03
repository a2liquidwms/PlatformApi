using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using NetStarterCommon.Core.Common.Models.BaseModels;

namespace PlatformApi.Models;

[Table("site")]
public class Site : BaseObject
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    [StringLength(100)]
    public required string Name { get; set; }
    
    [Required]
    public required Guid TenantId { get; set; }
    
    public bool IsActive { get; set; } = true;
    
    public virtual Tenant? Tenant { get; set; }
    
    public virtual ICollection<UserSite>? UserSites { get; set; }
}