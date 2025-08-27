using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using PlatformApi.Models.BaseModels;

namespace PlatformApi.Models;

[Table("user_invitations")]
public class UserInvitation : BaseObject
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    [StringLength(255)]
    public required string Email { get; set; }
    
    public Guid? TenantId { get; set; }
    
    public Guid? SiteId { get; set; }
    
    [Required]
    [StringLength(255)]
    public required string InvitationToken { get; set; }
    
    [Required]
    public required RoleScope Scope { get; set; }
    
    [Required]
    public required DateTime ExpiresAt { get; set; }
    
    public bool IsUsed { get; set; } = false;
}