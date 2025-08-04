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
    
    [Required]
    public required Guid TenantId { get; set; }
    
    [Required]
    [StringLength(255)]
    public required string InvitationToken { get; set; }
    
    [Column(TypeName = "json")]
    public string? InvitedRoles { get; set; }
    
    [Required]
    public required DateTime ExpiresAt { get; set; }
    
    public bool IsUsed { get; set; } = false;
}