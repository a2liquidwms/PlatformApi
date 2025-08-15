using System.ComponentModel.DataAnnotations;

namespace PlatformApi.Models.DTOs;

public class ForgotPasswordRequest
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    public Guid? TenantId { get; set; }
}

public class ResetPasswordRequest
{
    [Required]
    public required Guid UserId { get; set; }

    [Required]
    public required string Token { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 6)]
    public required string NewPassword { get; set; }
    
    public Guid? TenantId { get; set; }
}

public class ConfirmEmailRequest
{
    [Required]
    public required Guid UserId { get; set; }

    [Required]
    public required string Token { get; set; }
    
    public Guid? TenantId { get; set; }
}

public class ResendConfirmationEmailRequest
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
    
    public Guid? TenantId { get; set; }
}