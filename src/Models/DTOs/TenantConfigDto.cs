namespace PlatformApi.Models.DTOs;

public class TenantConfigDto
{
    public Guid Id { get; set; }

    public required Guid TenantId { get; set; }

    public required string SubDomain { get; set; }

    public string? SiteName { get; set; }

    public string? LogoPath { get; set; }

    public string? PrimaryColor { get; set; }
}