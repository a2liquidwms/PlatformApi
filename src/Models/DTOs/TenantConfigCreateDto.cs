namespace PlatformApi.Models.DTOs;

public class TenantConfigCreateDto
{
    public string? SiteName { get; set; }
    
    public string? LogoPath { get; set; }
    
    public string? PrimaryColor { get; set; }

    public decimal? GeocenterLat { get; set; }

    public decimal? GeocenterLong { get; set; }
}