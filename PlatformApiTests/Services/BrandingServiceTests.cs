using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using PlatformApi.Models;
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Services;

public class BrandingServiceTests
{
    private readonly Mock<ITenantService> _mockTenantService;
    private readonly Mock<IConfiguration> _mockConfiguration;
    private readonly Mock<ILogger<BrandingService>> _mockLogger;
    private readonly BrandingService _brandingService;

    public BrandingServiceTests()
    {
        _mockTenantService = new Mock<ITenantService>();
        _mockConfiguration = new Mock<IConfiguration>();
        _mockLogger = new Mock<ILogger<BrandingService>>();

        _mockConfiguration.Setup(x => x["AUTH_EMAIL_LINK_DOMAIN"]).Returns("example.com");
        _mockConfiguration.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("Platform Auth");
        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Development");

        _brandingService = new BrandingService(_mockTenantService.Object, _mockConfiguration.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task GetDefaultBrandingContextAsync_ReturnsDefaultBranding()
    {
        var result = await _brandingService.GetDefaultBrandingContextAsync();

        Assert.NotNull(result);
        Assert.Equal("Platform", result.SiteName);
        Assert.Equal("", result.LogoPath);
        Assert.Equal("#1d86f8", result.PrimaryColor);
        Assert.Null(result.SubDomain);
        Assert.Null(result.TenantId);
        Assert.Equal("http://example.com", result.BaseUrl);
        Assert.Equal("Platform Auth", result.EmailFromName);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithValidSubdomain_ReturnsTenantBranding()
    {
        var tenantId = Guid.NewGuid();
        var tenantConfig = new TenantConfig
        {
            TenantId = tenantId,
            LogoPath = "/logos/tenant.png",
            PrimaryColor = "#ff5722",
            Tenant = new Tenant
            {
                Id = tenantId,
                Code = "TEST001",
                Name = "Test Tenant",
                SubDomain = "testtenant"
            }
        };

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain("testtenant"))
            .ReturnsAsync(tenantConfig);

        var result = await _brandingService.GetBrandingContextAsync("testtenant");

        Assert.NotNull(result);
        Assert.Equal("Test Tenant", result.SiteName);
        Assert.Equal("/logos/tenant.png", result.LogoPath);
        Assert.Equal("#ff5722", result.PrimaryColor);
        Assert.Equal("testtenant", result.SubDomain);
        Assert.Equal(tenantId, result.TenantId);
        Assert.Equal("http://testtenant.example.com", result.BaseUrl);
        Assert.Equal("Test Tenant", result.EmailFromName);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithValidTenantId_ReturnsTenantBranding()
    {
        var tenantId = Guid.NewGuid();
        var tenantConfig = new TenantConfig
        {
            TenantId = tenantId,
            LogoPath = "/logos/tenant.png",
            PrimaryColor = "#ff5722",
            Tenant = new Tenant
            {
                Id = tenantId,
                Code = "TEST001",
                Name = "Test Tenant",
                SubDomain = "testtenant"
            }
        };

        _mockTenantService.Setup(x => x.GetTenantConfigById(tenantId))
            .ReturnsAsync(tenantConfig);

        var result = await _brandingService.GetBrandingContextAsync(null, tenantId);

        Assert.NotNull(result);
        Assert.Equal("Test Tenant", result.SiteName);
        Assert.Equal(tenantId, result.TenantId);
        Assert.Equal("testtenant", result.SubDomain);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithNullPrimaryColor_UsesDefaultColor()
    {
        var tenantId = Guid.NewGuid();
        var tenantConfig = new TenantConfig
        {
            TenantId = tenantId,
            PrimaryColor = null,
            Tenant = new Tenant
            {
                Id = tenantId,
                Code = "TEST001",
                Name = "Test Tenant",
                SubDomain = "testtenant"
            }
        };

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain("testtenant"))
            .ReturnsAsync(tenantConfig);

        var result = await _brandingService.GetBrandingContextAsync("testtenant");

        Assert.Equal("#007bff", result.PrimaryColor);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WhenTenantServiceFails_ReturnsDefaultBranding()
    {
        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain("nonexistent"))
            .ThrowsAsync(new Exception("Tenant not found"));

        var result = await _brandingService.GetBrandingContextAsync("nonexistent");

        Assert.NotNull(result);
        Assert.Equal("Platform", result.SiteName);
        Assert.Null(result.TenantId);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithNoParameters_ReturnsDefaultBranding()
    {
        var result = await _brandingService.GetBrandingContextAsync();

        Assert.NotNull(result);
        Assert.Equal("Platform", result.SiteName);
        Assert.Equal("http://example.com", result.BaseUrl);
    }

    [Fact]
    public async Task GetBrandingContextAsync_InProduction_ReturnsHttpsUrl()
    {
        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");
        var brandingService = new BrandingService(_mockTenantService.Object, _mockConfiguration.Object, _mockLogger.Object);

        var result = await brandingService.GetDefaultBrandingContextAsync();

        Assert.Equal("https://example.com", result.BaseUrl);
    }

    [Fact]
    public void Constructor_WithMissingBaseDomain_ThrowsInvalidOperationException()
    {
        _mockConfiguration.Setup(x => x["AUTH_EMAIL_LINK_DOMAIN"]).Returns((string?)null);

        Assert.Throws<InvalidOperationException>(() =>
            new BrandingService(_mockTenantService.Object, _mockConfiguration.Object, _mockLogger.Object));
    }

    [Fact]
    public async Task GetBrandingContextAsync_LogsWarningWhenTenantNotFound()
    {
        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain("invalid"))
            .ThrowsAsync(new Exception("Not found"));

        await _brandingService.GetBrandingContextAsync("invalid");

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to get tenant config")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task GetBrandingContextAsync_LogsInformationWhenTenantFound()
    {
        var tenantConfig = new TenantConfig
        {
            TenantId = Guid.NewGuid(),
            Tenant = new Tenant
            {
                Code = "TEST001",
                Name = "Test Tenant",
                SubDomain = "testtenant"
            }
        };

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain("testtenant"))
            .ReturnsAsync(tenantConfig);

        await _brandingService.GetBrandingContextAsync("testtenant");

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Tenant branding selected")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithBrandedTenantButNullSubdomain_ReturnsDefaultBaseUrl()
    {
        var tenantId = Guid.NewGuid();
        var tenantConfig = new TenantConfig
        {
            TenantId = tenantId,
            LogoPath = "/logos/tenant.png",
            PrimaryColor = "#ff5722",
            Tenant = new Tenant
            {
                Id = tenantId,
                Code = "TEST001",
                Name = "Test Tenant",
                SubDomain = null
            }
        };

        _mockTenantService.Setup(x => x.GetTenantConfigById(tenantId))
            .ReturnsAsync(tenantConfig);

        var result = await _brandingService.GetBrandingContextAsync(null, tenantId);

        Assert.NotNull(result);
        Assert.Equal("Test Tenant", result.SiteName);
        Assert.Equal("/logos/tenant.png", result.LogoPath);
        Assert.Equal("#ff5722", result.PrimaryColor);
        Assert.Null(result.SubDomain);
        Assert.Equal(tenantId, result.TenantId);
        Assert.Equal("http://example.com", result.BaseUrl);
        Assert.Equal("Test Tenant", result.EmailFromName);
    }
}