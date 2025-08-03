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
    private readonly string _testBaseDomain = "example.com";

    public BrandingServiceTests()
    {
        _mockTenantService = new Mock<ITenantService>();
        _mockConfiguration = new Mock<IConfiguration>();
        _mockLogger = new Mock<ILogger<BrandingService>>();

        // Setup default configuration
        _mockConfiguration.Setup(x => x["UI_BASE_DOMAIN"]).Returns(_testBaseDomain);
        _mockConfiguration.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("RedClay Auth");

        _brandingService = new BrandingService(
            _mockTenantService.Object,
            _mockConfiguration.Object,
            _mockLogger.Object);
    }

    private TenantConfig CreateTestTenantConfig(string? subdomain = "testclient")
    {
        return new TenantConfig
        {
            TenantId = Guid.NewGuid(),
            SiteName = "Test Client",
            LogoPath = "/logos/test.png",
            PrimaryColor = "#ff6600",
            Tenant = new Tenant
            {
                Id = Guid.NewGuid(),
                Name = "Test Tenant",
                SubDomain = subdomain!,
                Code = "TEST"
            }
        };
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithValidSubdomain_ReturnsTenantBranding()
    {
        // Arrange
        var subdomain = "testclient";
        var tenantConfig = CreateTestTenantConfig(subdomain);

        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");
        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(tenantConfig.SiteName, result.SiteName);
        Assert.Equal(tenantConfig.LogoPath, result.LogoPath);
        Assert.Equal(tenantConfig.PrimaryColor, result.PrimaryColor);
        Assert.Equal(tenantConfig.Tenant.SubDomain, result.SubDomain);
        Assert.Equal(tenantConfig.TenantId, result.TenantId);
        Assert.Equal($"https://{subdomain}.{_testBaseDomain}", result.BaseUrl);
        Assert.Equal(tenantConfig.SiteName, result.EmailFromName);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithValidTenantId_ReturnsTenantBranding()
    {
        // Arrange
        var tenantId = Guid.NewGuid();
        var tenantConfig = CreateTestTenantConfig();
        tenantConfig.TenantId = tenantId;

        _mockTenantService.Setup(x => x.GetTenantConfigById(tenantId))
            .ReturnsAsync(tenantConfig);
        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");

        // Act
        var result = await _brandingService.GetBrandingContextAsync(null, tenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(tenantConfig.SiteName, result.SiteName);
        Assert.Equal(tenantConfig.TenantId, result.TenantId);
        Assert.Equal($"https://{tenantConfig.Tenant.SubDomain}.{_testBaseDomain}", result.BaseUrl);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithSubdomainAndTenantId_PrioritizesSubdomain()
    {
        // Arrange
        var subdomain = "priority";
        var tenantId = Guid.NewGuid();
        var tenantConfig = CreateTestTenantConfig(subdomain);

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain, tenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(subdomain, result.SubDomain);
        
        // Verify subdomain was called but not tenantId
        _mockTenantService.Verify(x => x.GetTenantConfigBySubdomain(subdomain), Times.Once);
        _mockTenantService.Verify(x => x.GetTenantConfigById(It.IsAny<Guid>()), Times.Never);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithNonExistentSubdomain_ReturnsDefaultBranding()
    {
        // Arrange
        var subdomain = "nonexistent";

        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");
        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync((TenantConfig?)null);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("RedClay Services", result.SiteName);
        Assert.Equal("", result.LogoPath);
        Assert.Equal("#1d86f8", result.PrimaryColor);
        Assert.Equal("", result.SubDomain);
        Assert.Null(result.TenantId);
        Assert.Equal($"https://{_testBaseDomain}", result.BaseUrl);
        Assert.Equal("RedClay Auth", result.EmailFromName);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithNonExistentTenantId_ReturnsDefaultBranding()
    {
        // Arrange
        var tenantId = Guid.NewGuid();

        _mockTenantService.Setup(x => x.GetTenantConfigById(tenantId))
            .ReturnsAsync((TenantConfig?)null);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(null, tenantId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("RedClay Services", result.SiteName);
        Assert.Null(result.TenantId);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WhenTenantServiceThrows_ReturnsDefaultBranding()
    {
        // Arrange
        var subdomain = "error";

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("RedClay Services", result.SiteName);
        
        // Verify warning was logged
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
    public async Task GetBrandingContextAsync_WithTenantConfigNullTenant_ReturnsDefaultBranding()
    {
        // Arrange
        var subdomain = "nulltenant";
        var tenantConfig = new TenantConfig
        {
            TenantId = Guid.NewGuid(),
            SiteName = "Test",
            Tenant = null! // Null tenant
        };

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("RedClay Services", result.SiteName);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithNullSiteName_UsesTenantName()
    {
        // Arrange
        var subdomain = "testtenant";
        var tenantConfig = CreateTestTenantConfig(subdomain);
        tenantConfig.SiteName = null;
        tenantConfig.Tenant.Name = "Fallback Tenant Name";

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Fallback Tenant Name", result.SiteName);
        Assert.Equal("Fallback Tenant Name", result.EmailFromName);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithNullPrimaryColor_UsesDefaultColor()
    {
        // Arrange
        var subdomain = "colortest";
        var tenantConfig = CreateTestTenantConfig(subdomain);
        tenantConfig.PrimaryColor = null;

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal("#007bff", result.PrimaryColor);
    }

    [Fact]
    public async Task GetDefaultBrandingContextAsync_ReturnsCorrectDefaults()
    {
        // Act
        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");
        var result = await _brandingService.GetDefaultBrandingContextAsync();
        
        
        // Assert
        Assert.NotNull(result);
        Assert.Equal("RedClay Services", result.SiteName);
        Assert.Equal("", result.LogoPath);
        Assert.Equal("#1d86f8", result.PrimaryColor);
        Assert.Equal("", result.SubDomain);
        Assert.Null(result.TenantId);
        Assert.Equal($"https://{_testBaseDomain}", result.BaseUrl);
        Assert.Equal("RedClay Auth", result.EmailFromName);
    }

    [Fact]
    public async Task GetDefaultBrandingContextAsync_WithCustomDefaultSiteName_UsesCustomName()
    {
        // Arrange
        _mockConfiguration.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("Custom Default Site");
        
        var service = new BrandingService(
            _mockTenantService.Object,
            _mockConfiguration.Object,
            _mockLogger.Object);

        // Act
        var result = await service.GetDefaultBrandingContextAsync();

        // Assert
        Assert.NotNull(result);
        Assert.Equal("Custom Default Site", result.EmailFromName);
    }

    [Fact]
    public void Constructor_WithMissingBaseDomain_ThrowsInvalidOperationException()
    {
        // Arrange
        var mockConfigWithoutDomain = new Mock<IConfiguration>();
        mockConfigWithoutDomain.Setup(x => x["UI_BASE_DOMAIN"]).Returns((string?)null);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() =>
            new BrandingService(_mockTenantService.Object, mockConfigWithoutDomain.Object, _mockLogger.Object));
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithNullSubdomainInTenant_GeneratesCorrectBaseUrl()
    {
        // Arrange
        var tenantConfig = CreateTestTenantConfig();
        tenantConfig.Tenant.SubDomain = null!;
        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");

        _mockTenantService.Setup(x => x.GetTenantConfigById(It.IsAny<Guid>()))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(null, Guid.NewGuid());

        // Assert
        Assert.NotNull(result);
        Assert.Equal($"https://{_testBaseDomain}", result.BaseUrl);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithEmptyParameters_ReturnsDefaultBranding()
    {
        // Arrange - Set to Production environment to get https
        _mockConfiguration.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");
        
        var service = new BrandingService(
            _mockTenantService.Object,
            _mockConfiguration.Object,
            _mockLogger.Object);

        // Act
        var result = await service.GetBrandingContextAsync();

        // Assert
        Assert.NotNull(result);
        Assert.Equal("RedClay Services", result.SiteName);
        Assert.Equal($"https://{_testBaseDomain}", result.BaseUrl);
        
        // Verify no tenant service calls were made
        _mockTenantService.Verify(x => x.GetTenantConfigBySubdomain(It.IsAny<string>()), Times.Never);
        _mockTenantService.Verify(x => x.GetTenantConfigById(It.IsAny<Guid>()), Times.Never);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithEmptyStringSubdomain_ReturnsDefaultBranding()
    {
        // Act
        var result = await _brandingService.GetBrandingContextAsync("");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("RedClay Services", result.SiteName);
        
        // Verify no tenant service calls were made
        _mockTenantService.Verify(x => x.GetTenantConfigBySubdomain(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task GetBrandingContextAsync_LogsWarningOnTenantServiceException()
    {
        // Arrange
        var subdomain = "errortest";
        var tenantId = Guid.NewGuid();
        var exception = new Exception("Database connection failed");

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ThrowsAsync(exception);

        // Act
        var result = await _brandingService.GetBrandingContextAsync(subdomain, tenantId);

        // Assert
        Assert.NotNull(result);
        
        // Verify specific warning message
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => 
                    v.ToString()!.Contains("Failed to get tenant config") &&
                    v.ToString()!.Contains(subdomain) &&
                    v.ToString()!.Contains(tenantId.ToString())),
                It.Is<Exception>(ex => ex == exception),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task GetBrandingContextAsync_DevelopmentEnvironment_ReturnsHttpBaseUrl()
    {
        // Arrange
        var mockConfig = new Mock<IConfiguration>();
        mockConfig.Setup(x => x["UI_BASE_DOMAIN"]).Returns(_testBaseDomain);
        mockConfig.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("RedClay Auth");
        mockConfig.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Development");
        
        var service = new BrandingService(
            _mockTenantService.Object,
            mockConfig.Object,
            _mockLogger.Object);

        // Act
        var result = await service.GetBrandingContextAsync();

        // Assert
        Assert.NotNull(result);
        Assert.Equal($"http://{_testBaseDomain}", result.BaseUrl);
    }

    [Fact]
    public async Task GetBrandingContextAsync_ProductionEnvironment_ReturnsHttpsBaseUrl()
    {
        // Arrange
        var mockConfig = new Mock<IConfiguration>();
        mockConfig.Setup(x => x["UI_BASE_DOMAIN"]).Returns(_testBaseDomain);
        mockConfig.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("RedClay Auth");
        mockConfig.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");
        
        var service = new BrandingService(
            _mockTenantService.Object,
            mockConfig.Object,
            _mockLogger.Object);

        // Act
        var result = await service.GetBrandingContextAsync();

        // Assert
        Assert.NotNull(result);
        Assert.Equal($"https://{_testBaseDomain}", result.BaseUrl);
    }

    [Fact]
    public async Task GetBrandingContextAsync_StagingEnvironment_ReturnsHttpsBaseUrl()
    {
        // Arrange
        var mockConfig = new Mock<IConfiguration>();
        mockConfig.Setup(x => x["UI_BASE_DOMAIN"]).Returns(_testBaseDomain);
        mockConfig.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("RedClay Auth");
        mockConfig.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Staging");
        
        var service = new BrandingService(
            _mockTenantService.Object,
            mockConfig.Object,
            _mockLogger.Object);

        // Act
        var result = await service.GetBrandingContextAsync();

        // Assert
        Assert.NotNull(result);
        Assert.Equal($"https://{_testBaseDomain}", result.BaseUrl);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithTenantConfigInDevelopment_ReturnsHttpBaseUrl()
    {
        // Arrange
        var subdomain = "testclient";
        var tenantConfig = CreateTestTenantConfig(subdomain);
        
        var mockConfig = new Mock<IConfiguration>();
        mockConfig.Setup(x => x["UI_BASE_DOMAIN"]).Returns(_testBaseDomain);
        mockConfig.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("RedClay Auth");
        mockConfig.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Development");
        
        var service = new BrandingService(
            _mockTenantService.Object,
            mockConfig.Object,
            _mockLogger.Object);

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await service.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal($"http://{_testBaseDomain}", result.BaseUrl);
    }

    [Fact]
    public async Task GetBrandingContextAsync_WithTenantConfigInProduction_ReturnsHttpsBaseUrl()
    {
        // Arrange
        var subdomain = "testclient";
        var tenantConfig = CreateTestTenantConfig(subdomain);
        
        var mockConfig = new Mock<IConfiguration>();
        mockConfig.Setup(x => x["UI_BASE_DOMAIN"]).Returns(_testBaseDomain);
        mockConfig.Setup(x => x["DEFAULT_SITE_NAME"]).Returns("RedClay Auth");
        mockConfig.Setup(x => x["ASPNETCORE_ENVIRONMENT"]).Returns("Production");
        
        var service = new BrandingService(
            _mockTenantService.Object,
            mockConfig.Object,
            _mockLogger.Object);

        _mockTenantService.Setup(x => x.GetTenantConfigBySubdomain(subdomain))
            .ReturnsAsync(tenantConfig);

        // Act
        var result = await service.GetBrandingContextAsync(subdomain);

        // Assert
        Assert.NotNull(result);
        Assert.Equal($"https://{subdomain}.{_testBaseDomain}", result.BaseUrl);
    }
}