using Microsoft.Extensions.Logging;
using Moq;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Services;

public class EmailContentServiceTests
{
    private readonly Mock<IBrandingService> _mockBrandingService;
    private readonly Mock<ILogger<EmailContentService>> _mockLogger;
    private readonly EmailContentService _emailContentService;

    public EmailContentServiceTests()
    {
        _mockBrandingService = new Mock<IBrandingService>();
        _mockLogger = new Mock<ILogger<EmailContentService>>();

        // Since the context isn't used in the methods we're testing, pass null
        _emailContentService = new EmailContentService(
            _mockBrandingService.Object,
            null!,
            _mockLogger.Object);
    }

    private BrandingContext CreateTestBranding()
    {
        return new BrandingContext
        {
            SiteName = "Test Platform",
            LogoPath = "/logos/test.png",
            PrimaryColor = "#ff5722",
            SubDomain = "test",
            TenantId = Guid.NewGuid(),
            BaseUrl = "https://test.example.com",
            EmailFromName = "Test Support"
        };
    }

    [Fact]
    public async Task PrepareEmailConfirmationAsync_ReturnsValidEmailContent()
    {
        var branding = CreateTestBranding();
        var userId = Guid.NewGuid();
        var token = "test-token-123";
        var email = "test@example.com";
        var userName = "Test User";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, branding.TenantId))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PrepareEmailConfirmationAsync(
            email, token, userId, userName, branding.TenantId);

        Assert.NotNull(result);
        Assert.Equal(email, result.ToEmail);
        Assert.Contains("confirm", result.Subject.ToLower());
        Assert.Contains(userName, result.HtmlBody);
        Assert.Contains(userName, result.TextBody);
        Assert.Contains("confirm-email", result.HtmlBody);
        Assert.Contains(branding.BaseUrl, result.HtmlBody);
        Assert.Equal(branding, result.Branding);
    }

    [Fact]
    public async Task PrepareEmailConfirmationAsync_WithReturnUrl_IncludesReturnUrlInConfirmationLink()
    {
        var branding = CreateTestBranding();
        var userId = Guid.NewGuid();
        var token = "test-token-123";
        var email = "test@example.com";
        var userName = "Test User";
        var returnUrl = "/dashboard";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, branding.TenantId))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PrepareEmailConfirmationAsync(
            email, token, userId, userName, branding.TenantId, returnUrl);

        Assert.Contains("returnUrl", result.HtmlBody);
        Assert.Contains("dashboard", result.HtmlBody);
        Assert.Contains(branding.BaseUrl, result.HtmlBody);
    }

    [Fact]
    public async Task PreparePasswordResetAsync_ReturnsValidEmailContent()
    {
        var branding = CreateTestBranding();
        var userId = Guid.NewGuid();
        var token = "reset-token-456";
        var email = "test@example.com";
        var userName = "Test User";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, branding.TenantId))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PreparePasswordResetAsync(
            email, token, userId, userName, branding.TenantId);

        Assert.NotNull(result);
        Assert.Equal(email, result.ToEmail);
        Assert.Contains("reset", result.Subject.ToLower());
        Assert.Contains(userName, result.HtmlBody);
        Assert.Contains("reset-password", result.HtmlBody);
        Assert.Contains(branding.SiteName, result.HtmlBody);
        Assert.Contains(branding.BaseUrl, result.HtmlBody);
    }

    [Fact]
    public async Task PreparePasswordResetAsync_WithReturnUrl_IncludesReturnUrlInResetLink()
    {
        var branding = CreateTestBranding();
        var userId = Guid.NewGuid();
        var token = "reset-token-456";
        var email = "test@example.com";
        var userName = "Test User";
        var returnUrl = "/login";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, branding.TenantId))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PreparePasswordResetAsync(
            email, token, userId, userName, branding.TenantId, returnUrl);

        Assert.Contains("returnUrl", result.HtmlBody);
        Assert.Contains("login", result.HtmlBody);
        Assert.Contains(branding.BaseUrl, result.HtmlBody);
    }

    [Fact]
    public async Task PrepareWelcomeEmailAsync_ReturnsValidEmailContent()
    {
        var branding = CreateTestBranding();
        var email = "newuser@example.com";
        var userName = "New User";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, branding.TenantId))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PrepareWelcomeEmailAsync(
            email, userName, branding.TenantId);

        Assert.NotNull(result);
        Assert.Equal(email, result.ToEmail);
        Assert.Contains("welcome", result.Subject.ToLower());
        Assert.Contains(userName, result.HtmlBody);
        Assert.Contains(userName, result.TextBody);
        Assert.Contains(branding.SiteName, result.HtmlBody);
    }

    [Fact]
    public async Task PrepareInvitationEmailAsync_WithTenantScope_ReturnsValidEmailContent()
    {
        var branding = CreateTestBranding();
        var email = "invite@example.com";
        var token = "invitation-token-789";
        var userName = "Invited User";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, branding.TenantId))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PrepareInvitationEmailAsync(
            email, token, userName, RoleScope.Tenant, branding.TenantId);

        Assert.NotNull(result);
        Assert.Equal(email, result.ToEmail);
        Assert.Contains("invited", result.Subject.ToLower());
        Assert.Contains(userName, result.HtmlBody);
        Assert.Contains("register-invitation", result.HtmlBody);
        Assert.Contains(token, result.HtmlBody);
        Assert.Contains(branding.BaseUrl, result.HtmlBody);
    }

    [Fact]
    public async Task PrepareInvitationEmailAsync_WithInternalScope_ReturnsValidEmailContent()
    {
        var branding = CreateTestBranding();
        var email = "internal@example.com";
        var token = "internal-token-101";
        var userName = "Internal User";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, null))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PrepareInvitationEmailAsync(
            email, token, userName, RoleScope.Internal);

        Assert.NotNull(result);
        Assert.Equal(email, result.ToEmail);
        Assert.Contains("invited", result.Subject.ToLower());
        Assert.Contains(userName, result.HtmlBody);
        Assert.Contains("register-invitation", result.HtmlBody);
        Assert.Contains(branding.BaseUrl, result.HtmlBody);
    }

    [Fact]
    public async Task PrepareInvitationEmailAsync_WithUnsupportedScope_ThrowsArgumentException()
    {
        var branding = CreateTestBranding();
        var email = "test@example.com";
        var token = "token";
        var userName = "User";

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, null))
            .ReturnsAsync(branding);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _emailContentService.PrepareInvitationEmailAsync(
                email, token, userName, (RoleScope)999));
    }

    [Fact]
    public async Task PrepareEmailConfirmationAsync_WhenBrandingServiceFails_LogsErrorAndThrows()
    {
        var userId = Guid.NewGuid();
        var exception = new Exception("Branding service failed");

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, It.IsAny<Guid?>()))
            .ThrowsAsync(exception);

        var ex = await Assert.ThrowsAsync<Exception>(() =>
            _emailContentService.PrepareEmailConfirmationAsync(
                "test@example.com", "token", userId, "User"));

        Assert.Equal(exception, ex);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to prepare email confirmation content")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task PreparePasswordResetAsync_WhenBrandingServiceFails_LogsErrorAndThrows()
    {
        var userId = Guid.NewGuid();
        var exception = new Exception("Branding service failed");

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, It.IsAny<Guid?>()))
            .ThrowsAsync(exception);

        var ex = await Assert.ThrowsAsync<Exception>(() =>
            _emailContentService.PreparePasswordResetAsync(
                "test@example.com", "token", userId, "User"));

        Assert.Equal(exception, ex);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to prepare password reset content")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task PrepareWelcomeEmailAsync_WhenBrandingServiceFails_LogsErrorAndThrows()
    {
        var exception = new Exception("Branding service failed");

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, It.IsAny<Guid?>()))
            .ThrowsAsync(exception);

        var ex = await Assert.ThrowsAsync<Exception>(() =>
            _emailContentService.PrepareWelcomeEmailAsync("test@example.com", "User"));

        Assert.Equal(exception, ex);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to prepare welcome email content")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task PrepareInvitationEmailAsync_WhenBrandingServiceFails_LogsErrorAndThrows()
    {
        var exception = new Exception("Branding service failed");

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, It.IsAny<Guid?>()))
            .ThrowsAsync(exception);

        var ex = await Assert.ThrowsAsync<Exception>(() =>
            _emailContentService.PrepareInvitationEmailAsync(
                "test@example.com", "token", "User", RoleScope.Tenant));

        Assert.Equal(exception, ex);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to prepare invitation email content")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task AllEmailMethods_WithoutTenantId_CallBrandingServiceWithNullTenantId()
    {
        var branding = CreateTestBranding();
        var userId = Guid.NewGuid();

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, null))
            .ReturnsAsync(branding);

        await _emailContentService.PrepareEmailConfirmationAsync(
            "test@example.com", "token", userId, "User");
        await _emailContentService.PreparePasswordResetAsync(
            "test@example.com", "token", userId, "User");
        await _emailContentService.PrepareWelcomeEmailAsync("test@example.com", "User");
        await _emailContentService.PrepareInvitationEmailAsync(
            "test@example.com", "token", "User", RoleScope.Internal);

        _mockBrandingService.Verify(
            x => x.GetBrandingContextAsync(null, null),
            Times.Exactly(4));
    }

    [Fact]
    public async Task PrepareInvitationEmailAsync_WithSiteScope_UsesTenantInvitationTemplate()
    {
        var branding = CreateTestBranding();
        var email = "site@example.com";
        var token = "site-token-202";
        var userName = "Site User";
        var siteId = Guid.NewGuid();

        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(null, branding.TenantId))
            .ReturnsAsync(branding);

        var result = await _emailContentService.PrepareInvitationEmailAsync(
            email, token, userName, RoleScope.Site, branding.TenantId, siteId);

        Assert.NotNull(result);
        Assert.Equal(email, result.ToEmail);
        Assert.Contains(userName, result.HtmlBody);
        Assert.Contains(branding.BaseUrl, result.HtmlBody);
    }
}