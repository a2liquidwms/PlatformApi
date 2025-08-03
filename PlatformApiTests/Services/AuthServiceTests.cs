using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using NetStarterCommon.Core.Common.Constants;
using NetStarterCommon.Core.Common.Services;
using NetStarterCommon.Core.Common.Tenant;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Services;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;
using Xunit;

namespace PlatformApiTests.Services;

public class AuthServiceTests
{
    private readonly Mock<UserManager<AuthUser>> _mockUserManager;
    private readonly Mock<SignInManager<AuthUser>> _mockSignInManager;
    private readonly Mock<IConfiguration> _mockConfiguration;
    private readonly Mock<ILogger<AuthService>> _mockLogger;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly Mock<IUserService> _mockUserService;
    private readonly Mock<IEmailService> _mockEmailService;
    private readonly Mock<IBrandingService> _mockBrandingService;
    private readonly Mock<IUnitOfWork<PlatformDbContext>> _mockUnitOfWork;
    private readonly Mock<ISnsService> _mockSnsService;
    private readonly DbContextOptions<PlatformDbContext> _options;
    private readonly PlatformDbContext _dbContext;
    private readonly HttpContext _httpContext;

    public AuthServiceTests()
    {
        // Setup DbContext with in-memory database
        _options = new DbContextOptionsBuilder<PlatformDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        _dbContext = new PlatformDbContext(_options);

        // Mock HttpContext
        _httpContext = new DefaultHttpContext();
        var mockHttpContext = new Mock<HttpContext>();
        mockHttpContext.Setup(m => m.Items).Returns(_httpContext.Items);

        // Mock HttpContextAccessor
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(_httpContext);

        // Mock UserManager
        var mockUserStore = new Mock<IUserStore<AuthUser>>();
        _mockUserManager = new Mock<UserManager<AuthUser>>(
            mockUserStore.Object,
            Mock.Of<IOptions<IdentityOptions>>(),
            Mock.Of<IPasswordHasher<AuthUser>>(),
            Array.Empty<IUserValidator<AuthUser>>(),
            Array.Empty<IPasswordValidator<AuthUser>>(),
            Mock.Of<ILookupNormalizer>(),
            Mock.Of<IdentityErrorDescriber>(),
            Mock.Of<IServiceProvider>(),
            Mock.Of<ILogger<UserManager<AuthUser>>>());

        // Mock SignInManager
        _mockSignInManager = new Mock<SignInManager<AuthUser>>(
            _mockUserManager.Object,
            _mockHttpContextAccessor.Object,
            Mock.Of<IUserClaimsPrincipalFactory<AuthUser>>(),
            Mock.Of<IOptions<IdentityOptions>>(),
            Mock.Of<ILogger<SignInManager<AuthUser>>>(),
            Mock.Of<IAuthenticationSchemeProvider>(),
            Mock.Of<IUserConfirmation<AuthUser>>());

        // Mock Configuration
        _mockConfiguration = new Mock<IConfiguration>();
        _mockConfiguration.Setup(x => x["JWT_ISSUER"]).Returns("test-issuer");
        _mockConfiguration.Setup(x => x["JWT_AUDIENCE"]).Returns("test-audience");
        _mockConfiguration.Setup(x => x["JWT_SECRET"])
            .Returns("test-secret-key-with-minimum-16-chars-length-for-tests");
        _mockConfiguration.Setup(x => x["AUTH_ACCESS_TOKEN_MINUTES"]).Returns("5");
        _mockConfiguration.Setup(x => x["AUTH_REFRESH_TOKEN_DAYS"]).Returns("7");
        _mockConfiguration.Setup(x => x["EMAIL_CONFIRMATION_URL_TEMPLATE"])
            .Returns("{baseUrl}/confirm-email?token={token}&userId={userId}");
        _mockConfiguration.Setup(x => x["PASSWORD_RESET_URL_TEMPLATE"])
            .Returns("{baseUrl}/reset-password?token={token}&userId={userId}");

        // Mock Logger
        _mockLogger = new Mock<ILogger<AuthService>>();

        // Mock UserService
        _mockUserService = new Mock<IUserService>();

        // Mock EmailService
        _mockEmailService = new Mock<IEmailService>();

        // Mock BrandingService
        _mockBrandingService = new Mock<IBrandingService>();
        
        // Mock UnitOfWork
        _mockUnitOfWork = new Mock<IUnitOfWork<PlatformDbContext>>();
        _mockUnitOfWork.Setup(x => x.CompleteAsync()).Returns(Task.FromResult(1));
        
        // Mock SnsService
        _mockSnsService = new Mock<ISnsService>();
        
        var defaultBranding = new BrandingContext
        {
            SiteName = "Test Site",
            LogoPath = "",
            PrimaryColor = "#007bff",
            SubDomain = "",
            TenantId = null,
            BaseUrl = "https://test.example.com",
            EmailFromName = "Test Site"
        };
        _mockBrandingService.Setup(x => x.GetDefaultBrandingContextAsync())
            .ReturnsAsync(defaultBranding);
        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(It.IsAny<string>(), It.IsAny<Guid?>()))
            .ReturnsAsync(defaultBranding);
    }

    private AuthService CreateService()
    {
        // Create a concrete instance of TenantHelper with logger
        var tenantHelperLogger = Mock.Of<ILogger<TenantHelper>>();
        var tenantHelper = new TenantHelper(_mockHttpContextAccessor.Object, tenantHelperLogger);

        return new AuthService(
            _mockUserManager.Object,
            _mockSignInManager.Object,
            _mockConfiguration.Object,
            _mockLogger.Object,
            _dbContext,
            _mockUnitOfWork.Object,
            _mockHttpContextAccessor.Object,
            tenantHelper,
            _mockUserService.Object,
            _mockEmailService.Object,
            _mockBrandingService.Object,
            _mockSnsService.Object);
    }

    private AuthUser CreateTestUser()
    {
        return new AuthUser
        {
            Id = "test-user-id",
            UserName = "test@example.com",
            Email = "test@example.com",
            EmailConfirmed = true
        };
    }
    
    private BrandingContext CreateTestBranding()
    {
        return new BrandingContext
        {
            SiteName = "Test Client",
            LogoPath = "/logos/test.png",
            PrimaryColor = "#ff6600",
            SubDomain = "testclient",
            TenantId = Guid.NewGuid(),
            BaseUrl = "https://testclient.example.com",
            EmailFromName = "Test Client Support"
        };
    }

    [Fact]
    public async Task Register_ShouldCallUserManagerCreateAsync()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var password = "Test@password1";

        _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AuthUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await service.Register(user, password);

        // Assert
        Assert.True(result.Succeeded);
        _mockUserManager.Verify(x => x.CreateAsync(user, password), Times.Once);
    }

    [Fact]
    public async Task Register_WithBrandingContext_ShouldUseBrandingService()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var password = "Test@password1";
        var subdomain = "testclient";
        var tenantId = Guid.NewGuid();
        var expectedBranding = CreateTestBranding();

        _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AuthUser>(), It.IsAny<string>()))
            .ReturnsAsync(IdentityResult.Success);
        
        // Setup the email confirmation flow that happens after successful registration
        _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email!))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.GenerateEmailConfirmationTokenAsync(user))
            .ReturnsAsync("test-token");
        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(subdomain, tenantId))
            .ReturnsAsync(expectedBranding);
        _mockEmailService.Setup(x => x.SendEmailConfirmationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()))
            .ReturnsAsync(true);

        // Act
        var result = await service.Register(user, password, subdomain, tenantId);

        // Assert
        Assert.True(result.Succeeded);
        _mockUserManager.Verify(x => x.CreateAsync(user, password), Times.Once);
    }

    [Fact]
    public async Task Login_WithEmailNotConfirmed_ShouldThrowException()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        user.EmailConfirmed = false; // Set email as not confirmed
        var email = "test@example.com";
        var password = "Test@password1";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        // Act & Assert
        var exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.Login(email, password));
        
        Assert.Contains("Email not confirmed", exception.Message);
    }

    [Fact]
    public async Task Login_WithValidCredentials_ShouldGenerateTokens()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var email = "test@example.com";
        var password = "Test@password1";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);
        _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
            .ReturnsAsync(SignInResult.Success);
        _mockUserService.Setup(x => x.GetUserRoles(user.Id, null))
            .ReturnsAsync(new List<AuthRole>());
        _mockUserService.Setup(x => x.GetUserTenants(user.Id))
            .ReturnsAsync(new List<Tenant>());

        // Act
        var result = await service.Login(email, password);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.AccessToken);
        Assert.NotNull(result.RefreshToken);
        Assert.Equal("Bearer", result.TokenType);
        Assert.True(result.Expires > 0);
    }

    [Fact]
    public async Task SendEmailConfirmationAsync_WithBrandingContext_ShouldUseBrandingService()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        user.EmailConfirmed = false;
        var email = "test@example.com";
        var subdomain = "testclient";
        var tenantId = Guid.NewGuid();
        var token = "test-token";

        var expectedBranding = new BrandingContext
        {
            SiteName = "Test Client",
            BaseUrl = "https://testclient.example.com",
            PrimaryColor = "#ff0000",
            SubDomain = subdomain,
            TenantId = tenantId
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.GenerateEmailConfirmationTokenAsync(user))
            .ReturnsAsync(token);
        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(subdomain, tenantId))
            .ReturnsAsync(expectedBranding);
        _mockEmailService.Setup(x => x.SendEmailConfirmationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()))
            .ReturnsAsync(true);

        // Act
        var result = await service.SendEmailConfirmationAsync(email, subdomain, tenantId);

        // Assert
        Assert.True(result);
        _mockBrandingService.Verify(x => x.GetBrandingContextAsync(subdomain, tenantId), Times.Once);
        _mockEmailService.Verify(x => x.SendEmailConfirmationAsync(
            email, It.IsAny<string>(), user.Email!, expectedBranding), Times.Once);
    }

    [Fact]
    public async Task SendPasswordResetAsync_WithBrandingContext_ShouldUseBrandingService()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var email = "test@example.com";
        var subdomain = "testclient";
        var tenantId = Guid.NewGuid();
        var token = "reset-token";

        var expectedBranding = new BrandingContext
        {
            SiteName = "Test Client",
            BaseUrl = "https://testclient.example.com",
            PrimaryColor = "#ff0000",
            SubDomain = subdomain,
            TenantId = tenantId
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user))
            .ReturnsAsync(token);
        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(subdomain, tenantId))
            .ReturnsAsync(expectedBranding);
        _mockEmailService.Setup(x => x.SendPasswordResetAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()))
            .ReturnsAsync(true);

        // Act
        var result = await service.SendPasswordResetAsync(email, subdomain, tenantId);

        // Assert
        Assert.True(result);
        _mockBrandingService.Verify(x => x.GetBrandingContextAsync(subdomain, tenantId), Times.Once);
        _mockEmailService.Verify(x => x.SendPasswordResetAsync(
            email, It.IsAny<string>(), user.Email!, expectedBranding), Times.Once);
    }
    
    [Fact]
    public async Task Login_WithInvalidEmail_ShouldThrowException()
    {
        // Arrange
        var service = CreateService();
        var email = "nonexistent@example.com";
        var password = "Test@password1";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((AuthUser)null!);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.Login(email, password));
    }

    [Fact]
    public async Task Login_WithInvalidPassword_ShouldThrowException()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var email = "test@example.com";
        var password = "WrongPassword";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);
        _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
            .ReturnsAsync(SignInResult.Failed);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            service.Login(email, password));
    }

    [Fact]
    public async Task RefreshToken_WithValidToken_ShouldGenerateNewTokens()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var refreshToken = "valid-refresh-token";
        var userId = user.Id;

        // Add refresh token to in-memory database
        _dbContext.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = refreshToken,
            UserId = userId,
            Expires = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        });
        await _dbContext.SaveChangesAsync();

        _mockUserManager.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserService.Setup(x => x.GetUserRoles(user.Id, null))
            .ReturnsAsync(new List<AuthRole>());
        _mockUserService.Setup(x => x.GetUserTenants(user.Id))
            .ReturnsAsync(new List<Tenant>());

        // Act
        var result = await service.RefreshToken(userId, refreshToken);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.AccessToken);
        Assert.NotNull(result.RefreshToken);

        // Check that the old token is revoked
        var oldToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(t => t.Token == refreshToken);
        Assert.NotNull(oldToken);
        Assert.True(oldToken.IsRevoked);
    }

    [Fact]
    public async Task RefreshToken_WithExpiredToken_ShouldThrowException()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var refreshToken = "expired-refresh-token";
        var userId = user.Id;

        // Add expired refresh token to in-memory database
        _dbContext.RefreshTokens.Add(new RefreshToken
        {
            Id = Guid.NewGuid(),
            Token = refreshToken,
            UserId = userId,
            Expires = DateTime.UtcNow.AddDays(-1), // Expired
            IsRevoked = false
        });
        await _dbContext.SaveChangesAsync();

        _mockUserManager.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(user);

        // Act & Assert
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.RefreshToken(userId, refreshToken));
    }

    [Fact]
    public async Task GetUserByEmail_ShouldReturnUser()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var email = "test@example.com";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        // Act
        var result = await service.GetUserByEmail(email);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(user.Id, result.Id);
        Assert.Equal(user.Email, result.Email);
    }

    [Fact]
    public async Task JwtToken_ShouldContainCorrectClaims()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var email = "test@example.com";
        var password = "Test@password1";
        
        var roles = new List<AuthRole> 
        { 
            new() { Id = "role1", Name = "User", IsAdmin = false },
            new() { Id = "role2", Name = "Admin", IsAdmin = true }
        };
        
        var tenants = new List<Tenant>
        {
            new() { Id = Guid.NewGuid(), Code = "T1", Name = "Tenant 1" , SubDomain = "ten1"}
        };

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);
        _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
            .ReturnsAsync(SignInResult.Success);
        _mockUserService.Setup(x => x.GetUserRoles(It.Is<string>(s => s == user.Id), It.IsAny<Guid?>()))
            .ReturnsAsync(roles);
        _mockUserService.Setup(x => x.GetUserTenants(user.Id))
            .ReturnsAsync(tenants);

        // Act
        var tokenBundle = await service.Login(email, password);
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadJwtToken(tokenBundle.AccessToken);

        // Assert
        Assert.Contains(jwtToken.Claims, c => c.Type == "sub" && c.Value == user.Id);
        Assert.Contains(jwtToken.Claims, c => c.Type == "email" && c.Value == user.Email);
        
        var roleClaims = jwtToken.Claims.Where(c => c.Type == CommonConstants.RolesClaim).ToList();
        Assert.NotEmpty(roleClaims);
        
        var adminRoleClaims = jwtToken.Claims.Where(c => c.Type == CommonConstants.AdminRolesClaim).ToList();
        var hasAdminRoles = roles.Any(r => r.IsAdmin);
        
        if (hasAdminRoles)
        {
            Assert.NotEmpty(adminRoleClaims);
        }
        
        var tenantClaims = jwtToken.Claims.Where(c => c.Type == CommonConstants.TenantsClaim).ToList();
        Assert.NotEmpty(tenantClaims);
    }

    [Fact]
    public async Task ConfirmEmailAsync_WithValidToken_ShouldReturnTrueAndSendWelcomeEmail()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        user.EmailConfirmed = false;
        var userId = "user123";
        var token = "valid-token";
        var subdomain = "testclient";
        var tenantId = Guid.NewGuid();
        var expectedBranding = CreateTestBranding();

        _mockUserManager.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.ConfirmEmailAsync(user, token))
            .ReturnsAsync(IdentityResult.Success);
        _mockBrandingService.Setup(x => x.GetBrandingContextAsync(subdomain, tenantId))
            .ReturnsAsync(expectedBranding);
        _mockEmailService.Setup(x => x.SendWelcomeEmailAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()))
            .ReturnsAsync(true);

        // Act
        var result = await service.ConfirmEmailAsync(userId, token, subdomain, tenantId);

        // Assert
        Assert.True(result);
        _mockUserManager.Verify(x => x.ConfirmEmailAsync(user, token), Times.Once);
        _mockEmailService.Verify(x => x.SendWelcomeEmailAsync(
            user.Email!, user.UserName!, expectedBranding), Times.Once);
    }

    [Fact]
    public async Task ConfirmEmailAsync_WithInvalidToken_ShouldReturnFalse()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var userId = "user123";
        var token = "invalid-token";

        var errors = new[]
        {
            new IdentityError { Code = "InvalidToken", Description = "Invalid token" }
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.ConfirmEmailAsync(user, token))
            .ReturnsAsync(IdentityResult.Failed(errors));

        // Act
        var result = await service.ConfirmEmailAsync(userId, token);

        // Assert
        Assert.False(result);
        _mockUserManager.Verify(x => x.ConfirmEmailAsync(user, token), Times.Once);
    }

    [Fact]
    public async Task ResetPasswordAsync_WithValidToken_ShouldReturnTrue()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var userId = "user123";
        var token = "valid-token";
        var newPassword = "NewPassword123!";

        _mockUserManager.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.ResetPasswordAsync(user, token, newPassword))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await service.ResetPasswordAsync(userId, token, newPassword);

        // Assert
        Assert.True(result);
        _mockUserManager.Verify(x => x.ResetPasswordAsync(user, token, newPassword), Times.Once);
    }

    [Fact]
    public async Task ResetPasswordAsync_WithInvalidToken_ShouldReturnFalse()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        var userId = "user123";
        var token = "invalid-token";
        var newPassword = "NewPassword123!";

        var errors = new[]
        {
            new IdentityError { Code = "InvalidToken", Description = "Invalid token" }
        };

        _mockUserManager.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(user);
        _mockUserManager.Setup(x => x.ResetPasswordAsync(user, token, newPassword))
            .ReturnsAsync(IdentityResult.Failed(errors));

        // Act
        var result = await service.ResetPasswordAsync(userId, token, newPassword);

        // Assert
        Assert.False(result);
        _mockUserManager.Verify(x => x.ResetPasswordAsync(user, token, newPassword), Times.Once);
    }

    [Fact]
    public async Task SendEmailConfirmationAsync_WithNonExistentUser_ShouldReturnTrueButNotSendEmail()
    {
        // Arrange
        var service = CreateService();
        var email = "nonexistent@example.com";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((AuthUser)null!);

        // Act
        var result = await service.SendEmailConfirmationAsync(email);

        // Assert
        Assert.True(result); // Returns true to prevent user enumeration
        _mockEmailService.Verify(x => x.SendEmailConfirmationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()), 
            Times.Never);
    }

    [Fact]
    public async Task SendEmailConfirmationAsync_WithAlreadyConfirmedEmail_ShouldReturnTrue()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        user.EmailConfirmed = true; // Already confirmed
        var email = "test@example.com";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        // Act
        var result = await service.SendEmailConfirmationAsync(email);

        // Assert
        Assert.True(result);
        _mockEmailService.Verify(x => x.SendEmailConfirmationAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()), 
            Times.Never);
    }

    [Fact]
    public async Task SendPasswordResetAsync_WithNonExistentUser_ShouldReturnTrueButNotSendEmail()
    {
        // Arrange
        var service = CreateService();
        var email = "nonexistent@example.com";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync((AuthUser)null!);

        // Act
        var result = await service.SendPasswordResetAsync(email);

        // Assert
        Assert.True(result); // Returns true to prevent user enumeration
        _mockEmailService.Verify(x => x.SendPasswordResetAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()), 
            Times.Never);
    }

    [Fact]
    public async Task SendPasswordResetAsync_WithUnconfirmedEmail_ShouldReturnTrueButNotSendEmail()
    {
        // Arrange
        var service = CreateService();
        var user = CreateTestUser();
        user.EmailConfirmed = false; // Email not confirmed
        var email = "test@example.com";

        _mockUserManager.Setup(x => x.FindByEmailAsync(email))
            .ReturnsAsync(user);

        // Act
        var result = await service.SendPasswordResetAsync(email);

        // Assert
        Assert.True(result); // Returns true to prevent user enumeration
        _mockEmailService.Verify(x => x.SendPasswordResetAsync(
            It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<BrandingContext>()), 
            Times.Never);
    }
}