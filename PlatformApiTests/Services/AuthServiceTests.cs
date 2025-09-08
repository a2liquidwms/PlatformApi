using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformStarterCommon.Core.Common.Services;
using PlatformStarterCommon.Core.Common.Tenant;
using PlatformApi.Data;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Models.Messages;
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Services
{
    public class AuthServiceTests : IDisposable
    {
        private readonly Mock<UserManager<AuthUser>> _mockUserManager;
        private readonly Mock<SignInManager<AuthUser>> _mockSignInManager;
        private readonly Mock<IConfiguration> _mockConfiguration;
        private readonly Mock<ILogger<AuthService>> _mockLogger;
        private readonly PlatformDbContext _context;
        private readonly Mock<IUnitOfWork<PlatformDbContext>> _mockUow;
        private readonly Mock<TenantHelper> _mockTenantHelper;
        private readonly Mock<IUserService> _mockUserService;
        private readonly Mock<ITenantService> _mockTenantService;
        private readonly Mock<IEmailContentService> _mockEmailContentService;
        private readonly Mock<IEmailService> _mockEmailService;
        private readonly Mock<ISnsService> _mockSnsService;
        private readonly AuthService _authService;

        public AuthServiceTests()
        {
            // Create in-memory database
            var options = new DbContextOptionsBuilder<PlatformDbContext>()
                .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
                .Options;
            _context = new PlatformDbContext(options);

            // Mock UserManager
            var userStore = new Mock<IUserStore<AuthUser>>();
            _mockUserManager = new Mock<UserManager<AuthUser>>(
                userStore.Object, null!, null!, null!, null!, null!, null!, null!, null!);

            // Mock SignInManager
            var contextAccessor = new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>();
            var userClaimsPrincipalFactory = new Mock<IUserClaimsPrincipalFactory<AuthUser>>();
            _mockSignInManager = new Mock<SignInManager<AuthUser>>(
                _mockUserManager.Object, contextAccessor.Object, userClaimsPrincipalFactory.Object,
                null!, null!, null!, null!);

            // Mock other dependencies
            _mockConfiguration = new Mock<IConfiguration>();
            _mockLogger = new Mock<ILogger<AuthService>>();
            _mockUow = new Mock<IUnitOfWork<PlatformDbContext>>();
            _mockTenantHelper = new Mock<TenantHelper>(null!, null!);
            _mockUserService = new Mock<IUserService>();
            _mockTenantService = new Mock<ITenantService>();
            _mockEmailContentService = new Mock<IEmailContentService>();
            _mockEmailService = new Mock<IEmailService>();
            _mockSnsService = new Mock<ISnsService>();

            // Setup configuration defaults
            _mockConfiguration.Setup(x => x["AUTH_REFRESH_TOKEN_DAYS"]).Returns("180");
            _mockConfiguration.Setup(x => x["AUTH_ACCESS_TOKEN_MINUTES"]).Returns("5");
            _mockConfiguration.Setup(x => x["JWT_ISSUER"]).Returns("test-issuer");
            _mockConfiguration.Setup(x => x["JWT_AUDIENCE"]).Returns("test-audience");
            _mockConfiguration.Setup(x => x["JWT_SECRET"]).Returns("this-is-a-very-long-secret-key-for-testing-purposes-only");

            _authService = new AuthService(
                _mockUserManager.Object,
                _mockSignInManager.Object,
                _mockConfiguration.Object,
                _mockLogger.Object,
                _context,
                _mockUow.Object,
                _mockTenantHelper.Object,
                _mockUserService.Object,
                _mockTenantService.Object,
                _mockEmailContentService.Object,
                _mockEmailService.Object,
                _mockSnsService.Object);
        }

        public void Dispose()
        {
            _context.Dispose();
        }

        #region Register Tests

        [Fact]
        public async Task Register_ReturnsSuccess_WhenUserCreatedSuccessfully()
        {
            // Arrange
            var user = new AuthUser { UserName = "test@example.com", Email = "test@example.com", EmailConfirmed = true };
            var password = "Password123!";
            var tenantId = Guid.NewGuid();

            _mockUserService.Setup(x => x.CreateUserAsync(user, password))
                .ReturnsAsync(IdentityResult.Success);

            _mockEmailContentService.Setup(x => x.PrepareEmailConfirmationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<Guid?>(), It.IsAny<string?>()))
                .ReturnsAsync(new EmailContent 
                { 
                    ToEmail = "test@example.com", 
                    Subject = "Confirm", 
                    HtmlBody = "Body",
                    Branding = new BrandingContext()
                });

            _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<EmailContent>()))
                .ReturnsAsync(true);

            // Act
            var result = await _authService.Register(user, password, null, tenantId);

            // Assert
            Assert.True(result.Succeeded);
            _mockUserService.Verify(x => x.CreateUserAsync(user, password), Times.Once);
        }

        [Fact]
        public async Task Register_ReturnsFailure_WhenUserCreationFails()
        {
            // Arrange
            var user = new AuthUser { UserName = "test@example.com", Email = "test@example.com", EmailConfirmed = true };
            var password = "weak";
            var identityError = new IdentityError { Code = "PasswordTooWeak", Description = "Password is too weak" };

            _mockUserService.Setup(x => x.CreateUserAsync(user, password))
                .ReturnsAsync(IdentityResult.Failed(identityError));

            // Act
            var result = await _authService.Register(user, password);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Contains(result.Errors, e => e.Code == "PasswordTooWeak");
        }

        #endregion

        #region Login Tests

        [Fact]
        public async Task Login_ReturnsTokenBundle_WhenCredentialsValid()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123!";
            var user = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = email, 
                Email = email, 
                EmailConfirmed = true 
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            _mockUserService.Setup(x => x.GetUserTenantCount(user.Id))
                .ReturnsAsync(1);

            // Act
            var result = await _authService.Login(email, password);

            // Assert
            Assert.NotNull(result);
            Assert.NotNull(result.AccessToken);
            Assert.NotNull(result.RefreshToken);
            Assert.Equal("Bearer", result.TokenType);
        }

        [Fact]
        public async Task Login_ThrowsException_WhenUserNotFound()
        {
            // Arrange
            var email = "nonexistent@example.com";
            var password = "Password123!";

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync((AuthUser?)null);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(email, password));
            Assert.Equal("Invalid login", exception.Message);
        }

        [Fact]
        public async Task Login_ThrowsException_WhenEmailNotConfirmed()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123!";
            var user = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = email, 
                Email = email, 
                EmailConfirmed = false 
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(email, password));
            Assert.Contains("Email not confirmed", exception.Message);
        }

        [Fact]
        public async Task Login_ThrowsException_WhenPasswordInvalid()
        {
            // Arrange
            var email = "test@example.com";
            var password = "WrongPassword";
            var user = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = email, 
                Email = email, 
                EmailConfirmed = true 
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Failed);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(email, password));
            Assert.Equal("Invalid login", exception.Message);
        }

        [Fact]
        public async Task Login_ValidatesTenantAccess_WhenTenantIdProvided()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123!";
            var tenantId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = email, 
                Email = email, 
                EmailConfirmed = true 
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            _mockUserService.Setup(x => x.HasTenantAccess(user.Id, tenantId, true))
                .ReturnsAsync(false);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(email, password, tenantId));
            Assert.Equal("Tenant access denied", exception.Message);
        }

        #endregion

        #region Refresh Token Tests

        [Fact]
        public async Task RefreshToken_ReturnsNewTokenBundle_WhenTokenValid()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var refreshToken = "valid-refresh-token";
            var user = new AuthUser { Id = userId, UserName = "test@example.com", Email = "test@example.com", EmailConfirmed = true };

            var storedToken = new RefreshToken
            {
                Token = refreshToken,
                UserId = userId,
                Expires = DateTime.UtcNow.AddDays(30),
                IsRevoked = false,
                TenantId = null,
                SiteId = null
            };

            _context.RefreshTokens.Add(storedToken);
            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(0);

            // Act
            var result = await _authService.RefreshToken(refreshToken);

            // Assert
            Assert.NotNull(result);
            Assert.NotNull(result.AccessToken);
            Assert.NotNull(result.RefreshToken);
            Assert.NotEqual(refreshToken, result.RefreshToken); // Should be a new refresh token

            // Verify old token was revoked
            var revokedToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == refreshToken);
            Assert.True(revokedToken?.IsRevoked);
        }

        [Fact]
        public async Task RefreshToken_ThrowsUnauthorized_WhenTokenNotFound()
        {
            // Arrange
            var refreshToken = "non-existent-token";

            // Act & Assert
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => _authService.RefreshToken(refreshToken));
        }

        [Fact]
        public async Task RefreshToken_ThrowsUnauthorized_WhenTokenExpired()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var refreshToken = "expired-refresh-token";

            var expiredToken = new RefreshToken
            {
                Token = refreshToken,
                UserId = userId,
                Expires = DateTime.UtcNow.AddDays(-1), // Expired
                IsRevoked = false
            };

            _context.RefreshTokens.Add(expiredToken);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => _authService.RefreshToken(refreshToken));
        }

        [Fact]
        public async Task RefreshToken_ThrowsUnauthorized_WhenTokenRevoked()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var refreshToken = "revoked-refresh-token";

            var revokedToken = new RefreshToken
            {
                Token = refreshToken,
                UserId = userId,
                Expires = DateTime.UtcNow.AddDays(30),
                IsRevoked = true // Already revoked
            };

            _context.RefreshTokens.Add(revokedToken);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => _authService.RefreshToken(refreshToken));
        }

        #endregion

        #region Logout Tests

        [Fact]
        public async Task Logout_RevokesAllUserTokens_WhenSuccessful()
        {
            // Arrange
            var userId = Guid.NewGuid();

            var tokens = new[]
            {
                new RefreshToken { Token = "token1", UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = "token2", UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = "token3", UserId = Guid.NewGuid(), IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) } // Different user
            };

            _context.RefreshTokens.AddRange(tokens);
            await _context.SaveChangesAsync();

            _mockUow.Setup(x => x.CompleteAsync()).Returns(Task.CompletedTask);

            // Act
            var result = await _authService.Logout(userId);

            // Assert
            Assert.True(result);

            var userTokens = _context.RefreshTokens.Where(rt => rt.UserId == userId).ToList();
            Assert.All(userTokens, token => Assert.True(token.IsRevoked));

            // Verify other user's token was not affected
            var otherUserToken = _context.RefreshTokens.First(rt => rt.UserId != userId);
            Assert.False(otherUserToken.IsRevoked);

            _mockUow.Verify(x => x.CompleteAsync(), Times.Once);
        }

        [Fact]
        public async Task Logout_ReturnsFalse_WhenExceptionOccurs()
        {
            // Arrange
            var userId = Guid.NewGuid();

            _mockUow.Setup(x => x.CompleteAsync())
                .ThrowsAsync(new Exception("Database error"));

            // Act
            var result = await _authService.Logout(userId);

            // Assert
            Assert.False(result);
        }

        #endregion

        #region Email Confirmation Tests

        [Fact]
        public async Task SendEmailConfirmationAsync_SendsEmail_WhenUserExists()
        {
            // Arrange
            var email = "test@example.com";
            var user = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = email, 
                Email = email, 
                EmailConfirmed = false 
            };
            var token = "confirmation-token";

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockUserManager.Setup(x => x.GenerateEmailConfirmationTokenAsync(user))
                .ReturnsAsync(token);

            _mockEmailContentService.Setup(x => x.PrepareEmailConfirmationAsync(
                email, token, user.Id, user.UserName ?? email, It.IsAny<Guid?>(), It.IsAny<string?>()))
                .ReturnsAsync(new EmailContent { 
                    ToEmail = email, 
                    Subject = "Confirm", 
                    HtmlBody = "Body",
                    Branding = new BrandingContext() 
                });

            _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<EmailContent>()))
                .ReturnsAsync(true);

            // Act
            var result = await _authService.SendEmailConfirmationAsync(email);

            // Assert
            Assert.True(result);
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Once);
        }

        [Fact]
        public async Task SendEmailConfirmationAsync_ReturnsTrue_WhenUserNotFound()
        {
            // Arrange
            var email = "nonexistent@example.com";

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync((AuthUser?)null);

            // Act
            var result = await _authService.SendEmailConfirmationAsync(email);

            // Assert
            Assert.True(result); // Should return true to not reveal user existence
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Never);
        }

        [Fact]
        public async Task ConfirmEmailAsync_ReturnsTrue_WhenTokenValid()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var token = "valid-token";
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserManager.Setup(x => x.ConfirmEmailAsync(user, token))
                .ReturnsAsync(IdentityResult.Success);

            _mockEmailContentService.Setup(x => x.PrepareWelcomeEmailAsync(
                user.Email!, user.UserName ?? user.Email!, It.IsAny<Guid?>()))
                .ReturnsAsync(new EmailContent 
                { 
                    ToEmail = user.Email!, 
                    Subject = "Welcome", 
                    HtmlBody = "Welcome",
                    Branding = new BrandingContext()
                });

            _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<EmailContent>()))
                .ReturnsAsync(true);

            // Act
            var result = await _authService.ConfirmEmailAsync(userId, token);

            // Assert
            Assert.True(result);
            _mockUserManager.Verify(x => x.ConfirmEmailAsync(user, token), Times.Once);
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Once);
        }

        [Fact]
        public async Task ConfirmEmailAsync_ReturnsFalse_WhenUserNotFound()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var token = "valid-token";

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync((AuthUser?)null);

            // Act
            var result = await _authService.ConfirmEmailAsync(userId, token);

            // Assert
            Assert.False(result);
            _mockUserManager.Verify(x => x.ConfirmEmailAsync(It.IsAny<AuthUser>(), It.IsAny<string>()), Times.Never);
        }

        #endregion

        #region Password Reset Tests

        [Fact]
        public async Task SendPasswordResetAsync_SendsEmail_WhenUserExistsAndConfirmed()
        {
            // Arrange
            var email = "test@example.com";
            var user = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = email, 
                Email = email, 
                EmailConfirmed = true 
            };
            var token = "reset-token";

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockUserManager.Setup(x => x.GeneratePasswordResetTokenAsync(user))
                .ReturnsAsync(token);

            _mockEmailContentService.Setup(x => x.PreparePasswordResetAsync(
                email, token, user.Id, user.UserName ?? email, It.IsAny<Guid?>(), It.IsAny<string?>()))
                .ReturnsAsync(new EmailContent 
                { 
                    ToEmail = email, 
                    Subject = "Reset", 
                    HtmlBody = "Reset",
                    Branding = new BrandingContext()
                });

            _mockEmailService.Setup(x => x.SendEmailAsync(It.IsAny<EmailContent>()))
                .ReturnsAsync(true);

            // Act
            var result = await _authService.SendPasswordResetAsync(email);

            // Assert
            Assert.True(result);
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Once);
        }

        [Fact]
        public async Task ResetPasswordAsync_ReturnsTrue_WhenTokenValid()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var token = "valid-reset-token";
            var newPassword = "NewPassword123!";
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserManager.Setup(x => x.ResetPasswordAsync(user, token, newPassword))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _authService.ResetPasswordAsync(userId, token, newPassword);

            // Assert
            Assert.True(result);
            _mockUserManager.Verify(x => x.ResetPasswordAsync(user, token, newPassword), Times.Once);
        }

        #endregion

        #region JWT Token Tests

        [Fact]
        public async Task Login_GeneratesValidJwtToken_WithCorrectClaims()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123!";
            var userId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = email, 
                Email = email, 
                EmailConfirmed = true 
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(2);

            // Act
            var result = await _authService.Login(email, password);

            // Assert
            Assert.NotNull(result.AccessToken);

            // Validate JWT token structure
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.ReadJwtToken(result.AccessToken);

            Assert.Equal(userId.ToString(), jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Sub).Value);
            Assert.Equal(email, jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Email).Value);
            Assert.Equal(userId.ToString(), jwt.Claims.First(c => c.Type == CommonConstants.ClaimUserId).Value);
            Assert.Equal("2", jwt.Claims.First(c => c.Type == CommonConstants.TenantCountClaim).Value);
        }

        [Fact]
        public async Task RefreshToken_GeneratesValidJwtToken_WithSameClaims()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var tenantId = Guid.NewGuid();
            var refreshToken = "valid-refresh-token";
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            var storedToken = new RefreshToken
            {
                Token = refreshToken,
                UserId = userId,
                TenantId = tenantId,
                SiteId = null,
                Expires = DateTime.UtcNow.AddDays(30),
                IsRevoked = false
            };

            _context.RefreshTokens.Add(storedToken);
            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(1);

            _mockUserService.Setup(x => x.GetUserSiteCount(userId, tenantId))
                .ReturnsAsync(3);

            // Act
            var result = await _authService.RefreshToken(refreshToken);

            // Assert
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.ReadJwtToken(result.AccessToken);

            Assert.Equal(userId.ToString(), jwt.Claims.First(c => c.Type == CommonConstants.ClaimUserId).Value);
            Assert.Equal(tenantId.ToString(), jwt.Claims.First(c => c.Type == CommonConstants.ActiveTenantClaim).Value);
            Assert.Equal("3", jwt.Claims.First(c => c.Type == CommonConstants.SiteCountClaim).Value);
        }

        #endregion

        #region Security Edge Cases

        [Fact]
        public async Task Login_ThrowsException_WhenSiteProvidedWithoutTenant()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123!";
            var siteId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = email, 
                Email = email, 
                EmailConfirmed = true 
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(email, password, null, siteId));
            Assert.Equal("Cannot login to site without specifying tenant", exception.Message);
        }

        [Fact]
        public async Task RefreshToken_RevokesAllOtherTokens_WhenRefreshing()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var activeToken = "active-token";
            var otherToken1 = "other-token-1";
            var otherToken2 = "other-token-2";

            var tokens = new[]
            {
                new RefreshToken { Token = activeToken, UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = otherToken1, UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = otherToken2, UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) }
            };

            _context.RefreshTokens.AddRange(tokens);
            await _context.SaveChangesAsync();

            var user = new AuthUser { Id = userId, UserName = "test@example.com", Email = "test@example.com", EmailConfirmed = true };
            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString())).ReturnsAsync(user);
            _mockUserService.Setup(x => x.GetUserTenantCount(userId)).ReturnsAsync(1);

            // Act
            await _authService.RefreshToken(activeToken);

            // Assert
            var allTokens = _context.RefreshTokens.Where(rt => rt.UserId == userId).ToList();
            Assert.All(allTokens, token => Assert.True(token.IsRevoked));
        }

        #endregion

        #region Permission and Role Context Tests

        [Fact]
        public async Task GetUserPermissionsAsync_ReturnsPermissions_WhenUserExists()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var tenantId = Guid.NewGuid();
            var siteId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            // Create test roles with permissions
            var role1 = new Role
            {
                Id = Guid.NewGuid(),
                Name = "TestRole1",
                Scope = RoleScope.Tenant,
                TenantId = tenantId,
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission { RoleId = Guid.NewGuid(), PermissionCode = "read:data", Permission = new Permission { Code = "read:data" } },
                    new RolePermission { RoleId = Guid.NewGuid(), PermissionCode = "write:data", Permission = new Permission { Code = "write:data" } }
                }
            };

            var role2 = new Role
            {
                Id = Guid.NewGuid(),
                Name = "TestRole2",
                Scope = RoleScope.Site,
                TenantId = tenantId,
                SiteId = siteId,
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission { RoleId = Guid.NewGuid(), PermissionCode = "manage:users", Permission = new Permission { Code = "manage:users" } }
                }
            };

            // Add roles to context
            _context.Roles.AddRange(role1, role2);

            // Add user role assignments
            var userRoles = new[]
            {
                new UserRoles { UserId = userId, RoleId = role1.Id, Scope = RoleScope.Tenant, TenantId = tenantId },
                new UserRoles { UserId = userId, RoleId = role2.Id, Scope = RoleScope.Site, TenantId = tenantId, SiteId = siteId }
            };
            _context.UserRoles.AddRange(userRoles);

            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            // Act
            var permissions = await _authService.GetUserPermissionsAsync(userId, tenantId, siteId);

            // Assert
            var permissionList = permissions.ToList();
            Assert.Contains("read:data", permissionList);
            Assert.Contains("write:data", permissionList);
            Assert.Contains("manage:users", permissionList);
            Assert.Equal(3, permissionList.Count);
        }

        [Fact]
        public async Task GetUserRolesAsync_ReturnsRoles_WhenUserExists()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var tenantId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            // Create test roles
            var role1 = new Role
            {
                Id = Guid.NewGuid(),
                Name = "TenantAdmin",
                Description = "Tenant Administrator",
                Scope = RoleScope.Tenant,
                TenantId = tenantId,
                IsSystemRole = false
            };

            var role2 = new Role
            {
                Id = Guid.NewGuid(),
                Name = "DefaultUser",
                Description = "Default User Role",
                Scope = RoleScope.Default,
                TenantId = null,
                IsSystemRole = true
            };

            _context.Roles.AddRange(role1, role2);

            // Add user role assignments
            var userRoles = new[]
            {
                new UserRoles { UserId = userId, RoleId = role1.Id, Scope = RoleScope.Tenant, TenantId = tenantId }
            };
            _context.UserRoles.AddRange(userRoles);

            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            // Act
            var roles = await _authService.GetUserRolesAsync(userId, tenantId);

            // Assert
            var roleList = roles.ToList();
            Assert.Contains(roleList, r => r.Name == "TenantAdmin");
            Assert.Contains(roleList, r => r.Name == "DefaultUser");
            Assert.True(roleList.Any(r => r.IsSystemRole));
            Assert.True(roleList.Any(r => !r.IsSystemRole));
        }

        [Fact]
        public async Task SwitchTenant_ReturnsNewTokenBundle_WhenUserHasAccess()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var tenantId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            // Add existing refresh token
            var existingToken = new RefreshToken
            {
                Token = "old-token",
                UserId = userId,
                TenantId = null,
                IsRevoked = false,
                Expires = DateTime.UtcNow.AddDays(30)
            };
            _context.RefreshTokens.Add(existingToken);
            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.HasTenantAccess(userId, tenantId, true))
                .ReturnsAsync(true);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(2);

            _mockUserService.Setup(x => x.GetUserSiteCount(userId, tenantId))
                .ReturnsAsync(1);

            // Mock UOW to actually save changes to the in-memory database
            _mockUow.Setup(x => x.CompleteAsync()).Returns(async () => await _context.SaveChangesAsync());

            // Act
            var result = await _authService.SwitchTenant(userId, tenantId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(tenantId, result.TenantId);

            // Verify old tokens were revoked
            var revokedTokens = _context.RefreshTokens.Where(rt => rt.UserId == userId && rt.IsRevoked).ToList();
            Assert.Single(revokedTokens);

            // Verify JWT contains tenant claim
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.ReadJwtToken(result.AccessToken);
            Assert.Equal(tenantId.ToString(), jwt.Claims.First(c => c.Type == CommonConstants.ActiveTenantClaim).Value);
        }

        [Fact]
        public async Task SwitchTenant_ThrowsNotFoundException_WhenUserNotFound()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var tenantId = Guid.NewGuid();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync((AuthUser?)null);

            // Act & Assert
            await Assert.ThrowsAsync<NotFoundException>(
                () => _authService.SwitchTenant(userId, tenantId));
        }

        [Fact]
        public async Task SwitchTenant_ThrowsInvalidDataException_WhenUserLacksAccess()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var tenantId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.HasTenantAccess(userId, tenantId, true))
                .ReturnsAsync(false);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.SwitchTenant(userId, tenantId));
            Assert.Equal("User is not assigned to this tenant", exception.Message);
        }

        [Fact]
        public async Task SwitchSite_ReturnsNewTokenBundle_WhenUserHasAccess()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var tenantId = Guid.NewGuid();
            var siteId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            // Add site to context
            var site = new Site
            {
                Id = siteId,
                TenantId = tenantId,
                Name = "Test Site",
                Code = "test-site",
                IsActive = true
            };
            _context.Sites.Add(site);
            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.HasSiteAccess(userId, siteId, tenantId, true))
                .ReturnsAsync(true);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(1);

            _mockUserService.Setup(x => x.GetUserSiteCount(userId, tenantId))
                .ReturnsAsync(3);

            // Act
            var result = await _authService.SwitchSite(userId, siteId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(tenantId, result.TenantId);
            Assert.Equal(siteId, result.SiteId);

            // Verify JWT contains both tenant and site claims
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.ReadJwtToken(result.AccessToken);
            Assert.Equal(tenantId.ToString(), jwt.Claims.First(c => c.Type == CommonConstants.ActiveTenantClaim).Value);
            Assert.Equal(siteId.ToString(), jwt.Claims.First(c => c.Type == CommonConstants.ActiveSiteClaim).Value);
        }

        [Fact]
        public async Task SwitchSite_ThrowsNotFoundException_WhenSiteNotFound()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var siteId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<NotFoundException>(
                () => _authService.SwitchSite(userId, siteId));
            Assert.Equal("Site not found or inactive", exception.Message);
        }

        #endregion

        #region Invitation Registration Tests

        [Fact]
        public async Task RegisterViaInvitationAsync_CompletesPlaceholderUser_WhenUserExistsWithoutPassword()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123!";
            var invitationToken = "valid-invitation-token";
            var tenantId = Guid.NewGuid();

            var existingUser = new AuthUser 
            { 
                Id = Guid.NewGuid(),
                UserName = email, 
                Email = email,
                PasswordHash = null // Placeholder user without password
            };

            var invitation = new UserInvitation
            {
                Id = Guid.NewGuid(),
                Email = email,
                InvitationToken = invitationToken,
                TenantId = tenantId,
                Scope = RoleScope.Tenant,
                IsUsed = false,
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            };

            _context.UserInvitations.Add(invitation);
            await _context.SaveChangesAsync();

            _mockUserService.Setup(x => x.ValidateInvitationTokenAsync(invitationToken))
                .ReturnsAsync(invitation);

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(existingUser);

            _mockUserManager.Setup(x => x.AddPasswordAsync(existingUser, password))
                .ReturnsAsync(IdentityResult.Success);

            _mockUserManager.Setup(x => x.UpdateAsync(existingUser))
                .ReturnsAsync(IdentityResult.Success);

            _mockUow.Setup(x => x.CompleteAsync()).Returns(Task.CompletedTask);

            var request = new RegisterViaInvitationRequest
            {
                Email = email,
                Password = password,
                InvitationToken = invitationToken
            };

            // Act
            var result = await _authService.RegisterViaInvitationAsync(request);

            // Assert
            Assert.True(result.Succeeded);
            _mockUserManager.Verify(x => x.AddPasswordAsync(existingUser, password), Times.Once);
            _mockUserManager.Verify(x => x.UpdateAsync(existingUser), Times.Once);

            // Verify invitation was marked as used
            var updatedInvitation = await _context.UserInvitations.FindAsync(invitation.Id);
            Assert.True(updatedInvitation?.IsUsed);
        }

        [Fact]
        public async Task RegisterViaInvitationAsync_ReturnsFailure_WhenInvitationInvalid()
        {
            // Arrange
            var request = new RegisterViaInvitationRequest
            {
                Email = "test@example.com",
                Password = "Password123!",
                InvitationToken = "invalid-token"
            };

            _mockUserService.Setup(x => x.ValidateInvitationTokenAsync("invalid-token"))
                .ReturnsAsync((UserInvitation?)null);

            // Act
            var result = await _authService.RegisterViaInvitationAsync(request);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Contains(result.Errors, e => e.Code == "InvalidInvitation");
        }

        [Fact]
        public async Task RegisterViaInvitationAsync_ReturnsFailure_WhenEmailMismatch()
        {
            // Arrange
            var invitationEmail = "invitation@example.com";
            var requestEmail = "different@example.com";
            var invitationToken = "valid-invitation-token";

            var invitation = new UserInvitation
            {
                Email = invitationEmail,
                InvitationToken = invitationToken,
                TenantId = Guid.NewGuid(),
                Scope = RoleScope.Tenant,
                IsUsed = false,
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            };

            _mockUserService.Setup(x => x.ValidateInvitationTokenAsync(invitationToken))
                .ReturnsAsync(invitation);

            var request = new RegisterViaInvitationRequest
            {
                Email = requestEmail,
                Password = "Password123!",
                InvitationToken = invitationToken
            };

            // Act
            var result = await _authService.RegisterViaInvitationAsync(request);

            // Assert
            Assert.False(result.Succeeded);
            Assert.Contains(result.Errors, e => e.Code == "EmailMismatch");
        }

        #endregion
    }
}