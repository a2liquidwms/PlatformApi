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
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Services
{
    public class AuthServiceSecurityTests : IDisposable
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

        public AuthServiceSecurityTests()
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

        #region JWT Security Tests

        [Fact]
        public async Task Login_GeneratesUniqueJtiClaims_ForMultipleTokens()
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
                .ReturnsAsync(1);

            // Act - Generate two tokens
            var result1 = await _authService.Login(email, password);
            var result2 = await _authService.Login(email, password);

            // Assert - Verify different JTI claims (unique token IDs)
            var handler = new JwtSecurityTokenHandler();
            var jwt1 = handler.ReadJwtToken(result1.AccessToken);
            var jwt2 = handler.ReadJwtToken(result2.AccessToken);

            var jti1 = jwt1.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
            var jti2 = jwt2.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;

            Assert.NotEqual(jti1, jti2);
        }

        [Fact]
        public async Task Login_TokenExpiration_IsWithinConfiguredTimeframe()
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

            // Create new configuration mock with 15-minute expiration
            var configMock = new Mock<IConfiguration>();
            configMock.Setup(x => x["AUTH_REFRESH_TOKEN_DAYS"]).Returns("180");
            configMock.Setup(x => x["AUTH_ACCESS_TOKEN_MINUTES"]).Returns("15"); // 15 minutes
            configMock.Setup(x => x["JWT_ISSUER"]).Returns("test-issuer");
            configMock.Setup(x => x["JWT_AUDIENCE"]).Returns("test-audience");
            configMock.Setup(x => x["JWT_SECRET"]).Returns("this-is-a-very-long-secret-key-for-testing-purposes-only");

            // Create new AuthService instance with correct configuration
            var authService = new AuthService(
                _mockUserManager.Object,
                _mockSignInManager.Object,
                configMock.Object,
                _mockLogger.Object,
                _context,
                _mockUow.Object,
                _mockTenantHelper.Object,
                _mockUserService.Object,
                _mockTenantService.Object,
                _mockEmailContentService.Object,
                _mockEmailService.Object,
                _mockSnsService.Object);

            _mockUserManager.Setup(x => x.FindByEmailAsync(email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, password, false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(1);

            var beforeLogin = DateTime.UtcNow;

            // Act
            var result = await authService.Login(email, password);

            // Assert
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(result.AccessToken);

            var expClaim = jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Exp).Value;
            var expTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).DateTime;

            // Token should expire within 15-16 minutes from now (allowing 1 minute buffer)
            Assert.True(expTime > beforeLogin.AddMinutes(14));
            Assert.True(expTime < beforeLogin.AddMinutes(16));
        }

        [Fact]
        public async Task RefreshToken_GeneratesUrlSafeToken()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var user = new AuthUser { Id = userId, UserName = "test@example.com", Email = "test@example.com", EmailConfirmed = true };

            _mockUserManager.Setup(x => x.FindByEmailAsync(user.Email))
                .ReturnsAsync(user);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(user, "Password123!", false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Success);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(1);

            // Act
            var result = await _authService.Login(user.Email, "Password123!");

            // Assert - Refresh token should be URL-safe (no +, /, = characters)
            Assert.DoesNotContain("+", result.RefreshToken);
            Assert.DoesNotContain("/", result.RefreshToken);
            Assert.DoesNotContain("=", result.RefreshToken);
            Assert.True(result.RefreshToken!.Length > 50); // Should be reasonably long
        }

        #endregion

        #region Tenant Isolation Tests

        [Fact]
        public async Task Login_EnforcesTenantIsolation_WhenUserNotInTenant()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123!";
            var userId = Guid.NewGuid();
            var forbiddenTenantId = Guid.NewGuid();
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

            // User has no access to this tenant
            _mockUserService.Setup(x => x.HasTenantAccess(userId, forbiddenTenantId, true))
                .ReturnsAsync(false);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(email, password, forbiddenTenantId));
            Assert.Equal("Tenant access denied", exception.Message);
        }

        [Fact]
        public async Task SwitchTenant_PreventsUnauthorizedTenantAccess()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var forbiddenTenantId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            // User has no access to this tenant
            _mockUserService.Setup(x => x.HasTenantAccess(userId, forbiddenTenantId, true))
                .ReturnsAsync(false);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.SwitchTenant(userId, forbiddenTenantId));
            Assert.Equal("User is not assigned to this tenant", exception.Message);
        }

        [Fact]
        public async Task SwitchSite_ValidatesTenantOwnershipOfSite()
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

            // Create site belonging to a different tenant
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

            // User has no access to this site in this tenant
            _mockUserService.Setup(x => x.HasSiteAccess(userId, siteId, tenantId, true))
                .ReturnsAsync(false);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.SwitchSite(userId, siteId));
            Assert.Equal("User not assigned to this site", exception.Message);
        }

        #endregion

        #region Permission Escalation Prevention Tests

        [Fact]
        public async Task GetUserPermissionsAsync_OnlyReturnsAuthorizedPermissions()
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

            // Create roles - user only has access to limited role
            var userRole = new Role
            {
                Id = Guid.NewGuid(),
                Name = "BasicUser",
                Scope = RoleScope.Tenant,
                TenantId = tenantId,
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission { RoleId = Guid.NewGuid(), PermissionCode = "read:data", Permission = new Permission { Code = "read:data" } }
                }
            };

            var adminRole = new Role
            {
                Id = Guid.NewGuid(),
                Name = "Admin",
                Scope = RoleScope.Tenant,
                TenantId = tenantId,
                RolePermissions = new List<RolePermission>
                {
                    new RolePermission { RoleId = Guid.NewGuid(), PermissionCode = "admin:delete", Permission = new Permission { Code = "admin:delete" } }
                }
            };

            _context.Roles.AddRange(userRole, adminRole);

            // User only has basic user role assignment
            var userRoleAssignment = new UserRoles 
            { 
                UserId = userId, 
                RoleId = userRole.Id, 
                Scope = RoleScope.Tenant, 
                TenantId = tenantId 
            };
            _context.UserRoles.Add(userRoleAssignment);

            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            // Act
            var permissions = await _authService.GetUserPermissionsAsync(userId, tenantId);

            // Assert - Should only get basic permissions, not admin permissions
            var permissionList = permissions.ToList();
            Assert.Contains("read:data", permissionList);
            Assert.DoesNotContain("admin:delete", permissionList);
            Assert.Single(permissionList);
        }

        #endregion

        #region Refresh Token Security Tests

        [Fact]
        public async Task RefreshToken_PreventsReplayAttacks_ByRevokingOldTokens()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var refreshToken = "valid-refresh-token";
            var user = new AuthUser { Id = userId, UserName = "test@example.com", Email = "test@example.com", EmailConfirmed = true };

            // Create multiple refresh tokens for the user
            var tokens = new[]
            {
                new RefreshToken { Token = refreshToken, UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = "other-token-1", UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = "other-token-2", UserId = userId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) }
            };

            _context.RefreshTokens.AddRange(tokens);
            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(1);

            // Mock UOW to actually save changes to the in-memory database
            _mockUow.Setup(x => x.CompleteAsync()).Returns(async () => await _context.SaveChangesAsync());

            // Act - Refresh the token
            var result = await _authService.RefreshToken(refreshToken);

            // Assert - All old tokens should be revoked
            var allTokens = _context.RefreshTokens.Where(rt => rt.UserId == userId).ToList();
            var revokedTokens = allTokens.Where(rt => rt.IsRevoked).ToList();
            var activeTokens = allTokens.Where(rt => !rt.IsRevoked).ToList();

            Assert.Equal(3, revokedTokens.Count); // All old tokens revoked
            Assert.Single(activeTokens); // Only the new token is active
            Assert.NotEqual(refreshToken, result.RefreshToken); // New token is different
        }

        [Fact]
        public async Task RefreshToken_RejectsTamperedTokens()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var originalToken = "valid-refresh-token";
            var tamperedToken = "tampered-refresh-token"; // Different token

            var storedToken = new RefreshToken
            {
                Token = originalToken, // Only this token exists in database
                UserId = userId,
                Expires = DateTime.UtcNow.AddDays(30),
                IsRevoked = false
            };

            _context.RefreshTokens.Add(storedToken);
            await _context.SaveChangesAsync();

            // Act & Assert - Tampered token should be rejected
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => _authService.RefreshToken(tamperedToken));
        }

        [Fact]
        public async Task RefreshToken_RejectsExpiredTokens_EvenIfNotRevoked()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var expiredToken = "expired-refresh-token";

            var storedToken = new RefreshToken
            {
                Token = expiredToken,
                UserId = userId,
                Expires = DateTime.UtcNow.AddDays(-1), // Expired yesterday
                IsRevoked = false // Not revoked, but expired
            };

            _context.RefreshTokens.Add(storedToken);
            await _context.SaveChangesAsync();

            // Act & Assert
            await Assert.ThrowsAsync<UnauthorizedAccessException>(
                () => _authService.RefreshToken(expiredToken));
        }

        #endregion

        #region Brute Force Protection Simulation

        [Fact]
        public async Task Login_ConsistentFailureResponse_PreventsUserEnumeration()
        {
            // Arrange
            var nonExistentEmail = "nonexistent@example.com";
            var existentEmail = "existent@example.com";
            var wrongPassword = "WrongPassword123!";

            // Setup existing user but with wrong password scenario
            var existingUser = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = existentEmail, 
                Email = existentEmail, 
                EmailConfirmed = true 
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(nonExistentEmail))
                .ReturnsAsync((AuthUser?)null);

            _mockUserManager.Setup(x => x.FindByEmailAsync(existentEmail))
                .ReturnsAsync(existingUser);

            _mockSignInManager.Setup(x => x.CheckPasswordSignInAsync(existingUser, wrongPassword, false))
                .ReturnsAsync(Microsoft.AspNetCore.Identity.SignInResult.Failed);

            // Act & Assert - Both scenarios should return same exception type and message
            var exception1 = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(nonExistentEmail, wrongPassword));

            var exception2 = await Assert.ThrowsAsync<InvalidDataException>(
                () => _authService.Login(existentEmail, wrongPassword));

            // Both should have same error message to prevent user enumeration
            Assert.Equal("Invalid login", exception1.Message);
            Assert.Equal("Invalid login", exception2.Message);
        }

        #endregion

        #region Email Security Tests

        [Fact]
        public async Task SendEmailConfirmationAsync_DoesNotRevealUserExistence()
        {
            // Arrange
            var nonExistentEmail = "nonexistent@example.com";

            _mockUserManager.Setup(x => x.FindByEmailAsync(nonExistentEmail))
                .ReturnsAsync((AuthUser?)null);

            // Act
            var result = await _authService.SendEmailConfirmationAsync(nonExistentEmail);

            // Assert - Should return true even for non-existent users to prevent user enumeration
            Assert.True(result);
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Never);
        }

        [Fact]
        public async Task SendPasswordResetAsync_DoesNotRevealUserExistence()
        {
            // Arrange
            var nonExistentEmail = "nonexistent@example.com";

            _mockUserManager.Setup(x => x.FindByEmailAsync(nonExistentEmail))
                .ReturnsAsync((AuthUser?)null);

            // Act
            var result = await _authService.SendPasswordResetAsync(nonExistentEmail);

            // Assert - Should return true even for non-existent users
            Assert.True(result);
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Never);
        }

        [Fact]
        public async Task SendPasswordResetAsync_DoesNotSendToUnconfirmedUsers()
        {
            // Arrange
            var unconfirmedEmail = "unconfirmed@example.com";
            var unconfirmedUser = new AuthUser 
            { 
                Id = Guid.NewGuid(), 
                UserName = unconfirmedEmail, 
                Email = unconfirmedEmail, 
                EmailConfirmed = false // Not confirmed
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(unconfirmedEmail))
                .ReturnsAsync(unconfirmedUser);

            // Act
            var result = await _authService.SendPasswordResetAsync(unconfirmedEmail);

            // Assert - Should return true but not send email
            Assert.True(result);
            _mockEmailService.Verify(x => x.SendEmailAsync(It.IsAny<EmailContent>()), Times.Never);
        }

        #endregion

        #region Registration Security Tests

        [Fact]
        public async Task RegisterViaInvitationAsync_ValidatesEmailMatchStrictly()
        {
            // Arrange
            var invitationEmail = "invitation@example.com";
            var attackerEmail = "INVITATION@EXAMPLE.COM"; // Case variation attack attempt
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
                Email = attackerEmail, // Different case
                Password = "Password123!",
                InvitationToken = invitationToken
            };

            // Act
            var result = await _authService.RegisterViaInvitationAsync(request);

            // Assert - Should fail due to email mismatch (case-sensitive check)
            Assert.False(result.Succeeded);
            Assert.Contains(result.Errors, e => e.Code == "EmailMismatch");
        }

        #endregion

        #region Context Switching Security Tests

        [Fact]
        public async Task SwitchSite_RequiresSiteToBeActive()
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

            // Create inactive site
            var inactiveSite = new Site
            {
                Id = siteId,
                TenantId = tenantId,
                Name = "Inactive Site",
                Code = "inactive-site",
                IsActive = false // Site is inactive
            };
            _context.Sites.Add(inactiveSite);
            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            // Act & Assert - Should reject access to inactive sites
            var exception = await Assert.ThrowsAsync<NotFoundException>(
                () => _authService.SwitchSite(userId, siteId));
            Assert.Equal("Site not found or inactive", exception.Message);
        }

        [Fact] 
        public async Task SwitchTenant_RevokesAllExistingTokens_PreventingSessionReuse()
        {
            // Arrange
            var userId = Guid.NewGuid();
            var oldTenantId = Guid.NewGuid();
            var newTenantId = Guid.NewGuid();
            var user = new AuthUser 
            { 
                Id = userId, 
                UserName = "test@example.com", 
                Email = "test@example.com" 
            };

            // Create multiple refresh tokens for different contexts
            var tokens = new[]
            {
                new RefreshToken { Token = "token-1", UserId = userId, TenantId = oldTenantId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = "token-2", UserId = userId, TenantId = null, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) },
                new RefreshToken { Token = "token-3", UserId = userId, TenantId = oldTenantId, IsRevoked = false, Expires = DateTime.UtcNow.AddDays(30) }
            };

            _context.RefreshTokens.AddRange(tokens);
            await _context.SaveChangesAsync();

            _mockUserManager.Setup(x => x.FindByIdAsync(userId.ToString()))
                .ReturnsAsync(user);

            _mockUserService.Setup(x => x.HasTenantAccess(userId, newTenantId, true))
                .ReturnsAsync(true);

            _mockUserService.Setup(x => x.GetUserTenantCount(userId))
                .ReturnsAsync(2);

            _mockUserService.Setup(x => x.GetUserSiteCount(userId, newTenantId))
                .ReturnsAsync(1);

            // Act
            await _authService.SwitchTenant(userId, newTenantId);

            // Assert - All old tokens should be revoked
            var allTokens = _context.RefreshTokens.Where(rt => rt.UserId == userId).ToList();
            var revokedTokens = allTokens.Where(rt => rt.IsRevoked).ToList();

            Assert.Equal(3, revokedTokens.Count); // All old tokens revoked
        }

        #endregion
    }
}