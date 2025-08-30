using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using PlatformStarterCommon.Core.Common.Tenant;
using PlatformStarterCommon.Core.Common.Constants;
using PlatformApi.Controllers;
using PlatformApi.Models;
using PlatformApi.Models.DTOs;
using PlatformApi.Services;
using Xunit;

namespace PlatformApiTests.Controllers;

public class AuthControllerEmailTests
{
    private readonly Mock<ILogger<AuthController>> _mockLogger;
    private readonly Mock<IAuthService> _mockAuthService;
    private readonly Mock<SignInManager<AuthUser>> _mockSignInManager;
    private readonly Mock<IConfiguration> _mockConfiguration;
    private readonly Mock<TenantHelper> _mockTenantHelper;
    private readonly TenantHelper _tenantHelper;
    private readonly AuthController _controller;

    public AuthControllerEmailTests()
    {
        _mockLogger = new Mock<ILogger<AuthController>>();
        _mockAuthService = new Mock<IAuthService>();

        // Create minimally required UserManager mock
        var userStore = Mock.Of<IUserStore<AuthUser>>();
        var options = new Mock<IOptions<IdentityOptions>>();
        var passwordHasher = new Mock<IPasswordHasher<AuthUser>>();
        var userValidators = new List<IUserValidator<AuthUser>> { new Mock<IUserValidator<AuthUser>>().Object };
        var passwordValidators = new List<IPasswordValidator<AuthUser>>
            { new Mock<IPasswordValidator<AuthUser>>().Object };
        var lookupNormalizer = new Mock<ILookupNormalizer>();
        var identityErrorDescriber = new Mock<IdentityErrorDescriber>();
        var serviceProvider = new Mock<IServiceProvider>();
        var logger = new Mock<ILogger<UserManager<AuthUser>>>();

        var mockUserManager = new Mock<UserManager<AuthUser>>(
            userStore, options.Object, passwordHasher.Object, userValidators, passwordValidators,
            lookupNormalizer.Object, identityErrorDescriber.Object, serviceProvider.Object, logger.Object);

        // Create minimally required SignInManager mock
        var contextAccessor = new Mock<IHttpContextAccessor>();
        var claimsFactory = new Mock<IUserClaimsPrincipalFactory<AuthUser>>();
        var optionsAccessor = new Mock<IOptions<IdentityOptions>>();
        var loggerSignIn = new Mock<ILogger<SignInManager<AuthUser>>>();
        var authSchemeProvider = new Mock<IAuthenticationSchemeProvider>();
        var userConfirmation = new Mock<IUserConfirmation<AuthUser>>();

        _mockSignInManager = new Mock<SignInManager<AuthUser>>(
            mockUserManager.Object,
            contextAccessor.Object,
            claimsFactory.Object,
            optionsAccessor.Object,
            loggerSignIn.Object,
            authSchemeProvider.Object,
            userConfirmation.Object);

        _mockConfiguration = new Mock<IConfiguration>();

        // Create shared HttpContext that both controller and TenantHelper will use
        var sharedHttpContext = new DefaultHttpContext();

        // Create HttpContextAccessor that returns the shared context
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(sharedHttpContext);
        var mockTenantHelperLogger = new Mock<ILogger<TenantHelper>>();

        // Create concrete TenantHelper instance with the shared context accessor
        _tenantHelper = new TenantHelper(mockHttpContextAccessor.Object, mockTenantHelperLogger.Object);

        _controller = new AuthController(
            _mockLogger.Object,
            _mockAuthService.Object,
            _mockSignInManager.Object,
            _mockConfiguration.Object,
            _tenantHelper);

        // Set the controller to use the same shared HttpContext
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = sharedHttpContext
        };
    }

    [Fact]
    public async Task ConfirmEmail_WithValidRequest_ReturnsOkResult()
    {
        // Arrange
        var request = new ConfirmEmailRequest
        {
            UserId = "user123",
            Token = "valid-token"
        };

        _mockAuthService.Setup(x => x.ConfirmEmailAsync(
                request.UserId,
                request.Token,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ConfirmEmail(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var responseObj = okResult.Value as object;

        var property = responseObj!.GetType().GetProperty("Message");
        Assert.NotNull(property);
        Assert.Equal("Email confirmed successfully! You can now log in.", property.GetValue(responseObj));
    }

    [Fact]
    public async Task ConfirmEmail_WithInvalidToken_ReturnsBadRequest()
    {
        // Arrange
        var request = new ConfirmEmailRequest
        {
            UserId = "user123",
            Token = "invalid-token"
        };

        _mockAuthService.Setup(x => x.ConfirmEmailAsync(
                request.UserId,
                request.Token,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.ConfirmEmail(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Invalid or expired email confirmation token.", badRequestResult.Value);
    }

    [Fact]
    public async Task ConfirmEmail_WhenServiceThrowsException_ReturnsBadRequest()
    {
        // Arrange
        var request = new ConfirmEmailRequest
        {
            UserId = "user123",
            Token = "valid-token"
        };

        _mockAuthService.Setup(x => x.ConfirmEmailAsync(
                request.UserId,
                request.Token,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("Service error"));

        // Act
        var result = await _controller.ConfirmEmail(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Failed to confirm email. Please try again or request a new confirmation email.",
            badRequestResult.Value);
    }

    [Fact]
    public async Task ResendConfirmationEmail_WithValidEmail_ReturnsOkResult()
    {
        // Arrange
        var request = new ResendConfirmationEmailRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendEmailConfirmationAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ResendConfirmationEmail(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var responseObj = okResult.Value as object;

        var property = responseObj!.GetType().GetProperty("Message");
        Assert.NotNull(property);
        Assert.Equal("If the email address is registered, a confirmation email has been sent.",
            property.GetValue(responseObj));

        // Verify the service was called with the tenant helper values
        _mockAuthService.Verify(x => x.SendEmailConfirmationAsync(
            request.Email,
            It.IsAny<string?>(),
            It.IsAny<Guid?>()), Times.Once);
    }

    [Fact]
    public async Task ResendConfirmationEmail_WhenServiceThrowsException_ReturnsBadRequest()
    {
        // Arrange
        var request = new ResendConfirmationEmailRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendEmailConfirmationAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("Service error"));

        // Act
        var result = await _controller.ResendConfirmationEmail(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("There was an unexpected error while sending a confirmation email.", badRequestResult.Value);
    }

    [Fact]
    public async Task ForgotPassword_WithValidEmail_ReturnsOkResult()
    {
        // Arrange
        var request = new ForgotPasswordRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendPasswordResetAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var responseObj = okResult.Value as object;

        var property = responseObj!.GetType().GetProperty("Message");
        Assert.NotNull(property);
        Assert.Equal("If the email address is registered, a password reset email has been sent.",
            property.GetValue(responseObj));

        // Verify the service was called with the tenant helper values
        _mockAuthService.Verify(x => x.SendPasswordResetAsync(
            request.Email,
            It.IsAny<string?>(),
            It.IsAny<Guid?>()), Times.Once);
    }

    [Fact]
    public async Task ForgotPassword_WhenServiceThrowsException_ReturnsOkResult()
    {
        // Arrange
        var request = new ForgotPasswordRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendPasswordResetAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("Service error"));

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var responseObj = okResult.Value as object;

        var property = responseObj!.GetType().GetProperty("Message");
        Assert.NotNull(property);
        Assert.Equal("If the email address is registered, a password reset email has been sent.",
            property.GetValue(responseObj));
    }

    [Fact]
    public async Task ResetPassword_WithValidRequest_ReturnsOkResult()
    {
        // Arrange
        var request = new ResetPasswordRequest
        {
            UserId = "user123",
            Token = "valid-token",
            NewPassword = "NewPassword123!"
        };

        _mockAuthService.Setup(x => x.ResetPasswordAsync(
                request.UserId,
                request.Token,
                request.NewPassword,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ResetPassword(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var responseObj = okResult.Value as object;

        var property = responseObj!.GetType().GetProperty("Message");
        Assert.NotNull(property);
        Assert.Equal("Password reset successfully! You can now log in with your new password.",
            property.GetValue(responseObj));
    }

    [Fact]
    public async Task ResetPassword_WithInvalidToken_ReturnsBadRequest()
    {
        // Arrange
        var request = new ResetPasswordRequest
        {
            UserId = "user123",
            Token = "invalid-token",
            NewPassword = "NewPassword123!"
        };

        _mockAuthService.Setup(x => x.ResetPasswordAsync(
                request.UserId,
                request.Token,
                request.NewPassword,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(false);

        // Act
        var result = await _controller.ResetPassword(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Invalid or expired password reset token.", badRequestResult.Value);
    }

    [Fact]
    public async Task ResetPassword_WhenServiceThrowsException_ReturnsBadRequest()
    {
        // Arrange
        var request = new ResetPasswordRequest
        {
            UserId = "user123",
            Token = "valid-token",
            NewPassword = "NewPassword123!"
        };

        _mockAuthService.Setup(x => x.ResetPasswordAsync(
                request.UserId,
                request.Token,
                request.NewPassword,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("Service error"));

        // Act
        var result = await _controller.ResetPassword(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal("Failed to reset password. Please try again or request a new password reset email.",
            badRequestResult.Value);
    }

    [Fact]
    public async Task Register_UpdatedMessage_IncludesEmailConfirmationNotice()
    {
        // Arrange
        var request = new RegisterUserRequest
        {
            Email = "test@example.com",
            Password = "Password123!"
        };

        _mockAuthService.Setup(x => x.Register(
                It.IsAny<AuthUser>(),
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.Register(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var responseObj = okResult.Value as object;

        var property = responseObj!.GetType().GetProperty("Message");
        Assert.NotNull(property);
        Assert.Equal("User registered successfully", property.GetValue(responseObj));
    }

    [Fact]
    public async Task Register_WithBrandingContext_CallsServiceWithBrandingInfo()
    {
        // Arrange
        var request = new RegisterUserRequest
        {
            Email = "test@example.com",
            Password = "Password123!"
        };

        var tenantId = Guid.NewGuid();

        // Setup HttpContext to have tenant information
        _controller.HttpContext.Items[CommonConstants.TenantHttpContext] =
            tenantId;

        _mockAuthService.Setup(x => x.Register(
                It.IsAny<AuthUser>(),
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _controller.Register(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);

        // Verify the service was called with expected parameters
        _mockAuthService.Verify(x => x.Register(
            It.Is<AuthUser>(u => u.Email == request.Email),
            request.Password,
            It.IsAny<string?>(),
            tenantId), Times.Once);
    }

    [Fact]
    public async Task ResendConfirmationEmail_WithBrandingHeaders_PassesContextToService()
    {
        // Arrange
        var request = new ResendConfirmationEmailRequest
        {
            Email = "test@example.com"
        };
        var tenantId = Guid.NewGuid();

        // Setup HttpContext to have tenant information
        _controller.HttpContext.Items[CommonConstants.TenantHttpContext] =
            tenantId;

        _mockAuthService.Setup(x => x.SendEmailConfirmationAsync(
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ResendConfirmationEmail(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);

        // Verify the service was called with the tenant context
        _mockAuthService.Verify(x => x.SendEmailConfirmationAsync(
            request.Email,
            It.IsAny<string?>(),
            tenantId), Times.Once);
    }

    [Fact]
    public async Task ForgotPassword_WithBrandingHeaders_PassesContextToService()
    {
        // Arrange
        var request = new ForgotPasswordRequest
        {
            Email = "test@example.com"
        };
        var tenantId = Guid.NewGuid();

        // Setup HttpContext to have tenant information
        _controller.HttpContext.Items[CommonConstants.TenantHttpContext] =
            tenantId;

        _mockAuthService.Setup(x => x.SendPasswordResetAsync(
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);

        // Verify the service was called with the tenant context
        _mockAuthService.Verify(x => x.SendPasswordResetAsync(
            request.Email,
            It.IsAny<string?>(),
            tenantId), Times.Once);
    }

    [Fact]
    public async Task ConfirmEmail_LogsUserIdOnError()
    {
        // Arrange
        var request = new ConfirmEmailRequest
        {
            UserId = "user123",
            Token = "valid-token"
        };

        _mockAuthService.Setup(x => x.ConfirmEmailAsync(
                request.UserId,
                request.Token,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _controller.ConfirmEmail(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);

        // Verify error was logged with user ID
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Error confirming email for user") &&
                                              v.ToString()!.Contains(request.UserId)),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task ResendConfirmationEmail_LogsEmailOnError()
    {
        // Arrange
        var request = new ResendConfirmationEmailRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendEmailConfirmationAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("SMTP error"));

        // Act
        var result = await _controller.ResendConfirmationEmail(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);

        // Verify error was logged with email
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Error resending confirmation email to") &&
                                              v.ToString()!.Contains(request.Email)),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task ForgotPassword_LogsEmailOnError()
    {
        // Arrange
        var request = new ForgotPasswordRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendPasswordResetAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("Email service error"));

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);

        // Verify error was logged with email (but still returns OK for security)
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Error sending password reset email to") &&
                                              v.ToString()!.Contains(request.Email)),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task ResetPassword_LogsUserIdOnError()
    {
        // Arrange
        var request = new ResetPasswordRequest
        {
            UserId = "user123",
            Token = "valid-token",
            NewPassword = "NewPassword123!"
        };

        _mockAuthService.Setup(x => x.ResetPasswordAsync(
                request.UserId,
                request.Token,
                request.NewPassword,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ThrowsAsync(new Exception("Password validation error"));

        // Act
        var result = await _controller.ResetPassword(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);

        // Verify error was logged with user ID
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Error resetting password for user") &&
                                              v.ToString()!.Contains(request.UserId)),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task Register_WhenServiceReturnsErrors_ReturnsBadRequest()
    {
        // Arrange
        var request = new RegisterUserRequest
        {
            Email = "test@example.com",
            Password = "weak"
        };

        var errors = new[]
        {
            new IdentityError { Code = "PasswordTooShort", Description = "Password is too short" }
        };

        _mockAuthService.Setup(x => x.Register(
                It.IsAny<AuthUser>(),
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(IdentityResult.Failed(errors));

        // Act
        var result = await _controller.Register(request);

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(errors, badRequestResult.Value);
    }

    [Fact]
    public async Task ResendConfirmationEmail_ServiceReturnsSuccess_VerifiesCorrectServiceCall()
    {
        // Arrange
        var request = new ResendConfirmationEmailRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendEmailConfirmationAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ResendConfirmationEmail(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);

        // Verify exact method signature was called
        _mockAuthService.Verify(x => x.SendEmailConfirmationAsync(
            It.Is<string>(email => email == request.Email),
            It.IsAny<string?>(),
            It.IsAny<Guid?>()), Times.Once);
    }

    [Fact]
    public async Task ForgotPassword_ServiceReturnsSuccess_VerifiesCorrectServiceCall()
    {
        // Arrange
        var request = new ForgotPasswordRequest
        {
            Email = "test@example.com"
        };

        _mockAuthService.Setup(x => x.SendPasswordResetAsync(
                request.Email,
                It.IsAny<string?>(),
                It.IsAny<Guid?>()))
            .ReturnsAsync(true);

        // Act
        var result = await _controller.ForgotPassword(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);

        // Verify exact method signature was called
        _mockAuthService.Verify(x => x.SendPasswordResetAsync(
            It.Is<string>(email => email == request.Email),
            It.IsAny<string?>(),
            It.IsAny<Guid?>()), Times.Once);
    }
}