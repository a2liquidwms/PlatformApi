// using Amazon.SimpleEmail;
// using Amazon.SimpleEmail.Model;
// using Microsoft.Extensions.Configuration;
// using Microsoft.Extensions.Logging;
// using Moq;
// using PlatformApi.Models;
// using PlatformApi.Services;
// using Xunit;
//
// namespace PlatformApiTests.Services;
//
// public class EmailServiceTests
// {
//     private readonly Mock<IAmazonSimpleEmailService> _mockSesClient;
//     private readonly Mock<ILogger<EmailAwsSesService>> _mockLogger;
//     private readonly Mock<IBrandingService> _mockBrandingService;
//     private readonly Mock<IConfiguration> _mockConfiguration;
//     private readonly EmailAwsSesService _emailService;
//
//     public EmailServiceTests()
//     {
//         _mockSesClient = new Mock<IAmazonSimpleEmailService>();
//         _mockLogger = new Mock<ILogger<EmailAwsSesService>>();
//         _mockBrandingService = new Mock<IBrandingService>();
//         _mockConfiguration = new Mock<IConfiguration>();
//
//         // Setup configuration
//         _mockConfiguration.Setup(x => x["EMAIL_DOMAIN"]).Returns("example.com");
//         _mockConfiguration.Setup(x => x["EMAIL_CONFIGURATION_SET"]).Returns("TestConfigSet");
//
//         // Setup default branding
//         var defaultBranding = new BrandingContext
//         {
//             SiteName = "RedClay Auth",
//             LogoPath = "",
//             PrimaryColor = "#007bff",
//             SubDomain = "",
//             TenantId = null,
//             BaseUrl = "https://example.com",
//             EmailFromName = "RedClay Auth Team"
//         };
//         
//         _mockBrandingService.Setup(x => x.GetDefaultBrandingContextAsync())
//             .ReturnsAsync(defaultBranding);
//
//         _emailService = new EmailAwsSesService(
//             _mockSesClient.Object, 
//             _mockLogger.Object, 
//             _mockBrandingService.Object,
//             _mockConfiguration.Object);
//     }
//
//     private BrandingContext CreateTestBranding()
//     {
//         return new BrandingContext
//         {
//             SiteName = "Test Client",
//             LogoPath = "/logos/test.png",
//             PrimaryColor = "#ff6600",
//             SubDomain = "testclient",
//             TenantId = Guid.NewGuid(),
//             BaseUrl = "https://testclient.example.com",
//             EmailFromName = "Test Client Support"
//         };
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithValidParameters_ReturnsTrueAndSendsEmail()
//     {
//         // Arrange
//         // var email = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//         var textBody = "Test Text Body";
//         var branding = CreateTestBranding();
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendPasswordResetAsync(email, resetUrl, userName, branding);
//
//         // Assert
//         Assert.True(result);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 req.Destination.ToAddresses.Contains(email) &&
//                 req.Message.Subject.Data == $"Reset Your Password - {branding.SiteName}" &&
//                 req.Message.Body.Html!.Data.Contains(branding.SiteName) &&
//                 req.Message.Body.Html!.Data.Contains(resetUrl) &&
//                 req.Message.Body.Html!.Data.Contains(userName) &&
//                 req.Message.Body.Html!.Data.Contains(branding.PrimaryColor) &&
//                 req.Message.Body.Text!.Data.Contains(branding.SiteName)),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public async Task SendPasswordResetAsync_WithBranding_UsesCustomHeaderColor()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var resetUrl = "https://testclient.example.com/reset?token=def456";
//         var userName = "TestUser";
//         var branding = CreateTestBranding();
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendPasswordResetAsync(email, resetUrl, userName, branding);
//
//         // Assert
//         Assert.True(result);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 // Verify the header uses the custom color from branding
//                 req.Message.Body.Html!.Data.Contains($"background-color: {branding.PrimaryColor}") &&
//                 req.Message.Body.Html!.Data.Contains($"background-color: {branding.PrimaryColor}")),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public async Task SendWelcomeEmailAsync_WithBranding_UsesCustomSiteNameInSubject()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var userName = "TestUser";
//         var branding = CreateTestBranding();
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendWelcomeEmailAsync(email, userName, branding);
//
//         // Assert
//         Assert.True(result);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 req.Destination.ToAddresses.Contains(email) &&
//                 req.Message.Subject.Data == $"Welcome to {branding.SiteName}!" &&
//                 req.Message.Body.Html!.Data.Contains(userName) &&
//                 req.Message.Body.Html!.Data.Contains(branding.SiteName) &&
//                 req.Message.Body.Html!.Data.Contains(branding.PrimaryColor) &&
//                 req.Message.Body.Text!.Data.Contains(userName)),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public async Task SendWelcomeEmailAsync_WithBranding_UsesEmailFromName()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var userName = "TestUser";
//         var branding = CreateTestBranding();
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendWelcomeEmailAsync(email, userName, branding);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         
//         // The template should reference the EmailFromName in the footer
//         Assert.Contains(branding.EmailFromName, capturedRequest!.Message.Body.Html!.Data);
//         Assert.Contains(branding.EmailFromName, capturedRequest.Message.Body.Text!.Data);
//         
//         // Verify the source email format includes the EmailFromName
//         Assert.Equal($"{branding.EmailFromName} <no-reply@example.com>", capturedRequest.Source);
//     }
//
//     [Fact]
//     public async Task SendWelcomeEmailAsync_WithoutBranding_UsesDefaultSiteName()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var userName = "TestUser";
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendWelcomeEmailAsync(email, userName);
//
//         // Assert
//         Assert.True(result);
//         
//         // Verify default branding was used
//         _mockBrandingService.Verify(x => x.GetDefaultBrandingContextAsync(), Times.Once);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 req.Destination.ToAddresses.Contains(email) &&
//                 req.Message.Subject.Data == "Welcome to RedClay Auth!" &&
//                 req.Message.Body.Html!.Data.Contains(userName) &&
//                 req.Message.Body.Text!.Data.Contains(userName)),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public void Constructor_WithMissingEmailDomain_ThrowsInvalidOperationException()
//     {
//         // Arrange
//         var mockConfigWithoutDomain = new Mock<IConfiguration>();
//         mockConfigWithoutDomain.Setup(x => x["EMAIL_DOMAIN"]).Returns((string?)null);
//
//         // Act & Assert
//         Assert.Throws<InvalidOperationException>(() => 
//             new EmailAwsSesService(_mockSesClient.Object, _mockLogger.Object, _mockBrandingService.Object, mockConfigWithoutDomain.Object));
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithOnlyHtmlBody_SendsEmailWithoutTextPart()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody);
//
//         // Assert
//         Assert.True(result);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 req.Message.Body.Html!.Data == htmlBody &&
//                 req.Message.Body.Text == null),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithConfigurationSet_IncludesConfigurationSetInRequest()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//         var expectedConfigSet = "TestConfigSet";
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         Assert.Equal(expectedConfigSet, capturedRequest!.ConfigurationSetName);
//     }
//
//     [Fact]
//     public async Task SendEmailConfirmationAsync_LogsSuccessfulEmailSending()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var confirmationUrl = "https://app.com/confirm?token=abc123";
//         var userName = "TestUser";
//         var messageId = "test-message-id-123";
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = messageId });
//
//         // Act
//         var result = await _emailService.SendEmailConfirmationAsync(email, confirmationUrl, userName);
//
//         // Assert
//         Assert.True(result);
//         
//         // Verify success was logged
//         _mockLogger.Verify(
//             x => x.Log(
//                 LogLevel.Information,
//                 It.IsAny<EventId>(),
//                 It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Email sent successfully") && 
//                                               v.ToString()!.Contains(messageId) &&
//                                               v.ToString()!.Contains(email)),
//                 It.IsAny<Exception>(),
//                 It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
//             Times.Once);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithBranding_DoesNotIncludeBrandingInRequest()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//         var textBody = "Test Text Body";
//         var branding = CreateTestBranding();
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-message-id" });
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody, textBody, branding);
//
//         // Assert
//         Assert.True(result);
//         
//         // Verify branding context doesn't affect the basic email sending
//         // (branding should only be used in template generation, not in SES request)
//         Assert.NotNull(capturedRequest);
//         Assert.Equal(subject, capturedRequest!.Message.Subject.Data);
//         Assert.Equal(htmlBody, capturedRequest.Message.Body.Html!.Data);
//         Assert.Equal(textBody, capturedRequest.Message.Body.Text!.Data);
//     }
//
//     [Fact]
//     public async Task EmailTemplates_WithBranding_ContainAllBrandingElements()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var userName = "TestUser";
//         var branding = CreateTestBranding();
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendWelcomeEmailAsync(email, userName, branding);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         
//         var htmlBody = capturedRequest!.Message.Body.Html!.Data;
//         var textBody = capturedRequest.Message.Body.Text!.Data;
//         
//         // Verify all branding elements are included in templates
//         Assert.Contains(branding.SiteName, htmlBody);
//         Assert.Contains(branding.PrimaryColor, htmlBody);
//         Assert.Contains(branding.EmailFromName, htmlBody);
//         
//         Assert.Contains(branding.SiteName, textBody);
//         Assert.Contains(branding.EmailFromName, textBody);
//     }
//
//     [Fact]
//     public async Task EmailTemplates_WithNullBranding_UseDefaultValues()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var userName = "TestUser";
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendWelcomeEmailAsync(email, userName, null);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         
//         var htmlBody = capturedRequest!.Message.Body.Html!.Data;
//         var textBody = capturedRequest.Message.Body.Text!.Data;
//         
//         // Verify default values are used when branding is null
//         Assert.Contains("RedClay Auth", htmlBody);
//         Assert.Contains("RedClay Auth Team", htmlBody);
//         
//         Assert.Contains("RedClay Auth", textBody);
//         Assert.Contains("RedClay Auth Team", textBody);
//     }
//
//     [Fact]
//     public async Task SendEmailConfirmationAsync_WithCustomBrandingColor_UsesCustomButtonColor()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var confirmationUrl = "https://testclient.example.com/confirm?token=abc123";
//         var userName = "TestUser";
//         var branding = new BrandingContext
//         {
//             SiteName = "Custom Client",
//             PrimaryColor = "#00ff00", // Custom green color
//             BaseUrl = "https://custom.example.com",
//             EmailFromName = "Custom Support"
//         };
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendEmailConfirmationAsync(email, confirmationUrl, userName, branding);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         
//         var htmlBody = capturedRequest!.Message.Body.Html!.Data;
//         
//         // Verify the custom color is used in button and header styling
//         Assert.Contains("background-color: #00ff00", htmlBody);
//         Assert.Contains(branding.SiteName, htmlBody);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithEmptyEmailFromName_UsesDefaultSource()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//         var branding = CreateTestBranding();
//         branding.EmailFromName = ""; // Empty EmailFromName
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-message-id" });
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody, null, branding);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         
//         // When EmailFromName is empty, should use just the email address
//         Assert.Equal("no-reply@example.com", capturedRequest!.Source);
//     }
//
//     [Fact]
//     public async Task SendPasswordResetAsync_WithNullBranding_UsesDefaultBranding()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var resetUrl = "https://app.com/reset?token=def456";
//         var userName = "TestUser";
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendPasswordResetAsync(email, resetUrl, userName, null);
//
//         // Assert
//         Assert.True(result);
//         
//         // Verify default branding was used
//         _mockBrandingService.Verify(x => x.GetDefaultBrandingContextAsync(), Times.Once);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 req.Message.Subject.Data == "Reset Your Password - RedClay Auth" &&
//                 req.Message.Body.Html!.Data.Contains("RedClay Auth")),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_LogsEmailDetails()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//         var branding = CreateTestBranding();
//         var messageId = "test-message-id-456";
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = messageId });
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody, null, branding);
//
//         // Assert
//         Assert.True(result);
//         
//         // Verify success was logged with all details
//         _mockLogger.Verify(
//             x => x.Log(
//                 LogLevel.Information,
//                 It.IsAny<EventId>(),
//                 It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Email sent successfully") && 
//                                               v.ToString()!.Contains(messageId) &&
//                                               v.ToString()!.Contains(toEmail) &&
//                                               v.ToString()!.Contains(branding.SiteName)),
//                 It.IsAny<Exception>(),
//                 It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
//             Times.Once);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithNullConfigurationSet_DoesNotSetConfigurationSet()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//
//         // Setup configuration without EMAIL_CONFIGURATION_SET
//         _mockConfiguration.Setup(x => x["EMAIL_CONFIGURATION_SET"]).Returns((string?)null);
//         
//         var emailServiceWithoutConfigSet = new EmailAwsSesService(
//             _mockSesClient.Object, 
//             _mockLogger.Object, 
//             _mockBrandingService.Object,
//             _mockConfiguration.Object);
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await emailServiceWithoutConfigSet.SendEmailAsync(toEmail, subject, htmlBody);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         Assert.Null(capturedRequest!.ConfigurationSetName);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithEmptyConfigurationSet_DoesNotSetConfigurationSet()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//
//         // Setup configuration with empty EMAIL_CONFIGURATION_SET
//         _mockConfiguration.Setup(x => x["EMAIL_CONFIGURATION_SET"]).Returns("");
//         
//         var emailServiceWithEmptyConfigSet = new EmailAwsSesService(
//             _mockSesClient.Object, 
//             _mockLogger.Object, 
//             _mockBrandingService.Object,
//             _mockConfiguration.Object);
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await emailServiceWithEmptyConfigSet.SendEmailAsync(toEmail, subject, htmlBody);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         Assert.Null(capturedRequest!.ConfigurationSetName);
//     }
// }dEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-message-id" });
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody, textBody, branding);
//
//         // Assert
//         Assert.True(result);
//         
//         Assert.NotNull(capturedRequest);
//         Assert.Contains(toEmail, capturedRequest!.Destination.ToAddresses);
//         Assert.Equal(subject, capturedRequest.Message.Subject.Data);
//         Assert.Equal(htmlBody, capturedRequest.Message.Body.Html!.Data);
//         Assert.Equal(textBody, capturedRequest.Message.Body.Text!.Data);
//         Assert.Equal($"{branding.EmailFromName} <no-reply@example.com>", capturedRequest.Source);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WithNullBranding_UsesDefaultBranding()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//
//         SendEmailRequest? capturedRequest = null;
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .Callback<SendEmailRequest, CancellationToken>((req, token) => 
//             {
//                 capturedRequest = req;
//             })
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-message-id" });
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody, null, null);
//
//         // Assert
//         Assert.True(result);
//         Assert.NotNull(capturedRequest);
//         
//         // Verify default branding service was called
//         _mockBrandingService.Verify(x => x.GetDefaultBrandingContextAsync(), Times.Once);
//         
//         // Verify the source uses default branding
//         Assert.Equal("RedClay Auth Team <no-reply@example.com>", capturedRequest!.Source);
//     }
//
//     [Fact]
//     public async Task SendEmailAsync_WhenSesThrowsException_ReturnsFalseAndLogsError()
//     {
//         // Arrange
//         var toEmail = "recipient@example.com";
//         var subject = "Test Subject";
//         var htmlBody = "<h1>Test HTML Body</h1>";
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ThrowsAsync(new Exception("SES Error"));
//
//         // Act
//         var result = await _emailService.SendEmailAsync(toEmail, subject, htmlBody);
//
//         // Assert
//         Assert.False(result);
//         
//         // Verify error was logged
//         _mockLogger.Verify(
//             x => x.Log(
//                 LogLevel.Error,
//                 It.IsAny<EventId>(),
//                 It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed to send email")),
//                 It.IsAny<Exception>(),
//                 It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
//             Times.Once);
//     }
//
//     [Fact]
//     public async Task SendEmailConfirmationAsync_WithBranding_UsesCustomSiteName()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var confirmationUrl = "https://testclient.example.com/confirm?token=abc123";
//         var userName = "TestUser";
//         var branding = CreateTestBranding();
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendEmailConfirmationAsync(email, confirmationUrl, userName, branding);
//
//         // Assert
//         Assert.True(result);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 req.Destination.ToAddresses.Contains(email) &&
//                 req.Message.Subject.Data == $"Confirm Your Email Address - {branding.SiteName}" &&
//                 req.Message.Body.Html!.Data.Contains(branding.SiteName) &&
//                 req.Message.Body.Html!.Data.Contains(confirmationUrl) &&
//                 req.Message.Body.Html!.Data.Contains(userName) &&
//                 req.Message.Body.Html!.Data.Contains(branding.PrimaryColor) &&
//                 req.Message.Body.Text!.Data.Contains(branding.SiteName) &&
//                 req.Message.Body.Text!.Data.Contains(confirmationUrl)),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public async Task SendEmailConfirmationAsync_WithoutBranding_UsesDefaultSiteName()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var confirmationUrl = "https://app.com/confirm?token=abc123";
//         var userName = "TestUser";
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<SendEmailRequest>(), default))
//             .ReturnsAsync(new SendEmailResponse { MessageId = "test-id" });
//
//         // Act
//         var result = await _emailService.SendEmailConfirmationAsync(email, confirmationUrl, userName);
//
//         // Assert
//         Assert.True(result);
//         
//         // Verify default branding was used
//         _mockBrandingService.Verify(x => x.GetDefaultBrandingContextAsync(), Times.Once);
//         
//         _mockSesClient.Verify(x => x.SendEmailAsync(
//             It.Is<SendEmailRequest>(req => 
//                 req.Destination.ToAddresses.Contains(email) &&
//                 req.Message.Subject.Data == "Confirm Your Email Address - RedClay Auth" &&
//                 req.Message.Body.Html!.Data.Contains("RedClay Auth") && // Default site name
//                 req.Message.Body.Html!.Data.Contains(confirmationUrl) &&
//                 req.Message.Body.Html!.Data.Contains(userName)),
//             default), Times.Once);
//     }
//
//     [Fact]
//     public async Task SendPasswordResetAsync_WithBranding_UsesCustomSiteNameAndColors()
//     {
//         // Arrange
//         var email = "user@example.com";
//         var resetUrl = "https://testclient.example.com/reset?token=def456";
//         var userName = "TestUser";
//         var branding = CreateTestBranding();
//
//         _mockSesClient.Setup(x => x.SendEmailAsync(It.IsAny<Sen