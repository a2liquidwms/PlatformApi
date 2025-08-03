using System.Text.Json;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using PlatformApi.Models.Messages;

namespace PlatformApi.Services;

public class SnsService : ISnsService
{
    private readonly IAmazonSimpleNotificationService _snsClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SnsService> _logger;

    public SnsService(IAmazonSimpleNotificationService snsClient, IConfiguration configuration, ILogger<SnsService> logger)
    {
        _snsClient = snsClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task PublishUserCreatedAsync(UserCreatedMessage message)
    {
        await PublishMessageAsync("user-created", message);
    }

    public async Task PublishUserModifiedAsync(UserModifiedMessage message)
    {
        await PublishMessageAsync("user-modified", message);
    }

    public async Task PublishTenantCreatedAsync(TenantCreatedMessage message)
    {
        await PublishMessageAsync("tenant-created", message);
    }

    private async Task PublishMessageAsync<T>(string messageType, T message)
    {
        try
        {
            var topicArn = _configuration["AWS_SNS_TOPIC_ARN"]!; // Safe to use ! since we validate at startup

            var messageJson = JsonSerializer.Serialize(message);
            
            var publishRequest = new PublishRequest
            {
                TopicArn = topicArn,
                Message = messageJson,
                Subject = messageType,
                MessageAttributes = new Dictionary<string, MessageAttributeValue>
                {
                    ["message-type"] = new MessageAttributeValue
                    {
                        DataType = "String",
                        StringValue = messageType
                    }
                }
            };

            var response = await _snsClient.PublishAsync(publishRequest);
            _logger.LogInformation("Published {MessageType} message with MessageId: {MessageId}", messageType, response.MessageId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish {MessageType} message", messageType);
            throw;
        }
    }
}