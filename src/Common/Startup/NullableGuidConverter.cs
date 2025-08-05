using System.Text.Json;
using System.Text.Json.Serialization;

namespace PlatformApi.Common.Startup;

public class NullableGuidConverter : JsonConverter<Guid?>
{
    public override Guid? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType == JsonTokenType.String)
        {
            var stringValue = reader.GetString();
            
            // Treat empty string as null
            if (string.IsNullOrWhiteSpace(stringValue))
            {
                return null;
            }

            // Try to parse as Guid
            if (Guid.TryParse(stringValue, out var guid))
            {
                return guid;
            }
            
            // Invalid Guid format
            throw new JsonException($"Unable to convert \"{stringValue}\" to Guid.");
        }

        throw new JsonException($"Unable to convert token type {reader.TokenType} to Guid.");
    }

    public override void Write(Utf8JsonWriter writer, Guid? value, JsonSerializerOptions options)
    {
        if (value.HasValue)
        {
            writer.WriteStringValue(value.Value.ToString());
        }
        else
        {
            writer.WriteNullValue();
        }
    }
}