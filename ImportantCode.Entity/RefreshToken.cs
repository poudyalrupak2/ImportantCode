using System.Text.Json.Serialization;

namespace ImportantCode.Entity
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public User User { get; set; }
        public string UserId { get; set; }
        [JsonPropertyName("username")] 
        public string UserName { get; set; } = string.Empty; // can be used for usage tracking
                                                                                            // can optionally include other metadata, such as user agent, ip address, device name, and so on

        [JsonPropertyName("tokenString")]
        public string TokenString { get; set; } = string.Empty;

        [JsonPropertyName("expireAt")] public DateTime ExpireAt { get; set; }

        // Additional metadata properties
        [JsonPropertyName("userAgent")] public string UserAgent { get; set; } = string.Empty;
        [JsonPropertyName("ipAddress")] public string IpAddress { get; set; } = string.Empty;
        [JsonPropertyName("deviceName")] public string DeviceName { get; set; } = string.Empty;
    }
}
