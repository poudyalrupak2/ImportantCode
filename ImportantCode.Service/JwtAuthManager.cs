using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using ImportantCode.Data;
using ImportantCode.Entity;
using ImportantCode.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace ImportantCode.Service;

public interface IJwtAuthManager
{
    Task<JwtAuthResult> GenerateTokens(User user, string userAgent, string ipAddress, string deviceName);
    Task<JwtAuthResult> Refresh(string refreshToken, string accessToken, DateTime now, string userAgent, string ipAddress, string deviceName);
    Task RemoveExpiredRefreshTokens(DateTime now);
    Task RemoveRefreshTokenByUserName(string userName);
    (ClaimsPrincipal, JwtSecurityToken?) DecodeJwtToken(string token);
    Task<bool> RevokeRefreshToken(string refreshToken);
}

public class JwtAuthManager : IJwtAuthManager
{
    private readonly byte[] _secret;
    private readonly JwtTokenConfig _jwtTokenConfig;
    private readonly UserManager<User> _userManager;
    private readonly ImportantCodeDbContext _dbContext;

    public JwtAuthManager(UserManager<User> userManager, JwtTokenConfig jwtTokenConfig, ImportantCodeDbContext dbContext)
    {
        _jwtTokenConfig = jwtTokenConfig;
        _secret = Encoding.ASCII.GetBytes(_jwtTokenConfig.Secret);
        _userManager = userManager;
        _dbContext = dbContext;
    }

    public async Task<JwtAuthResult> GenerateTokens(User user, string userAgent, string ipAddress, string deviceName)
    {
        var userRoles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        if (!claims.Any(x => x.Type == JwtRegisteredClaimNames.Aud))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Aud, _jwtTokenConfig.Audience));
        }

        var accessToken = GenerateAccessToken(claims);
        var refreshToken = await GenerateRefreshTokenAsync(user, userAgent, ipAddress, deviceName);

        return new JwtAuthResult
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    public async Task<JwtAuthResult> Refresh(string refreshToken, string accessToken, DateTime now, string userAgent, string ipAddress, string deviceName)
    {
        var (principal, jwtToken) = DecodeJwtToken(accessToken);
        if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        var userName = principal.Identity?.Name;
        var user = await _userManager.FindByNameAsync(userName);

        var storedRefreshToken = await _dbContext.RefreshToken
            .FirstOrDefaultAsync(x => x.TokenString == refreshToken && x.UserId == user.Id && x.ExpireAt > now);

        if (storedRefreshToken == null)
        {
            throw new SecurityTokenException("Invalid refresh token");
        }

        // Remove the old refresh token
        _dbContext.RefreshToken.Remove(storedRefreshToken);
        await _dbContext.SaveChangesAsync();

        // Generate new tokens
        return await GenerateTokens(user, userAgent, ipAddress, deviceName);
    }

    public async Task RemoveExpiredRefreshTokens(DateTime now)
    {
        var expiredTokens = await _dbContext.RefreshToken.Where(x => x.ExpireAt < now).ToListAsync();
        if (expiredTokens.Any())
        {
            _dbContext.RefreshToken.RemoveRange(expiredTokens);
            await _dbContext.SaveChangesAsync();
        }
    }

    public async Task RemoveRefreshTokenByUserName(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user != null)
        {
            var refreshTokens = await _dbContext.RefreshToken.Where(x => x.UserId == user.Id).ToListAsync();
            if (refreshTokens.Any())
            {
                _dbContext.RefreshToken.RemoveRange(refreshTokens);
                await _dbContext.SaveChangesAsync();
            }
        }
    }

    public (ClaimsPrincipal, JwtSecurityToken?) DecodeJwtToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new SecurityTokenException("Invalid token");
        }

        var principal = new JwtSecurityTokenHandler().ValidateToken(token,
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _jwtTokenConfig.Issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(_secret),
                ValidAudience = _jwtTokenConfig.Audience,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1)
            }, out var validatedToken);

        return (principal, validatedToken as JwtSecurityToken);
    }

    private string GenerateAccessToken(IEnumerable<Claim> claims)
    {
        var jwtToken = new JwtSecurityToken(
            _jwtTokenConfig.Issuer,
            _jwtTokenConfig.Audience,
            claims,
            expires: DateTime.Now.AddMinutes(_jwtTokenConfig.AccessTokenExpiration),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(_secret), SecurityAlgorithms.HmacSha256));

        return new JwtSecurityTokenHandler().WriteToken(jwtToken);
    }

    private async Task<RefreshToken> GenerateRefreshTokenAsync(User user, string userAgent, string ipAddress, string deviceName)
    {
        var refreshToken = new RefreshToken
        {
            UserName = user.UserName,
            UserId = user.Id,
            TokenString = GenerateRefreshTokenString(),
            ExpireAt = DateTime.Now.AddMinutes(_jwtTokenConfig.RefreshTokenExpiration),
            UserAgent = userAgent,
            IpAddress = ipAddress,
            DeviceName = deviceName
        };

        _dbContext.RefreshToken.Add(refreshToken);
        await _dbContext.SaveChangesAsync();

        return refreshToken;
    }

    private static string GenerateRefreshTokenString()
    {
        var randomNumber = new byte[32];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    public async Task<bool> RevokeRefreshToken(string refreshToken)
    {
        var storedRefreshToken = await _dbContext.RefreshToken.FirstOrDefaultAsync(x => x.TokenString == refreshToken);

        if (storedRefreshToken != null)
        {
            _dbContext.RefreshToken.Remove(storedRefreshToken);
            await _dbContext.SaveChangesAsync();
            return true;
        }

        return false;
    }
}
