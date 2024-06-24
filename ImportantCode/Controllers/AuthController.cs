using ImportantCode.Entity;
using ImportantCode.Entity.Dto;
using ImportantCode.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly IJwtAuthManager _tokenService;

    public AuthController(UserManager<User> userManager, IJwtAuthManager tokenService)
    {
        _userManager = userManager;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = new User { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            return Ok(new { UserId = user.Id });
        }

        return BadRequest(result.Errors);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByNameAsync(model.Username);
        if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
        {
            return Unauthorized("Invalid username or password.");
        }

        var userAgent = Request.Headers["User-Agent"].ToString();
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        var deviceName = GetDeviceName(userAgent);

        var tokenResult = await _tokenService.GenerateTokens(user, userAgent, ipAddress, deviceName);

        return Ok(new
        {
            Token = tokenResult.AccessToken,
            RefreshToken = tokenResult.RefreshToken.TokenString
        });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] TokenModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userAgent = Request.Headers["User-Agent"].ToString();
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        var deviceName = GetDeviceName(userAgent);

        try
        {
            var tokenResult = await _tokenService.Refresh(model.RefreshToken, model.Token, DateTime.Now, userAgent, ipAddress, deviceName);
            return Ok(new
            {
                Token = tokenResult.AccessToken,
                RefreshToken = tokenResult.RefreshToken.TokenString
            });
        }
        catch (SecurityTokenException ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
    }
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] TokenModel model)
    {
        await _tokenService.RevokeRefreshToken(model.RefreshToken);
        return Ok(new { message = "Logged out successfully" });
    }

    private string GetDeviceName(string userAgent)
    {
        var uaParser = UAParser.Parser.GetDefault();
        var clientInfo = uaParser.Parse(userAgent);

        return $"{clientInfo.Device.Family} {clientInfo.OS.Family} {clientInfo.OS.Major}";
    }

}
