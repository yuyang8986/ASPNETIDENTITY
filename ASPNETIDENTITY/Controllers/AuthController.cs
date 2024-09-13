using ASPNETIDENTITY.Domain.Entities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<ApplicationUser> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await _userManager.FindByNameAsync(model.Username);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }
        return Unauthorized();
    }

    [HttpPost("Signup")]
    public async Task<IActionResult> Signup([FromBody] SignupModel model)
    {
        var user = new ApplicationUser
        {
            UserName = model.Username,
            Email = model.Email,
        };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }
        return BadRequest(result.Errors);
    }

    [HttpGet("GetData")]
    [Authorize]
    public IActionResult GetData()
    {
        return Ok("This is a protected data");
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var claims = new List<Claim>
         {
             new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
             new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
             new Claim(ClaimTypes.NameIdentifier, user.Id),
         };
        // 添加角色声明
        var roles = _userManager.GetRolesAsync(user).Result;
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // 可以根据角色赋予不同的scope
        claims.Add(new Claim("scope", roles.Contains("Admin") ? "admin" : "user"));
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    audience: _configuration["Jwt:Audience"],
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

}