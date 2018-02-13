using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using IdentityServer.Models;
using IdentityServer.Services;
using IdentityServer4.Authentication.UI;

namespace Security.IdentityServer.Controllers.Api
{
    [Produces("application/json")]
    [Route("token")]
    public class AccountApiController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger _logger;
        private IConfiguration _configuration;

        public AccountApiController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ILogger<AccountController> logger,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _logger = logger;
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> GenerateToken([FromBody] LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
                    if (result.Succeeded)
                    {

                        var claims = new[]
                        {
                          new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                          new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        };

                        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["TokenAuthentication:SecretKey"]));
                        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                        var token = new JwtSecurityToken(_configuration["Tokens:Issuer"],
                          _configuration["Tokens:Issuer"],
                          claims,
                          expires: DateTime.Now.AddMinutes(30),
                          signingCredentials: creds);

                        return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
                    }
                }
            }
            return Ok(new { message = "Las credenciales son incorrectas." });
        }
    }
}