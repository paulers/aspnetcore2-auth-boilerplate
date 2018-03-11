using AspNetCore2AuthBoilerplate.Models;
using AspNetCore2AuthBoilerplate.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AspNetCore2AuthBoilerplate.Controllers
{
    [Route("auth")]
    public class AuthenticationController : Controller
    {
        private IConfiguration _configuration;
        private ILogger<AuthenticationController> _logger;
        private IUsersService _usersService;

        public AuthenticationController(IConfiguration configuration, ILogger<AuthenticationController> logger, IUsersService usersService)
        {
            _configuration = configuration;
            _logger = logger;
            _usersService = usersService;
        }

        /// <summary>
        /// Logs user in and sets a cookie
        /// </summary>
        /// <param name="model">Model containing the username, password and rememberMe setting</param>
        /// <returns>Redirects to root or returnUrl if present</returns>
        [HttpPost("login"), ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginRequestModel model)
        {
            // early return if model is invalid
            if (!ModelState.IsValid)
            {
                _logger.LogError("Invalid model supplied when logging in.");
                return View(model);
            }

            // validate credentials
            var validCredentials = await _usersService.ValidateCredentials(model.Username, model.Password);

            // if valid
            if (validCredentials)
            {
                _logger.LogInformation($"Credentials verified for user {model.Username}.");
                // grab the user from the database
                // note: if credentials were verified, user will always exist
                var user = await _usersService.FindByEmail(model.Username);

                // if user selected 
                AuthenticationProperties props = null;
                if (model.RememberMe)
                {
                    var rememberMeHoursSetting = _configuration["RememberMeDurationInHours"];

                    if (string.IsNullOrEmpty(rememberMeHoursSetting))
                    {
                        rememberMeHoursSetting = "24";
                    }

                    var hours = double.Parse(rememberMeHoursSetting);

                    props = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.Add(TimeSpan.FromHours(hours))
                    };
                }

                _logger.LogInformation($"Loggin user {model.Username} in...");
                var identity = new ClaimsIdentity(CreateClaimList(user), "ApplicationUser");
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                // if return URL provided
                if (!string.IsNullOrEmpty(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }

                // otherwise return to root
                return Redirect("~/");
            } else
            {
                return Redirect("~/Unauthorized");
            }
        }

        /// <summary>
        /// Entry point for logging in with external providers
        /// </summary>
        /// <param name="provider">String representing extrenal providers. Ex: Google, Microsoft, Facebook, etc</param>
        /// <param name="returnUrl">String representing the redirect URL after user signs in.</param>
        /// <returns>Redirects to the meat and potatoes method of the login process.</returns>
        [HttpGet("login/external")]
        public IActionResult ExternalProviderLogin(string provider, string returnUrl)
        {
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action("ExternalProviderLoginCallback"),
                Items =
                {
                    { "returnUrl", returnUrl },
                    { "scheme", provider }
                }
            };

            return Challenge(props, provider);
        }

        /// <summary>
        /// Method called after successfully coming back from an External Provider
        /// </summary>
        /// <returns>Redirects to root or return url after successful login</returns>
        [HttpGet]
        public async Task<IActionResult> ExternalProviderLoginCallback()
        {
            // Authenticate with extrenal provider
            var result = await HttpContext.AuthenticateAsync();
            // If fail, throw an exception and bail
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error.");
            }

            // Retrieve User
            var externalUser = result.Principal;
            // Get the claims
            var externalUserClaims = externalUser.Claims.ToList();

            // Retrieve the userId from the external provider -- we will use it to look up the user in our database
            var userIdClaim = externalUserClaims.FirstOrDefault(x => x.Type == "sub");
            if (userIdClaim == null)
            {
                userIdClaim = externalUserClaims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            }
            // If we can't find an Id, throw, because there's something wrong with the profile coming back
            if (userIdClaim == null)
            {
                throw new Exception("Couldn't retrieve user Id from external provider.");
            }

            var userEmailAddress = externalUserClaims.FirstOrDefault(x => x.Type == ClaimTypes.Email);

            // Find a user in our database
            var user = await _usersService.FindByEmail(userEmailAddress.Value);
            if (user == null)
            {
                // TODO: Create a new user in the system

                // Or

                // Return with unauthorized since we aim to add users ourselves.
                await HttpContext.SignOutAsync();
                return Redirect("~/Unauthorized");
            }

            // Set up new claims array
            var claims = CreateClaimList(user);

            // Get the SessionId from the external provider, as we will be using it to sign out
            var sid = externalUserClaims.FirstOrDefault(x => x.Type == "sid");
            if (sid != null)
            {
                claims.Add(new Claim("sid", sid.Value));
            }

            // sign out the external user to clean up those cookies
            await HttpContext.SignOutAsync();

            // create our new identity
            var identity = new ClaimsIdentity(claims, "ApplicationUser");
            var principal = new ClaimsPrincipal(identity);
            // and sign them in
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            // log the sign in action
            _logger.LogInformation($"User {user.Name} with Id {user.Id} signed in.");

            // if we have a return url, use it
            var returnUrl = result.Properties.Items["returnUrl"];
            if (!string.IsNullOrEmpty(returnUrl))
            {
                return Redirect(returnUrl);
            }

            // otherwise return to root
            return Redirect("~/");
        }

        /// <summary>
        /// Entry point for logging out
        /// </summary>
        /// <returns>Redirects to root after successful session clear</returns>
        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            var user = HttpContext.User;
            if (user?.Identity.IsAuthenticated == true)
            {
                await HttpContext.SignOutAsync();
            }

            return Redirect("~/");
        }

        [HttpPost("token")]
        public async Task<IActionResult> RequestToken([FromBody]TokenRequestModel request)
        {
            var validRequest = await _usersService.ValidateClientIdAndSecretCombo(request.ClientId, request.Secret);
            if (validRequest)
            {
                var userId = await _usersService.GetUserIdentityByClientId(request.ClientId);
                if (userId == null)
                {
                    return BadRequest("Client Id is incorrect.");
                }

                var claims = new[]
                {
                    new Claim("uid", userId.ToString())
                };

                // create key and use it to hash the signed crednetials
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["ServerKey"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                // set token expiry
                var expires = DateTime.Now.AddMinutes(60);

                // create token object
                var token = new JwtSecurityToken(
                    issuer: _configuration["Authentication:Tokens:Issuer"],
                    audience: _configuration["Authentication:Tokens:Issuer"],
                    claims: claims,
                    expires: expires,
                    signingCredentials: creds);

                // we're golden
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expires
                });
            }

            // we're not golden
            return BadRequest("Could not verify identity.");
        }

        #region Private Methods
        private List<Claim> CreateClaimList(User user)
        {
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Name),
                    new Claim("uid", user.Id.ToString()),
                    new Claim("email", user.Email)
                };
            return claims;
        }
        #endregion

    }
}
