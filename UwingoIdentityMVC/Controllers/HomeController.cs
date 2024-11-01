using Entity.ModelsDto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using UwingoIdentityMVC.Models;

namespace UwingoIdentityMVC.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        //[Authorize]
        public async Task<IActionResult> Index()
        {
            if (User.Identity.IsAuthenticated && GenerateClient.Client.DefaultRequestHeaders.Authorization != null)
            {
                // Kullanıcının claim'lerini al
                var companyIdClaim = User.Claims.FirstOrDefault(c => c.Type == "CompanyId");
                var applicationIdClaim = User.Claims.FirstOrDefault(c => c.Type == "ApplicationId");

                string companyId = companyIdClaim?.Value; // CompanyId
                string applicationId = applicationIdClaim?.Value; // ApplicationId

                var model = new DashboardViewModel
                {
                    CompanyCount = await GetCountAsync("api/Company/GetCompanyCount"),
                    ApplicationCount = await GetCountAsync("api/Application/GetApplicationCount"),
                    CompanyApplicationCount = await GetCountAsync("api/CompanyApplication/GetCompanyApplicationCount"),
                    RoleCount = await GetCountAsync($"api/Role/GetRoleCount?companyId={companyId}&applicationId={applicationId}"),
                    TenantCount = await GetCountAsync("api/Tenant/GetTenantCount"),
                    UserCount = await GetCountAsync($"api/Authentication/GetUserCount?companyId={companyId}&applicationId={applicationId}") // CompanyId ve ApplicationId gönder
                };

                return View(model);
            }
            else
            {
                return RedirectToAction("Login", "Authentication");
            }
        }


        [HttpGet]
        public async Task<IActionResult> Settings()
        {
            try
            {
                var userName = User.Identity.Name;
                var response = await GenerateClient.Client.GetAsync($"api/Authentication/GetUserByUserName/{userName}");

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"User with username {userName} not found.");
                    return RedirectToAction("Login", "Authentication");
                }

                var user = await response.Content.ReadFromJsonAsync<UserDto>();
                return View(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred while fetching user settings: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpPost]
        public async Task<IActionResult> UpdateAccountSettings(string userName, string currentPassword, string newPassword, string confirmPassword)
        {
            if (newPassword != confirmPassword)
            {
                ModelState.AddModelError(string.Empty, "Passwords do not match.");
                return View("Settings");
            }
            if (currentPassword == newPassword)
            {
                ModelState.AddModelError(string.Empty, "Your new password must be different from your old password");
                return View("Settings");
            }

            try
            {
                var userResponse = await GenerateClient.Client.GetAsync($"api/Authentication/GetUserByUserName/{User.Identity.Name}"); //getuserbyusernameyap
                if (!userResponse.IsSuccessStatusCode)
                {
                    _logger.LogError($"User not found: {userName}");
                    return BadRequest("User not found.");
                }

                var user = await userResponse.Content.ReadFromJsonAsync<UserDto>();
                user.UserName = userName;

                var data = new
                {
                    userName = user.UserName,
                    currentPassword = currentPassword,
                    newPassword = newPassword
                };

                var content = new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json");
                var updateResponse = await GenerateClient.Client.PutAsync("api/Authentication/ChangePassword", content);

                if (updateResponse.IsSuccessStatusCode) return RedirectToAction("Index");
                else
                {
                    ModelState.AddModelError(string.Empty, "Failed to update account settings.");
                    return View("Settings", user);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred while updating account settings: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpGet]
        public async Task<IActionResult> Profile()
        {
            try
            {
                var userName = User.Identity.Name;
                var response = await GenerateClient.Client.GetAsync($"api/Authentication/GetUserByUserName/{userName}");

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning($"User with username {userName} not found.");
                    return RedirectToAction("Login", "Authentication");
                }

                var user = await response.Content.ReadFromJsonAsync<UserDto>();
                return View(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred while fetching the profile: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        [HttpPost]
        public async Task<IActionResult> UpdateProfile(UserDto updatedUser)
        {
            try
            {
                var content = new StringContent(JsonConvert.SerializeObject(updatedUser), Encoding.UTF8, "application/json");
                var response = await GenerateClient.Client.PutAsync("api/Authentication/UpdateUserProfile", content);
                
                if (response.IsSuccessStatusCode) 
                    return RedirectToAction("Profile");
                else
                {
                    ModelState.AddModelError(string.Empty, "Failed to update profile.");
                    return View("Profile", updatedUser);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred while updating the profile: {ex.Message}");
                return StatusCode(500, "Internal server error");
            }
        }

        public IActionResult Sales()
        {
            return View();
        }

        public IActionResult Widgets() => View();

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private async Task<int> GetCountAsync(string endpoint)
        {
            HttpResponseMessage response = await GenerateClient.Client.GetAsync(endpoint);

            switch ((int)response.StatusCode)
            {
                case 200:
                    var data = await response.Content.ReadAsStringAsync();
                    return JsonConvert.DeserializeObject<int>(data);
                case 404:
                    return 0;
                case 401:
                    bool isTokenRefreshed = await RefreshToken();
                    if (isTokenRefreshed)
                    {
                        response = await GenerateClient.Client.GetAsync(endpoint);
                        if (response.IsSuccessStatusCode)
                        {
                            data = await response.Content.ReadAsStringAsync();
                            return JsonConvert.DeserializeObject<int>(data);
                        }
                    }
                    return 0;
                default:
                    return 0;

            }
        }

        private async Task<bool> RefreshToken()
        {
            var tokenData = new
            {
                AccessToken = TokenStaticDto.AccessToken,
                RefreshToken = TokenStaticDto.RefreshToken
            };

            string url = "api/Authentication/refresh";

            var jsonContent = new StringContent(JsonConvert.SerializeObject(tokenData), Encoding.UTF8, "application/json");

            var response = await GenerateClient.Client.PostAsync(url, jsonContent);

            if(response.IsSuccessStatusCode) 
            {
                var tokenDtoJson = await response.Content.ReadAsStringAsync();
                var tokenDto = JsonConvert.DeserializeObject<TokenDto>(tokenDtoJson);

                TokenStaticDto.AccessToken = tokenDto.AccessToken;
                TokenStaticDto.RefreshToken = tokenDto.RefreshToken;

                if (GenerateClient.Client.DefaultRequestHeaders.Contains("Authorization"))
                {
                    GenerateClient.Client.DefaultRequestHeaders.Remove("Authorization");
                }
                GenerateClient.Client.DefaultRequestHeaders.Add("Authorization", "Bearer " + tokenDto.AccessToken);

                return true;
            }
            return false;
        }

        public async Task<IActionResult> RefreshTokenApi()
        {
            var tokenData = new
            {
                AccessToken = TokenStaticDto.AccessToken,
                RefreshToken = TokenStaticDto.RefreshToken
            };

            string url = "api/Authentication/refresh";

            var jsonContent = new StringContent(JsonConvert.SerializeObject(tokenData), Encoding.UTF8, "application/json");

            var response = await GenerateClient.Client.PostAsync(url, jsonContent);

            if (response.IsSuccessStatusCode)
            {
                var tokenDtoJson = await response.Content.ReadAsStringAsync();
                var tokenDto = JsonConvert.DeserializeObject<TokenDto>(tokenDtoJson);

                TokenStaticDto.AccessToken = tokenDto.AccessToken;
                TokenStaticDto.RefreshToken = tokenDto.RefreshToken;

                if (GenerateClient.Client.DefaultRequestHeaders.Contains("Authorization"))
                {
                    GenerateClient.Client.DefaultRequestHeaders.Remove("Authorization");
                }
                GenerateClient.Client.DefaultRequestHeaders.Add("Authorization", "Bearer " + tokenDto.AccessToken);

                return Json(true);
            }
            return Json(false);
        }
        public IActionResult SetLanguage(string culture, string returnUrl)
        {
            Response.Cookies.Append(
              CookieRequestCultureProvider.DefaultCookieName,
              CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
              new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1) }
              );
            return LocalRedirect(returnUrl);
        }
    }
}