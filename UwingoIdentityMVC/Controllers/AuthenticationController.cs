using Entity.Models;
using Entity.ModelsDto;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Net;
using Entity.ModelView;

namespace UwingoIdentityMVC.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(ILogger<AuthenticationController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> Login()
        {

            var companyResponse = await GenerateClient.Client.GetAsync("api/Company/GetAllCompaniesForLogin");
            var applicationResponse = await GenerateClient.Client.GetAsync("api/Application/GetAllApplicationsForLogin");

            if (companyResponse.IsSuccessStatusCode && applicationResponse.IsSuccessStatusCode)
            {
                var companyData = await companyResponse.Content.ReadAsStringAsync();
                var applicationData = await applicationResponse.Content.ReadAsStringAsync();

                var companies = JsonConvert.DeserializeObject<List<CompanyDto>>(companyData);
                var applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(applicationData);

                return View(new Tuple<List<CompanyDto>, List<ApplicationDto>>(companies, applications));
            }

            TempData["Error"] = "Şirket ve uygulama bilgileri yüklenemedi.";
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(UserLoginDto user)
        {
            List<CompanyDto> companies = new List<CompanyDto>();
            List<ApplicationDto> applications = new List<ApplicationDto>();

            if (user.ApplicationId == Guid.Empty || user.CompanyId == Guid.Empty)
            {
                var companyResponse = await GenerateClient.Client.GetAsync("api/Company/GetAllCompaniesForLogin");
                var applicationResponse = await GenerateClient.Client.GetAsync("api/Application/GetAllApplicationsForLogin");

                if (companyResponse.IsSuccessStatusCode && applicationResponse.IsSuccessStatusCode)
                {
                    var companyData = await companyResponse.Content.ReadAsStringAsync();
                    var applicationData = await applicationResponse.Content.ReadAsStringAsync();

                    companies = JsonConvert.DeserializeObject<List<CompanyDto>>(companyData);
                    applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(applicationData);
                }
                ModelState.AddModelError("", "Lütfen bir şirket ve uygulama seçiniz.");
                return View("Login", Tuple.Create(companies, applications));
            }

            var api = "api/Authentication/login";
            TokenDto token = new TokenDto();

            HttpResponseMessage responseMessage = await GenerateClient.Client.PostAsJsonAsync(api, user);

            if (responseMessage.IsSuccessStatusCode)
            {
                ViewBag.Message = "Başarılı";
                var data = await responseMessage.Content.ReadAsStringAsync();
                token = JsonConvert.DeserializeObject<TokenDto>(data);

                if (token != null)
                {
                    if (GenerateClient.Client.DefaultRequestHeaders.Contains("Authorization"))
                    {
                        GenerateClient.Client.DefaultRequestHeaders.Remove("Authorization");
                    }
                    GenerateClient.Client.DefaultRequestHeaders.Add("Authorization", "Bearer " + token.AccessToken);

                    TokenStaticDto.AccessToken = token.AccessToken;
                    TokenStaticDto.RefreshToken = token.RefreshToken;

                    string myUrl = $"api/Authentication/GetClaims/{user.UserName}";

                    HttpResponseMessage claimResponse = await GenerateClient.Client.GetAsync(myUrl);
                    var myClaimData = await claimResponse.Content.ReadFromJsonAsync<List<ClaimDto>>();

                    var claims = myClaimData.Select(c => new Claim(c.Type, c.Value)).ToList();
                    claims.Add(new Claim("CompanyId", user.CompanyId.ToString())); // CompanyId ekle
                    claims.Add(new Claim("ApplicationId", user.ApplicationId.ToString())); // ApplicationId ekle

                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true
                    };
                    var userIdentity = new ClaimsIdentity(claims, "Login");
                    await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                    await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(userIdentity),
                    authProperties);

                    return RedirectToAction("Index", "Home");
                }
            }
            else
            {
                var companyResponse = await GenerateClient.Client.GetAsync("api/Company/GetAllCompaniesForLogin");
                var applicationResponse = await GenerateClient.Client.GetAsync("api/Application/GetAllApplicationsForLogin");

                if (companyResponse.IsSuccessStatusCode && applicationResponse.IsSuccessStatusCode)
                {
                    var companyData = await companyResponse.Content.ReadAsStringAsync();
                    var applicationData = await applicationResponse.Content.ReadAsStringAsync();

                    companies = JsonConvert.DeserializeObject<List<CompanyDto>>(companyData);
                    applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(applicationData);
                }
                ModelState.AddModelError("", "Kullanıcı adı veya şifre yanlış.");
                return View("Login", Tuple.Create(companies, applications));
            }

            return RedirectToAction("Index", "Home");
        }

        public IActionResult NotFound() => View();

        public IActionResult InternalError() => View();

        public IActionResult LockScreen() => View();

        public IActionResult RecoverPassword() => View();

        public IActionResult Register()
        {
            List<RoleDto> roleList = GetAllRolesFunc();
            return View(roleList);
        }

        [HttpPost]
        public async Task<IActionResult> RegisterUser(UserRegistrationDto myUser, Guid roleId)
        {
            var apiRegister = "api/Authentication/register";

            // Kullanıcı adından ApplicationId'yi al

            // Kullanıcıyı kaydet
            HttpResponseMessage registerResponse = await GenerateClient.Client.PostAsJsonAsync(apiRegister, myUser);

            if (registerResponse.IsSuccessStatusCode)
            {
                return View("Index");
            }
            else ViewBag.Message = "Kullanıcı kaydı başarısız oldu.";



            return View("Index");
        }


        private List<RoleDto> GetAllRolesFunc()
        {
            var api = "api/Role/GetAllRoles";
            HttpResponseMessage responseMessage = GenerateClient.Client.GetAsync(api).Result;
            List<RoleDto> roleList = new List<RoleDto>();

            if (responseMessage.IsSuccessStatusCode)
            {
                var data = responseMessage.Content.ReadAsStringAsync().Result;
                roleList = JsonConvert.DeserializeObject<List<RoleDto>>(data);
            }

            return roleList;
        }

        public async Task<IActionResult> Logout()
        {
            // Clear the token from the HttpClient Authorization header
            if (GenerateClient.Client.DefaultRequestHeaders.Contains("Authorization"))
            {
                GenerateClient.Client.DefaultRequestHeaders.Remove("Authorization");
            }
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            // Redirect to the login page
            return RedirectToAction("Login", "Authentication");
        }

        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword([FromBody] EmailDto email)
        {
            var apiEndpoint = "api/Authentication/ForgotPassword";
            var response = await GenerateClient.Client.PostAsJsonAsync(apiEndpoint, email);

            if (response.IsSuccessStatusCode)
                return Ok("Şifre sıfırlama e-postası gönderildi.");

            return BadRequest("Şifre sıfırlama e-postası gönderilemedi.");
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            var model = new ResetPasswordVM
            {
                Token = token,
                Email = email
            };
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            var apiEndpoint = "api/Authentication/ResetPassword";
            var response = await GenerateClient.Client.PostAsJsonAsync(apiEndpoint, dto);

            if (response.IsSuccessStatusCode)
                return Ok("Şifreniz başarıyla sıfırlandı.");

            return BadRequest("Şifre sıfırlama işlemi başarısız oldu.");
        }

    }
}
