using Entity.Models;
using Entity.ModelsDto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Newtonsoft.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;

namespace UwingoIdentityMVC.Controllers
{
    //[Authorize(Roles = "Admin,TenantAdmin")]
    public class UserController : Controller
    {
        private readonly ILogger<UserController> _logger;
        public UserController(ILogger<UserController> logger)
        {
            _logger = logger;
        }

        public async Task<IActionResult> Index(Guid companyId, Guid applicationId, int pageNumber = 1, int pageSize = 10)
        {
            List<CompanyDto> companyList = new List<CompanyDto>();
            List<ApplicationDto> applicationList = new List<ApplicationDto>();
            // Kullanıcının gerekli yetkilerini kontrol et
            bool hasGetAllCompanies = User.HasClaim(c => c.Type == "Company" && c.Value == "GetAllCompanies");
            bool hasGetAllApplications = User.HasClaim(c => c.Type == "Application" && c.Value == "GetAllApplications");
            bool hasGetAllUsers = User.HasClaim(c => c.Type == "User" && c.Value == "GetAllUsers");

            // Eğer companyId veya applicationId gönderilmemişse, tüm kullanıcıları listelemek yerine şirket ve uygulama seçimi yapılmasını isteyebiliriz.
            if (companyId == Guid.Empty || applicationId == Guid.Empty)
            {
                if (hasGetAllCompanies)
                {
                    ViewBag.Companies = await GetCompanies(); // Şirketleri view'a gönder
                    ViewBag.Applications = await GetApplications(); // Uygulamaları view'a gönder
                }
                else if (hasGetAllApplications || User.IsInRole("TenantAdmin"))
                {
                    var companyIdClaim = User.Claims.FirstOrDefault(c => c.Type == "CompanyId");
                    var result = await GetApplicationsByCompany(Guid.Parse(companyIdClaim.Value));
                    if (result is OkObjectResult okResult && okResult.Value is IEnumerable<ApplicationDto> applications)
                    {
                        ViewBag.Applications = applications; // Doğrudan ViewBag'e ata
                    }
                    CompanyDto company = new CompanyDto { Id = Guid.Parse(companyIdClaim.Value), Name = "Şirketiniz" };
                    companyList.Add(company);
                    ViewBag.Companies = companyList;
                }
                else if (hasGetAllUsers)
                {
                    var companyIdClaim = User.Claims.FirstOrDefault(c => c.Type == "CompanyId");
                    CompanyDto company = new CompanyDto { Id = Guid.Parse(companyIdClaim.Value), Name = "Şirketiniz" };
                    companyList.Add(company);
                    ViewBag.Companies = companyList;

                    var applicationIdClaim = User.Claims.FirstOrDefault(c => c.Type == "ApplicationId");
                    ApplicationDto application = new ApplicationDto { Id = Guid.Parse(applicationIdClaim.Value), Name = "Uygulamanız"};
                    applicationList.Add(application);
                    ViewBag.Applications = applicationList;
                }

                return View(); // Şirket ve uygulama seçim ekranı
            }

            // Eğer companyId ve applicationId seçilmişse, API çağrısını yaparak kullanıcıları getiriyoruz
            IEnumerable<UwingoUserDto> users = (IEnumerable<UwingoUserDto>)await GetUsersByCompanyAndApplication(companyId, applicationId, pageNumber, pageSize);

            // ViewBag'e gerekli bilgileri gönderiyoruz
            ViewBag.PageNumber = pageNumber;
            ViewBag.PageSize = pageSize;
            ViewBag.TotalRecords = users?.Count() ?? 0;

            // Şirket ve uygulama bilgilerini yeniden view'a göndermek için
            ViewBag.CompanyId = companyId;
            ViewBag.ApplicationId = applicationId;

            return View(users); // Kullanıcılar listesi ile view'i döndürüyoruz
        }


        private async Task<List<CompanyDto>> GetCompanies()
        {

            var apiUC = $"api/Company/GetAllCompanies";
            HttpResponseMessage httpResponse = await GenerateClient.Client.GetAsync(apiUC);

            if (httpResponse.IsSuccessStatusCode)
            {
                var companies = await httpResponse.Content.ReadAsStringAsync();
                List<CompanyDto> companyList = JsonConvert.DeserializeObject<List<CompanyDto>>(companies);

                return companyList;
            }
            return null;
        }

        private async Task<List<ApplicationDto>> GetApplications()
        {
            var apiUC = $"api/Application/GetAllApplications";
            HttpResponseMessage httpResponse = await GenerateClient.Client.GetAsync(apiUC);

            if (httpResponse.IsSuccessStatusCode)
            {
                var application = await httpResponse.Content.ReadAsStringAsync();
                List<ApplicationDto> applicationList = JsonConvert.DeserializeObject<List<ApplicationDto>>(application);

                return applicationList;
            }
            return null;
        }

        [HttpPost]
        public async Task<IActionResult> GetUsersByCompanyAndApplication(Guid companyId, Guid applicationId, int pageNumber = 1, int pageSize = 10)
        {
            try
            {
                if (!User.HasClaim(c => c.Type == "User" && c.Value == "GetAllUsers"))
                {
                    return StatusCode(403);
                }

                // API endpointine istek gönderiliyor
                var apiUrl = $"api/Authentication/GetUsersByCompanyApplication?companyId={companyId}&applicationId={applicationId}&pageNumber={pageNumber}&pageSize={pageSize}";
                HttpResponseMessage httpResponse = await GenerateClient.Client.GetAsync(apiUrl);

                if (httpResponse.IsSuccessStatusCode)
                {
                    var responseContent = await httpResponse.Content.ReadAsStringAsync();
                    List<UwingoUserDto> users = JsonConvert.DeserializeObject<List<UwingoUserDto>>(responseContent);

                    ViewBag.TotalRecords = users.Count;
                    ViewBag.PageNumber = pageNumber;
                    ViewBag.PageSize = pageSize;

                    ViewBag.CompanyId = companyId;
                    ViewBag.ApplicationId = applicationId;

                    return PartialView("_usersTablePartial", users);
                }
                else
                {
                    _logger.LogError("Kullanıcılar alınırken hata oluştu. Status Code: {0}", httpResponse.StatusCode);
                    return StatusCode((int)httpResponse.StatusCode, "Kullanıcıları getirirken bir hata oluştu.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("GetUsersByCompanyAndApplication metodunda hata: {Message}", ex.Message);
                return StatusCode(500, "Internal server error");
            }
        }



        public async Task<IActionResult> Create()
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "CreateUser"))
                return StatusCode(403);

            List<ApplicationDto> applications = new List<ApplicationDto>();
            List<CompanyDto> companies = new List<CompanyDto>();
            List<CompanyApplicationDto> companyApplications = new List<CompanyApplicationDto>();
            List<RoleDto> roles = new List<RoleDto>();

            var isAdmin = User.IsInRole("Admin");
            var isTenantAdmin = User.IsInRole("TenantAdmin");
            var isUser = User.IsInRole("User");

            // Kullanıcı adminse tüm şirketlerin uygulamalarını getirelim
            if (isAdmin)
            {
                // Tüm companyApplication verilerini çek
                var response = await GenerateClient.Client.GetAsync("api/CompanyApplication/GetAllCompanyApplications");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    companyApplications = JsonConvert.DeserializeObject<List<CompanyApplicationDto>>(data);
                }

                // Tüm application verilerini çek
                response = await GenerateClient.Client.GetAsync("api/Application/GetAllApplications");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(data);
                }

                // Tüm company verilerini çek
                response = await GenerateClient.Client.GetAsync("api/Company/GetAllCompanies");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    companies = JsonConvert.DeserializeObject<List<CompanyDto>>(data);

                    // Eşleşen Company ve Applicationları bul
                    foreach (var company in companies)
                    {
                        var matchingCompanyApps = companyApplications.Where(ca => ca.CompanyId == company.Id).ToList();
                        foreach (var ca in matchingCompanyApps)
                        {
                            // Eşleşen application'ı bul ve ekle
                            var matchingApplication = applications.FirstOrDefault(app => app.Id == ca.ApplicationId);
                            if (matchingApplication != null)
                            {
                                // Bu application'ı tekrar göndermek için ekleyebiliriz.
                                applications.Add(matchingApplication);
                            }
                        }
                    }
                }
            }
            // TenantAdmin ise sadece kendi tenantına ait uygulamaları getirelim
            else if (isTenantAdmin)
            {
                var userName = User.Identity.Name;
                var response = await GenerateClient.Client.GetAsync($"api/Application/GetApplicationByUserName/{userName}");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    var applicationList = JsonConvert.DeserializeObject<List<ApplicationDto>>(data);
                    foreach (var application in applicationList)
                    {
                        applications.Add(application);
                    }
                }
            }
            // User ise sadece bulunduğu applicationu getirelim
            else if (isUser)
            {
                var userName = User.Identity.Name;

                var response = await GenerateClient.Client.GetAsync($"api/Authentication/GetApplicationIdByUserName/{userName}");
                if (response.IsSuccessStatusCode)
                {
                    var data = await response.Content.ReadAsStringAsync();
                    string applicationId = JsonConvert.DeserializeObject<string>(data);

                    HttpResponseMessage response2 = await GenerateClient.Client.GetAsync($"api/Application/GetApplicationById/{applicationId}");

                    if (response2.IsSuccessStatusCode)
                    {
                        var application = await response2.Content.ReadAsStringAsync();
                        ApplicationDto applicationDto = JsonConvert.DeserializeObject<ApplicationDto>(application);
                        applications.Add(applicationDto);
                    }
                }
            }

            if (isAdmin)
            {
                roles.Add(new RoleDto { Id = "9970bb6b-2a25-4380-b695-c523b9c0476f", Name = "Admin" });
                roles.Add(new RoleDto { Id = "07434bdc-8ce9-450f-ac5c-e53308022a28", Name = "TenantAdmin" });
                roles.Add(new RoleDto { Id = "93997af7-441d-41ab-bee9-5ca5dc42100d", Name = "User" });
            }
            else if (isTenantAdmin)
            {
                roles.Add(new RoleDto { Id = "07434bdc-8ce9-450f-ac5c-e53308022a28", Name = "TenantAdmin" });
                roles.Add(new RoleDto { Id = "93997af7-441d-41ab-bee9-5ca5dc42100d", Name = "User" });
            }
            else if (isUser)
            {
                roles.Add(new RoleDto { Id = "93997af7-441d-41ab-bee9-5ca5dc42100d", Name = "User" });
            }


            return View(Tuple.Create(companies, applications, roles));
        }

        [HttpPost]
        public async Task<IActionResult> Create(UserRegistrationDto myUser, Guid companyId, Guid applicationId)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "CreateUser"))
                return StatusCode(403);

            List<ApplicationDto> applications = new List<ApplicationDto>();
            List<CompanyDto> companies = new List<CompanyDto>();
            List<RoleDto> roles = new List<RoleDto>();

            var userName = User.Identity.Name;
            var apiRegister = "api/Authentication/register";

            IEnumerable<UserDto> myUsers;

            if (User.IsInRole("Admin")) //İstek gönderen kişi adminse tüm CompanyApplicationları çekip, parametre olarak gelen company ve applicationID ile eşleşen CompanyApplicationId'yi alıp yeni kullanıcıya atıyor.
            {
                var companyApplications = $"api/CompanyApplication/GetAllCompanyApplications";
                HttpResponseMessage appResponse = await GenerateClient.Client.GetAsync(companyApplications);

                if (appResponse.IsSuccessStatusCode)
                {
                    var appData = await appResponse.Content.ReadAsStringAsync();
                    var allCompanyApplications = JsonConvert.DeserializeObject<List<CompanyApplicationDto>>(appData);

                    myUser.CompanyApplicationId = allCompanyApplications.Where(ca => ca.ApplicationId == applicationId && ca.CompanyId == companyId).FirstOrDefault().Id;
                }
            }
            else // Eğer admin değisle istek gönderen kişinin ait olduğu companyApplicationId çekiliyor.
            {
                var caIdApi = $"api/CompanyApplication/GetCompanyApplicationIdByUserName/{userName}";
                HttpResponseMessage caResponse = await GenerateClient.Client.GetAsync(caIdApi);
                var ca = await caResponse.Content.ReadAsStringAsync();

                var companyApplicationId = JsonConvert.DeserializeObject<Guid>(ca);

                if (User.IsInRole("User")) myUser.CompanyApplicationId = companyApplicationId; // Eğer usersa sadece kendi companyApplicationuna ekleme yapabildiği için yeni usera direkt atanıyor
                else // Eğer tenantAdminse o companye ait olan tüm companyApplicationlar çekiliyor, parametre olarak gönderilen ApplicationId ile eşleşen verinin CompanyApplicationId'si usera atanıyor.
                {
                    var caApi = $"api/CompanyApplication/GetCompanyApplicationsByUserName/{userName}";
                    caResponse = await GenerateClient.Client.GetAsync(caApi);
                    var data = await caResponse.Content.ReadAsStringAsync();

                    List<CompanyApplicationDto> companyApplications = JsonConvert.DeserializeObject<List<CompanyApplicationDto>>(data);
                    var caId = companyApplications.Where(ca => ca.ApplicationId == applicationId).FirstOrDefault().Id;
                    myUser.CompanyApplicationId = caId;
                }

            }

            HttpResponseMessage registerResponse = await GenerateClient.Client.PostAsJsonAsync(apiRegister, myUser);

            companies = await GetCompanies(); // Şirketleri view'a gönder
            applications = await GetApplications(); // Uygulamaları view'a gönder


            return View(Tuple.Create(companies, applications, roles)); // Şirket ve uygulama seçim ekranı
        }

        public async Task<IActionResult> Edit(string id, Guid companyId, Guid applicationId)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "EditUser"))
                return StatusCode(403);

            var apiGetUser = $"api/Authentication/GetUserById/{id}";
            HttpResponseMessage userResponse = await GenerateClient.Client.GetAsync(apiGetUser);

            if (userResponse.IsSuccessStatusCode)
            {
                var userData = await userResponse.Content.ReadAsStringAsync();
                var myUser = JsonConvert.DeserializeObject<UserDto>(userData);

                return View(myUser);
            }

            return RedirectToAction("Index");
        }


        [HttpPost]
        public async Task<IActionResult> Edit([FromBody] UserDto myUser, [FromQuery] Guid companyId, [FromQuery] Guid applicationId)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "EditUser"))
                return StatusCode(403);

            var apiUpdateUser = $"api/Authentication/UpdateUser";

            HttpResponseMessage updateResponse = await GenerateClient.Client.PutAsJsonAsync(apiUpdateUser, myUser);

            if (updateResponse.IsSuccessStatusCode)
                return RedirectToAction("Index");
            else
                ViewBag.Message = "Kullanıcı güncellemesi başarısız oldu.";

            return View(myUser);
        }


        [HttpPost]
        public async Task<IActionResult> Delete(string id)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "DeleteUser"))
                return StatusCode(403);

            var apiDeleteUser = $"api/Authentication/DeleteUser/{id}";
            HttpResponseMessage deleteResponse = await GenerateClient.Client.DeleteAsync(apiDeleteUser);

            if (deleteResponse.IsSuccessStatusCode)
            {
                return RedirectToAction("Index");
            }
            else
            {
                _logger.LogError($"User deletion failed for ID {id}. Status Code: {deleteResponse.StatusCode}");
                return StatusCode((int)deleteResponse.StatusCode, "Kullanıcı silinirken bir hata oluştu.");
            }
        }


        public async Task<IActionResult> GetAllUserClaims()
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "GetUserClaims"))
                return StatusCode(403);

            var apiUC = $"api/Authentication/GetAllClaims";
            HttpResponseMessage httpResponse = await GenerateClient.Client.GetAsync(apiUC);

            if (httpResponse.IsSuccessStatusCode)
            {
                var claims = await httpResponse.Content.ReadAsStringAsync();
                List<ClaimDto> allUserClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);

                return Json(allUserClaims);
            }
            return RedirectToAction("Index");
        }


        public async Task<IActionResult> GetUserClaims(string userId, Guid companyId, Guid applicationId)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "GetUserClaims"))
                return StatusCode(403);
            // Tüm mevcut claim'leri çekin
            var apiAllClaims = $"api/Authentication/GetAllUserClaims/{companyId}/{applicationId}";
            HttpResponseMessage allClaimsResponse = await GenerateClient.Client.GetAsync(apiAllClaims);

            List<ClaimDto> allClaims = new List<ClaimDto>();
            if (allClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await allClaimsResponse.Content.ReadAsStringAsync();
                allClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Kullanıcının sahip olduğu claim'leri çekin
            var apiUserClaims = $"api/Authentication/GetUserClaimsByUserId/{userId}";
            HttpResponseMessage userClaimsResponse = await GenerateClient.Client.GetAsync(apiUserClaims);

            List<ClaimDto> userClaims = new List<ClaimDto>();
            if (userClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await userClaimsResponse.Content.ReadAsStringAsync();
                userClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Kullanıcı claim'lerine sahip olup olmadığını kontrol etmek için
            var model = allClaims.Select(claim => new ClaimViewModel
            {
                Type = claim.Type,
                Value = claim.Value,
                IsSelected = userClaims.Any(uc => uc.Type == claim.Type && uc.Value == claim.Value)
            }).ToList();

            return PartialView("_UserClaims", model);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateUserClaims([FromBody] UserClaimsDto dto)
        {
            if (!User.HasClaim(c => c.Type == "User" && c.Value == "EditUserClaims"))
                return StatusCode(403);

            if (string.IsNullOrEmpty(dto.UserId) || dto.Claims == null)
                return BadRequest("Bilinmeyen kullanıcıID ya da yetkisi.");

            // Backend URL, assuming this is your backend's address
            var backendUrl = $"api/Authentication/UpdateUserClaims?userId={dto.UserId}";

            var client = GenerateClient.Client;

            var content = new StringContent(JsonConvert.SerializeObject(dto.Claims), Encoding.UTF8, "application/json");

            var response = await client.PutAsync(backendUrl, content); // Use PUT for updates

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsStringAsync();
                return Ok(result);
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                return StatusCode((int)response.StatusCode, error);
            }
        }

        private async Task<IEnumerable<UserDto>> GetUser(int pageNumber = 1, int pageSize = 10)
        {
            var userRole = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;

            IEnumerable<UserDto> myUsers = null;

            if (userRole == "Admin")
            {
                // Eğer kullanıcı Admin ise, tüm kullanıcıları getir
                var apiGetAllUsers = $"api/Authentication/GetPaginatedUsers?pageNumber={pageNumber}&pageSize={pageSize}";
                HttpResponseMessage allUsersResponse = await GenerateClient.Client.GetAsync(apiGetAllUsers);

                if (allUsersResponse.IsSuccessStatusCode)
                {
                    var users = await allUsersResponse.Content.ReadAsStringAsync();
                    myUsers = JsonConvert.DeserializeObject<IEnumerable<UserDto>>(users);

                    if (myUsers.Count() > 0)
                    {
                        int totalRecords = myUsers.Count();

                        ViewBag.TotalRecords = totalRecords;
                        ViewBag.PageNumber = pageNumber;
                        if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                        else ViewBag.PageSize = pageSize;
                    }
                }
            }
            else if (userRole == "TenantAdmin" || userRole == "User")
            {
                // Eğer kullanıcı TenantAdmin ise, kendi ApplicationId'sine bağlı olan kullanıcıları getir
                var apiGetApptId = $"api/Authentication/GetApplicationIdByUserName/{User.Identity.Name}";
                HttpResponseMessage tenantResponse = await GenerateClient.Client.GetAsync(apiGetApptId);

                if (tenantResponse.IsSuccessStatusCode)
                {
                    var applicationData = await tenantResponse.Content.ReadAsStringAsync();
                    var applicationId = JsonConvert.DeserializeObject<Guid>(applicationData);

                    var apiGetUsersByApplicationId = $"api/Authentication/GetPaginatedUsersByApplicationId/{applicationId}?pageNumber={pageNumber}&pageSize={pageSize}";
                    HttpResponseMessage usersResponse = await GenerateClient.Client.GetAsync(apiGetUsersByApplicationId);

                    if (usersResponse.IsSuccessStatusCode)
                    {
                        var users = await usersResponse.Content.ReadAsStringAsync();
                        myUsers = JsonConvert.DeserializeObject<IEnumerable<UserDto>>(users);

                        if (myUsers.Count() > 0)
                        {
                            int totalRecords = myUsers.Count();
                            ViewBag.TotalRecords = totalRecords;
                            ViewBag.PageNumber = pageNumber;
                            if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                            else ViewBag.PageSize = pageSize;
                        }
                    }
                }
            }
            return myUsers;
        }

        [HttpGet]
        public async Task<IActionResult> GetApplicationsByCompany(Guid companyId)
        {
            // Backend'deki API'ye istek gönder
            var response = await GenerateClient.Client.GetAsync($"api/CompanyApplication/GetApplicationsByCompanyId/{companyId}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                var applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(data);
                return Ok(applications);
            }
            else
            {
                return StatusCode((int)response.StatusCode, "Uygulamalar getirilirken bir hata oluştu.");
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetRolesByCompanyAndApplication(Guid companyId, Guid applicationId)
        {
            // Backend'deki endpoint'e istek gönder
            var response = await GenerateClient.Client.GetAsync($"api/Authentication/GetRolesByCompanyApplication?companyId={companyId}&applicationId={applicationId}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                var roles = JsonConvert.DeserializeObject<List<RoleDto>>(data);
                return Ok(roles);
            }
            return BadRequest("Roller alınırken bir hata oluştu.");
        }
    }
}