using Entity.ModelsDto;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace UwingoIdentityMVC.Controllers
{
    public class RoleController : Controller
    {
        private readonly ILogger<RoleController> _logger;
        public RoleController(ILogger<RoleController> logger)
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
            bool hasGetAllRoles = User.HasClaim(c => c.Type == "Role" && c.Value == "GetAllRoles");

            // Eğer companyId veya applicationId gönderilmemişse, gerekli bilgileri al
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
                    if (companyIdClaim != null)
                    {
                        var result = await GetApplicationsByCompany(Guid.Parse(companyIdClaim.Value));
                        if (result is OkObjectResult okResult && okResult.Value is IEnumerable<ApplicationDto> applications)
                        {
                            ViewBag.Applications = applications; // Uygulamaları doğrudan ViewBag'e ata
                        }

                        CompanyDto company = new CompanyDto { Id = Guid.Parse(companyIdClaim.Value), Name = "Şirketiniz" };
                        companyList.Add(company);
                        ViewBag.Companies = companyList;
                    }
                }
                else if (hasGetAllRoles)
                {
                    var companyIdClaim = User.Claims.FirstOrDefault(c => c.Type == "CompanyId");
                    if (companyIdClaim != null)
                    {
                        CompanyDto company = new CompanyDto { Id = Guid.Parse(companyIdClaim.Value), Name = "Şirketiniz" };
                        companyList.Add(company);
                        ViewBag.Companies = companyList;

                        var applicationIdClaim = User.Claims.FirstOrDefault(c => c.Type == "ApplicationId");
                        if (applicationIdClaim != null)
                        {
                            ApplicationDto application = new ApplicationDto { Id = Guid.Parse(applicationIdClaim.Value), Name = "Uygulamanız" };
                            applicationList.Add(application);
                            ViewBag.Applications = applicationList;
                        }
                    }
                }

                return View(); // Şirket ve uygulama seçim ekranı
            }

            // Eğer companyId ve applicationId seçilmişse, API çağrısını yaparak rolleri getiriyoruz
            IEnumerable<RoleDto> roleList = (IEnumerable<RoleDto>)await GetRolesByCompanyAndApplication(companyId, applicationId, pageNumber, pageSize);

            // ViewBag'e gerekli bilgileri gönderiyoruz
            ViewBag.PageNumber = pageNumber;
            ViewBag.PageSize = pageSize;
            ViewBag.TotalRecords = roleList?.Count() ?? 0;

            // Şirket ve uygulama bilgilerini yeniden view'a göndermek için
            ViewBag.CompanyId = companyId;
            ViewBag.ApplicationId = applicationId;

            return View(roleList); // Roller listesi ile view'i döndürüyoruz
        }

        public async Task<IActionResult> Create()
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "CreateRole"))
                return StatusCode(403);

            var (companies, applications) = await GetCompaniesAndApplicationsAsync();

            return View(Tuple.Create(companies, applications));
        }

        [HttpPost]
        public async Task<IActionResult> Create(RoleDto role)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "CreateRole"))
                return StatusCode(403);
            role.Id = Guid.NewGuid().ToString();
            var content = new StringContent(JsonConvert.SerializeObject(role), System.Text.Encoding.UTF8, "application/json");
            HttpResponseMessage response = await GenerateClient.Client.PostAsync("api/Role/CreateRole", content);

            var conten2t = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
                return RedirectToAction("Index");
            else
                ModelState.AddModelError(string.Empty, "An error occurred while creating the role.");

            var (companies, applications) = await GetCompaniesAndApplicationsAsync();

            return View(Tuple.Create(companies, applications));
        }

        public async Task<IActionResult> Edit(string id)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "EditRole"))
                return StatusCode(403);

            RoleDto role = null;
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Role/GetRoleById/{id}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                role = JsonConvert.DeserializeObject<RoleDto>(data);
            }
            else
            {
                ViewBag.ErrorMessage = "An error occurred while fetching data.";
                return RedirectToAction(nameof(Index));
            }

            return View(role);
        }

        [HttpPost]
        public async Task<IActionResult> Edit([FromBody] RoleDto role)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "EditRole"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(role), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await GenerateClient.Client.PutAsync($"api/Role/UpdateRole/{role.Id}", content);

                if (response.IsSuccessStatusCode) return RedirectToAction("Index");
                else ModelState.AddModelError(string.Empty, "An error occurred while updating the role.");
            }
            return View(role);
        }

        public async Task<IActionResult> Delete(string id)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "DeleteRole"))
                return StatusCode(403);

            HttpResponseMessage response = await GenerateClient.Client.DeleteAsync($"api/Role/DeleteRole/{id}");

            if (response.IsSuccessStatusCode)
                return RedirectToAction("Index");
            else
            {
                ViewBag.ErrorMessage = "An error occurred while deleting the role.";
                return RedirectToAction(nameof(Index));
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetRoleClaims(string roleId, Guid companyId, Guid applicationId)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "GetRoleClaims"))
                return StatusCode(403);
            // Tüm mevcut claim'leri çekiyor
            var apiAllClaims = $"api/Authentication/GetAllRoleClaims/{companyId}/{applicationId}";
            HttpResponseMessage allClaimsResponse = await GenerateClient.Client.GetAsync(apiAllClaims);

            List<ClaimDto> allClaims = new List<ClaimDto>();
            if (allClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await allClaimsResponse.Content.ReadAsStringAsync();
                allClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Rolün sahip olduğu claim'leri çekiyor
            var apiRoleClaims = $"api/Authentication/GetRoleClaimsByRoleId/{roleId}";
            HttpResponseMessage roleClaimsResponse = await GenerateClient.Client.GetAsync(apiRoleClaims);

            List<ClaimDto> roleClaims = new List<ClaimDto>();
            if (roleClaimsResponse.IsSuccessStatusCode)
            {
                var claims = await roleClaimsResponse.Content.ReadAsStringAsync();
                roleClaims = JsonConvert.DeserializeObject<List<ClaimDto>>(claims);
            }

            // Rolün claim'lerine sahip olup olmadığını kontrol etmek için
            var model = allClaims.Select(claim => new ClaimViewModel
            {
                Type = claim.Type,
                Value = claim.Value,
                IsSelected = roleClaims.Any(rc => rc.Type == claim.Type && rc.Value == claim.Value)
            }).ToList();

            return PartialView("_RoleClaims", model);
        }

        [HttpPost]
        public async Task<IActionResult> UpdateRoleClaims([FromBody] RoleClaimsDto dto)
        {
            if (!User.HasClaim(c => c.Type == "Role" && c.Value == "EditRoleClaims"))
                return StatusCode(403);

            if (string.IsNullOrEmpty(dto.RoleId) || dto.Claims == null)
                return BadRequest("Bilinmeyen rol ID ya da yetkisi.");

            var backendUrl = $"api/Authentication/UpdateRoleClaims?roleId={dto.RoleId}";

            var content = new StringContent(JsonConvert.SerializeObject(dto.Claims), Encoding.UTF8, "application/json");

            var response = await GenerateClient.Client.PutAsync(backendUrl, content); // Use PUT for updates

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

        [HttpPost]
        public async Task<IActionResult> GetRolesByCompanyAndApplication(Guid companyId, Guid applicationId, int pageNumber, int pageSize)
        {
            try
            {
                if (!User.HasClaim(c => c.Type == "Role" && c.Value == "GetAllRoles"))
                {
                    return StatusCode(403);
                }

                // API endpointine istek gönderiliyor
                var apiUrl = $"api/Authentication/GetRolesByCompanyApplication?companyId={companyId}&applicationId={applicationId}&pageNumber={pageNumber}&pageSize={pageSize}";
                HttpResponseMessage httpResponse = await GenerateClient.Client.GetAsync(apiUrl);

                if (httpResponse.IsSuccessStatusCode)
                {
                    var responseContent = await httpResponse.Content.ReadAsStringAsync();
                    List<RoleDto> roles = JsonConvert.DeserializeObject<List<RoleDto>>(responseContent);

                    ViewBag.TotalRecords = roles.Count;
                    ViewBag.PageNumber = pageNumber;
                    ViewBag.PageSize = pageSize;

                    ViewBag.CompanyId = companyId;
                    ViewBag.ApplicationId = applicationId;

                    return PartialView("_rolesTablePartial", roles);
                }
                else
                {
                    _logger.LogError("Kullanıcılar alınırken hata oluştu. Status Code: {0}", httpResponse.StatusCode);
                    return StatusCode((int)httpResponse.StatusCode, "Kullanıcıları getirirken bir hata oluştu.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("GetRolesByCompanyAndApplication metodunda hata: {Message}", ex.Message);
                return StatusCode(500, "Internal server error");
            }
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
        private async Task<(List<CompanyDto>, List<ApplicationDto>)> GetCompaniesAndApplicationsAsync()
        {
            List<ApplicationDto> applications = new List<ApplicationDto>();
            List<CompanyDto> companies = new List<CompanyDto>();
            List<CompanyApplicationDto> companyApplications = new List<CompanyApplicationDto>();

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
                    applications = JsonConvert.DeserializeObject<List<ApplicationDto>>(data);
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

            return (companies, applications); // Şirketler ve uygulamalar listesi döndürülüyor
        }

    }
}
