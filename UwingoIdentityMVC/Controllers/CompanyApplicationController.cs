using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Threading.Tasks;
using System.Net.Http.Json;
using UwingoIdentityMVC.Models;
using System.Text.Json;
using System;
using Entity.ModelsDto;
using Newtonsoft.Json;

namespace UwingoIdentityMVC.Controllers
{
    public class CompanyApplicationController : Controller
    {

        public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 10)
        {
            if (!User.HasClaim(c => c.Type == "CompanyApplication" && c.Value == "GetAllCompanyApplications"))
                return StatusCode(403);
            var response = await GenerateClient.Client.GetAsync($"api/CompanyApplication/GetPaginatedCompanyApplications?pageNumber={pageNumber}&pageSize={pageSize}");
            if (response.IsSuccessStatusCode)
            {
                var companyApplications = await response.Content.ReadFromJsonAsync<List<CompanyApplicationDto>>();
                var companyApplicationTuples = new List<Tuple<CompanyApplicationDto, CompanyDto, ApplicationDto>>();

                foreach (var item in companyApplications)
                {
                    var company = await GetCompanyByIdAsync(item.CompanyId);
                    var application = await GetApplicationByIdAsync(item.ApplicationId);

                    var companyApplicationTuple = new Tuple<CompanyApplicationDto, CompanyDto, ApplicationDto>(item, company, application);
                    companyApplicationTuples.Add(companyApplicationTuple);
                }

                response = await GenerateClient.Client.GetAsync($"api/CompanyApplication/GetCompanyApplicationCount");

                if (response.IsSuccessStatusCode)
                {
                    var totalCompanyApplication = await response.Content.ReadAsStringAsync();
                    int totalRecords = JsonConvert.DeserializeObject<int>(totalCompanyApplication);

                    ViewBag.TotalRecords = totalRecords;
                    ViewBag.PageNumber = pageNumber;
                    if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                    else ViewBag.PageSize = pageSize;
                }

                return View(companyApplicationTuples);
            }

            return View(new List<Tuple<CompanyApplicationDto, CompanyDto, ApplicationDto>>());
        }

        public async Task<IActionResult> Create()
        {
            if (!User.HasClaim(c => c.Type == "CompanyApplication" && c.Value == "CreateCompanyApplication"))
                return StatusCode(403);

            var companies = await GetCompaniesAsync();
            var applications = await GetApplicationsAsync();
            var model = new Tuple<CompanyApplicationDto, List<CompanyDto>, List<ApplicationDto>>(new CompanyApplicationDto(), companies, applications);
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CompanyApplicationDto model)
        {
            if (!User.HasClaim(c => c.Type == "CompanyApplication" && c.Value == "CreateCompanyApplication"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var response = await GenerateClient.Client.PostAsJsonAsync("api/CompanyApplication/CreateCompanyApplication", model);
                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction(nameof(Index));
                }
                ModelState.AddModelError(string.Empty, "An error occurred while creating the company application.");
            }
            return View(model);
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "CompanyApplication" && c.Value == "EditCompanyApplication"))
                return StatusCode(403);

            var response = await GenerateClient.Client.GetAsync($"api/CompanyApplication/GetCompanyApplication/{id}");
            if (response.IsSuccessStatusCode)
            {
                var companyApplication = await response.Content.ReadFromJsonAsync<CompanyApplicationDto>();
                var model = new Tuple<CompanyApplicationDto, List<CompanyDto>, List<ApplicationDto>>(companyApplication, await GetCompaniesAsync(), await GetApplicationsAsync());
                return View(model);
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public async Task<IActionResult> Edit([FromBody] CompanyApplicationDto model)
        {
            if (!User.HasClaim(c => c.Type == "CompanyApplication" && c.Value == "EditCompanyApplication"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var response = await GenerateClient.Client.PutAsJsonAsync($"api/CompanyApplication/UpdateCompanyApplication", model);
                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction("Index");
                }
                ModelState.AddModelError(string.Empty, "An error occurred while updating the company application.");
            }
            return View(model);
        }

        public async Task<IActionResult> Delete(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "CompanyApplication" && c.Value == "DeleteCompanyApplication"))
                return StatusCode(403);

            var response = await GenerateClient.Client.DeleteAsync($"api/CompanyApplication/DeleteCompanyApplication/{id}");
            if (response.IsSuccessStatusCode)
            {
                return RedirectToAction(nameof(Index));
            }
            return RedirectToAction(nameof(Index));
        }

        private async Task<List<CompanyDto>> GetCompaniesAsync()
        {
            var response = await GenerateClient.Client.GetAsync("api/Company/GetAllCompanies");
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<List<CompanyDto>>();
            }
            return new List<CompanyDto>();
        }

        private async Task<List<ApplicationDto>> GetApplicationsAsync()
        {
            var response = await GenerateClient.Client.GetAsync("api/Application/GetAllApplications");
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<List<ApplicationDto>>();
            }
            return new List<ApplicationDto>();
        }

        private async Task<CompanyDto> GetCompanyByIdAsync(Guid companyId)
        {
            var response = await GenerateClient.Client.GetAsync($"api/Company/GetCompanyById/{companyId}");
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<CompanyDto>();
            }

            return null; // Or handle it as needed
        }

        private async Task<ApplicationDto> GetApplicationByIdAsync(Guid applicationId)
        {
            var response = await GenerateClient.Client.GetAsync($"api/Application/GetApplicationById/{applicationId}");
            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadFromJsonAsync<ApplicationDto>();
            }

            return null; // Or handle it as needed
        }
    }
}
