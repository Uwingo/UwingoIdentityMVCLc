using Entity.ModelsDto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace UwingoIdentityMVC.Controllers
{
    public class CompanyController : Controller
    {
        public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 10)
        {
            if (!User.HasClaim(c => c.Type == "Company" && c.Value == "GetAllCompanies"))
                return StatusCode(403);

            List<CompanyDto> companyList = new List<CompanyDto>();
            List<TenantDto> tenantList = new List<TenantDto>();
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Company/GetPaginatedCompanies?pageNumber={pageNumber}&pageSize={pageSize}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                companyList = JsonConvert.DeserializeObject<List<CompanyDto>>(data);

                response = await GenerateClient.Client.GetAsync($"api/Company/GetCompanyCount");

                if (response.IsSuccessStatusCode)
                {
                    var totalCompanyApplication = await response.Content.ReadAsStringAsync();
                    int totalRecords = JsonConvert.DeserializeObject<int>(totalCompanyApplication);

                    ViewBag.TotalRecords = totalRecords;
                    ViewBag.PageNumber = pageNumber;
                    if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                    else ViewBag.PageSize = pageSize;
                }

                response = await GenerateClient.Client.GetAsync($"api/Tenant/GetAllTenants");
                if (response.IsSuccessStatusCode)
                {
                    data = await response.Content.ReadAsStringAsync();
                    tenantList = JsonConvert.DeserializeObject<List<TenantDto>>(data);
                }
                else ViewBag.ErrorMessage = "An error occurred while fetching data.";

            }
            return View(Tuple.Create(companyList, tenantList));
        }

        public async Task<ActionResult> Create()
        {
            if (!User.HasClaim(c => c.Type == "Company" && c.Value == "CreateCompany"))
                return StatusCode(403);

            List<TenantDto> tenantList = new List<TenantDto>();
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Tenant/GetAllTenants");
            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                tenantList = JsonConvert.DeserializeObject<List<TenantDto>>(data);
            }
            return View(tenantList);
        }

        [HttpPost]
        public async Task<IActionResult> Create(CompanyDto company)
        {
            if (!User.HasClaim(c => c.Type == "Company" && c.Value == "CreateCompany"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(company), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await GenerateClient.Client.PostAsync("api/Company/CreateCompany", content);

                if (response.IsSuccessStatusCode)
                    return RedirectToAction("Index");
                else
                    ModelState.AddModelError(string.Empty, "An error occurred while creating the company."); 
            }
            return View(company);
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "Company" && c.Value == "EditCompany"))
                return StatusCode(403);

            CompanyDto company = null;
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Company/GetCompanyById/{id}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                company = JsonConvert.DeserializeObject<CompanyDto>(data);
            }
            else
            {
                ViewBag.ErrorMessage = "An error occurred while fetching data.";
                return RedirectToAction(nameof(Index));
            }

            return View(company);
        }

        [HttpPost]
        public async Task<IActionResult> Edit([FromBody]CompanyDto company)
        {
            if (!User.HasClaim(c => c.Type == "Company" && c.Value == "EditCompany"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(company), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await GenerateClient.Client.PutAsync($"api/Company/UpdateCompany/{company.Id}", content);

                if (response.IsSuccessStatusCode) return RedirectToAction("Index");
                else ModelState.AddModelError(string.Empty, "An error occurred while updating the company.");
            }
            return View(company);
        }

        public async Task<IActionResult> Delete(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "Company" && c.Value == "DeleteCompany"))
                return StatusCode(403);

            HttpResponseMessage response = await GenerateClient.Client.DeleteAsync($"api/Company/DeleteCompany/{id}");

            if (response.IsSuccessStatusCode)
                return RedirectToAction("Index");
            else
            {
                ViewBag.ErrorMessage = "Company silinirken bir hata oluştu.";
                return RedirectToAction("Index");
            }
        }
    }
}
