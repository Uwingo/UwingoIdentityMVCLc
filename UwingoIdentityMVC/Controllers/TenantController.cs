using Entity.ModelsDto;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace UwingoIdentityMVC.Controllers
{
    public class TenantController : Controller
    {
        public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 10)
        {
            if (!User.HasClaim(c => c.Type == "Tenant" && c.Value == "GetAllTenants"))
                return StatusCode(403);

            List<TenantDto> tenantList = new List<TenantDto>();
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Tenant/GetPaginatedTenants?pageNumber={pageNumber}&pageSize={pageSize}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                tenantList = JsonConvert.DeserializeObject<List<TenantDto>>(data);

                response = await GenerateClient.Client.GetAsync($"api/Tenant/GetTenantCount");

                if (response.IsSuccessStatusCode)
                {
                    var totalTenant = await response.Content.ReadAsStringAsync();
                    int totalRecords = JsonConvert.DeserializeObject<int>(totalTenant);

                    ViewBag.TotalRecords = totalRecords;
                    ViewBag.PageNumber = pageNumber;
                    if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                    else ViewBag.PageSize = pageSize;
                }
            }
            else ViewBag.ErrorMessage = "An error occurred while fetching data.";
            
            return View(tenantList);
        }

        public IActionResult Create()
        {
            if (!User.HasClaim(c => c.Type == "Tenant" && c.Value == "CreateTenant"))
                return StatusCode(403);

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Create(TenantDto tenant, CompanyDto company)
        {
            if (!User.HasClaim(c => c.Type == "Tenant" && c.Value == "CreateTenant"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(tenant), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await GenerateClient.Client.PostAsync("api/Tenant/CreateTenant", content);

                if (response.IsSuccessStatusCode)
                {
                    var myTenant = await response.Content.ReadAsStringAsync();
                    Guid tenantId = JsonConvert.DeserializeObject<Guid>(myTenant);
                    company.Name = tenant.Name;
                    company.TenantId = tenantId;

                    content = new StringContent(JsonConvert.SerializeObject(company), System.Text.Encoding.UTF8, "application/json");
                    response = await GenerateClient.Client.PostAsync("api/Company/CreateCompany", content);

                    return RedirectToAction(nameof(Index));
                }
                else
                    ModelState.AddModelError(string.Empty, "An error occurred while creating the tenant.");
                
            }

            return View(tenant);
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "Tenant" && c.Value == "EditTenant"))
                return StatusCode(403);

            TenantDto tenant = null;
            HttpResponseMessage response = await GenerateClient.Client.GetAsync($"api/Tenant/GetTenantById/{id}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                tenant = JsonConvert.DeserializeObject<TenantDto>(data);
            }
            else
            {
                ViewBag.ErrorMessage = "An error occurred while fetching data.";
                return RedirectToAction(nameof(Index));
            }

            return View(tenant);
        }

        [HttpPost]
        public async Task<IActionResult> Edit([FromBody]TenantDto tenant)
        {
            if (!User.HasClaim(c => c.Type == "Tenant" && c.Value == "EditTenant"))
                return StatusCode(403);

            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(tenant), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await GenerateClient.Client.PutAsync($"api/Tenant/UpdateTenant/{tenant.Id}", content);

                if (response.IsSuccessStatusCode) return RedirectToAction("Index");
                else ModelState.AddModelError(string.Empty, "An error occurred while updating the tenant.");
                
            }

            return View(tenant);
        }

        public async Task<IActionResult> Delete(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "Tenant" && c.Value == "DeleteTenant"))
                return StatusCode(403);

            HttpResponseMessage response = await GenerateClient.Client.DeleteAsync($"api/Company/DeleteCompanyByTenantId/{id}");

            if (response.IsSuccessStatusCode)
            {
                response = await GenerateClient.Client.DeleteAsync($"api/Tenant/DeleteTenant/{id}");

                if (response.IsSuccessStatusCode) return RedirectToAction("Index");
                else 
                {
                    ViewBag.ErrorMessage = "An error occurred while deleting the tenant.";
                    return RedirectToAction("Index");
                }
            }
            else
            {
                ViewBag.ErrorMessage = "An error occurred while deleting the company.";
                return RedirectToAction("Index");
            }
        }
    }
}
