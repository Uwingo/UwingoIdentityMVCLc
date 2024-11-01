using Entity.ModelsDto;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http.Headers;

namespace UwingoIdentityMVC.Controllers
{
    public class ApplicationController : Controller
    {
        public async Task<IActionResult> Index(int pageNumber = 1, int pageSize = 10)
        {
            if (!User.HasClaim(c => c.Type == "Application" && c.Value == "GetAllApplications")) 
                return StatusCode(403);
            
            List<ApplicationDto> applicationList = new List<ApplicationDto>();
            HttpResponseMessage response = await SendAuthorizedRequestAsync(HttpMethod.Get, $"api/Application/GetPaginatedApplications?pageNumber={pageNumber}&pageSize={pageSize}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                applicationList = JsonConvert.DeserializeObject<List<ApplicationDto>>(data);

                response = await SendAuthorizedRequestAsync(HttpMethod.Get, $"api/Application/GetApplicationCount");

                if (response.IsSuccessStatusCode)
                {
                    var totalCompanyApplication = await response.Content.ReadAsStringAsync();
                    int totalRecords = JsonConvert.DeserializeObject<int>(totalCompanyApplication);

                    ViewBag.TotalRecords = totalRecords;
                    ViewBag.PageNumber = pageNumber;
                    if (totalRecords < pageSize) ViewBag.PageSize = totalRecords;
                    else ViewBag.PageSize = pageSize;
                }
            }
            else ViewBag.ErrorMessage = "An error occurred while fetching data.";

            return View(applicationList);
        }

        public IActionResult Create()
        {
            if (!User.HasClaim(c => c.Type == "Application" && c.Value == "CreateApplication")) 
                return StatusCode(403);
            else 
                return View();
        }

        [HttpPost]
        public async Task<IActionResult> Create(ApplicationDto application)
        {
            if (!User.HasClaim(c => c.Type == "Application" && c.Value == "CreateApplication"))
                return StatusCode(403);
            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(application), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await SendAuthorizedRequestAsync(HttpMethod.Post, "api/Application/CreateApplication", content);

                if (response.IsSuccessStatusCode)
                {
                    return RedirectToAction(nameof(Index));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "An error occurred while creating the application.");
                }
            }

            return View(application);
        }

        public async Task<IActionResult> Edit(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "Application" && c.Value == "EditApplication"))
                return StatusCode(403);

            ApplicationDto application = null;
            HttpResponseMessage response = await SendAuthorizedRequestAsync(HttpMethod.Get, $"api/Application/GetApplicationById/{id}");

            if (response.IsSuccessStatusCode)
            {
                var data = await response.Content.ReadAsStringAsync();
                application = JsonConvert.DeserializeObject<ApplicationDto>(data);
            }
            else
            {
                ViewBag.ErrorMessage = "An error occurred while fetching data.";
                return RedirectToAction(nameof(Index));
            }

            return View(application);
        }

        [HttpPost]
        public async Task<IActionResult> Edit([FromBody] ApplicationDto application)
        {
            if (!User.HasClaim(c => c.Type == "Application" && c.Value == "EditApplication"))
                return StatusCode(403);
            if (ModelState.IsValid)
            {
                var content = new StringContent(JsonConvert.SerializeObject(application), System.Text.Encoding.UTF8, "application/json");
                HttpResponseMessage response = await SendAuthorizedRequestAsync(HttpMethod.Put, $"api/Application/UpdateApplication/{application.Id}", content);

                if (response.IsSuccessStatusCode) 
                    return RedirectToAction("Index");
                else
                    ModelState.AddModelError(string.Empty, "An error occurred while updating the application.");
                
            }
            return View(application);
        }

        public async Task<IActionResult> Delete(Guid id)
        {
            if (!User.HasClaim(c => c.Type == "Application" && c.Value == "DeleteApplication"))
                return StatusCode(403);
            HttpResponseMessage response = await SendAuthorizedRequestAsync(HttpMethod.Delete, $"api/Application/DeleteApplication/{id}");

            if (response.IsSuccessStatusCode)
            {
                return RedirectToAction(nameof(Index));
            }
            else
            {
                ViewBag.ErrorMessage = "An error occurred while deleting the application.";
                return RedirectToAction(nameof(Index));
            }
        }

        private async Task<HttpResponseMessage> SendAuthorizedRequestAsync(HttpMethod method, string url, HttpContent content = null)
        {
            var token = GenerateClient.Client.DefaultRequestHeaders.Authorization?.Parameter;
            if (string.IsNullOrEmpty(token))
            {
                return new HttpResponseMessage(System.Net.HttpStatusCode.Unauthorized);
            }

            var request = new HttpRequestMessage(method, url)
            {
                Content = content
            };

            return await GenerateClient.Client.SendAsync(request);
        }
    }
}
