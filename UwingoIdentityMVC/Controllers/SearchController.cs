using Microsoft.AspNetCore.Mvc;
using System.Net.Http;

namespace UwingoIdentityMVC.Controllers
{
    public class SearchController : Controller
    {
        [HttpGet("GetDatas")]
        public async Task<IActionResult> GetDatas(string entityType, string searchTerm)
        {
            // Request'i dinamik olarak yönlendirme
            var apiUrl = $"api/{entityType}/Search?searchTerm={searchTerm}";

            var response = await GenerateClient.Client.GetAsync(apiUrl);
            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadAsStringAsync();
                return Ok(result);
            }

            return BadRequest("Veriler getirilemedi.");
        }
    }
}
