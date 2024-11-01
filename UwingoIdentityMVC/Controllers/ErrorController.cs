using Microsoft.AspNetCore.Mvc;

namespace UwingoIdentityMVC.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            switch (statusCode)
            {
                case 403:
                    return View("403");  // Özel 403 sayfası
                case 404:
                    return View("404");  // Özel 404 sayfası
                default:
                    return View("Error"); // Diğer durumlar için genel hata sayfası
            }
        }
    }
}
