using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace UwingoIdentityMVC.Controllers
{
    public class AppsController : Controller
    {
        //[Authorize(Policy = "Edit")]
        public IActionResult Index() => RedirectToAction("Inbox");

        public IActionResult Inbox() => View();

        public IActionResult ReadEmail() => View();

        public IActionResult Chat() => View();

        public IActionResult Contacts() => View();

        public IActionResult Calendar() => View();

        public IActionResult FileManager() => View();

        public IActionResult Invoice() => View();

        public IActionResult Tasks() => View();
        
        public IActionResult Projects() => View();

        public IActionResult Project() => View();

        [HttpGet("Project/Overview")]
        public IActionResult ProjectOverview() => View();
        
        [HttpGet("Project/Board")]
        public IActionResult ProjectBoard() => View();

        [HttpGet("Project/Teams")]
        public IActionResult ProjectTeams() => View();

        [HttpGet("Project/Files")]
        public IActionResult ProjectFiles() => View();

        [HttpGet("Ecommerce/Products")]
        public IActionResult EcommerceProducts() => View();

        [HttpGet("Ecommerce/ProductsList")]
        public IActionResult EcommerceProductList() => View();

        [HttpGet("Ecommerce/ProcuctDetail")]
        public IActionResult EcommerceProcuctDetail() => View();

        [HttpGet("Ecommerce/Cart")]
        public IActionResult EcommerceCart() => View();

        [HttpGet("Ecommerce/Checkout")]
        public IActionResult EcommerceCheckout() => View();
    }
}
