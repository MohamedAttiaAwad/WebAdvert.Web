using Microsoft.AspNetCore.Mvc;

namespace WebAdvert.Web.Controllers
{
    public class AdvertManagementController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
