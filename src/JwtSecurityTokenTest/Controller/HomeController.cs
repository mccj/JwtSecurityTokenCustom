using Microsoft.AspNetCore.Mvc;

namespace JwtSecurityTokenTest
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return Redirect("/swagger");
        }
    }
}
