using Amazon.Extensions.CognitoAuthentication;
using Amazon.AspNetCore.Identity.Cognito;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using WebAdvert.Web.Models;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> signInManager;
        private readonly UserManager<CognitoUser> userManager;
        private readonly CognitoUserPool pool;

        public AccountsController(CognitoUserPool cognitoUserPool, SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager)
        {
            this.pool = cognitoUserPool;
            this.signInManager = signInManager;
            this.userManager = userManager;
        }

        public async Task<ActionResult> Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<ActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists");
                    return View(model);
                }

                user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);
                var createdUser = await userManager.CreateAsync(user, model.Password).ConfigureAwait(false);

                if (createdUser.Succeeded) RedirectToAction("Confirm");
            }

            return View(model);

        }

        [HttpGet]
        public async Task<ActionResult> Confirm()
        {
            var model = new ConfirmModel();
            return View(model);

        }

        [HttpPost]
        [ActionName("Confirm")]
        public async Task<IActionResult> ConfirmPost(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByEmailAsync(model.Email).ConfigureAwait(false);
                if (user == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found");
                    return View(model);
                }

                var result = await ((CognitoUserManager<CognitoUser>)userManager)
                    .ConfirmSignUpAsync(user, model.Code, true).ConfigureAwait(false);
                if (result.Succeeded) return RedirectToAction("Index", "Home");

                foreach (var item in result.Errors) ModelState.AddModelError(item.Code, item.Description);

                return View(model);
            }

            return View(model);
        }

        [HttpGet]
        public async Task<ActionResult> Login()
        {
            var model = new LoginModel();
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(model.Email,
                    model.Password, model.RememberMe, false).ConfigureAwait(false);
                if (result.Succeeded)
                    return RedirectToAction("Index", "Home");
                ModelState.AddModelError("LoginError", "Email and password do not match");
            }

            return View("Login", model);
        }

        [HttpGet]
        public async Task<ActionResult> Reset()
        {
            var model = new ResetModel();
            return View(model);
        }

        [HttpPost]
        [ActionName("Reset")]
        public async Task<IActionResult> Reset(string Email,string CurrentPassword, string NewPassword)
        {
            if (ModelState.IsValid)
            {
                var user = pool.GetUser(Email);
                if (user.Status == null)
                {
                    ModelState.AddModelError("UserExists", "User not exist");
                    return View();
                }

                user.Attributes.Add(CognitoAttribute.Name.AttributeName, Email);
                var updatedUser = await userManager.ChangePasswordAsync(user, 
                    CurrentPassword,NewPassword).ConfigureAwait(false);

                if (updatedUser.Succeeded) RedirectToAction("Confirm");
            }

            return View();
        }

    }
}
