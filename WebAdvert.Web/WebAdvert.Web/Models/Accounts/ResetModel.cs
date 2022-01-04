namespace WebAdvert.Web.Models.Accounts
{
    public class ResetModel
    {
        public string Email { get; internal set; }
        public string CurrentPassword { get; set; }
        public string NewPassword { get; internal set; }
        public string ConfirmNewPassword { get; internal set; }

    }
}