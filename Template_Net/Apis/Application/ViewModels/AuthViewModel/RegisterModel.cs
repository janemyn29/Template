using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ViewModels.AuthViewModel
{
    public class RegisterModel
    {
        public string Email { get; set; }
        public string Username { get; set; }
        public string Fullname { get; set; } 
        public string Address { get; set; } 
        public string Avatar { get; set; }
        public string PhoneNumber { get; set; }
        public string Password { get; set; }
        public DateTime Birthday { get; set; }
    }
}
