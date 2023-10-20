using Application.ViewModels.AuthViewModel;
using Domain.Entities;
using FluentValidation;
using Infrastructures;
using Microsoft.AspNetCore.Identity;

namespace WebAPI.Validations.Auth
{
    public class RegisterModelValidator : AbstractValidator<RegisterModel>
    {
        public RegisterModelValidator()
        {
            RuleFor(x => x.Username).NotEmpty().WithMessage("Tên đăng nhập không được để trống.")
                .WithMessage("Tên không quá 50 ký tự.");
            RuleFor(x => x.Email).NotEmpty().WithMessage("Email không được để trống.")
                .MaximumLength(50)
                .WithMessage("Email không quá 50 ký tự.");
            RuleFor(x => x.PhoneNumber).NotEmpty().WithMessage("Số điện thoại không được để trống.")
               .MaximumLength(10)
                .WithMessage("Số điện thoại phải có 10 ký tự.").MinimumLength(10)
                .WithMessage("Số điện thoại  phải có 10 ký tự.");
            RuleFor(x => x.Fullname).NotEmpty().WithMessage("Họ tên không được để trống.")
                .MaximumLength(50)
                .WithMessage("Họ tên ngắn không quá 50 ký tự.");
            RuleFor(x => x.Birthday).NotEmpty().WithMessage("Ngày sinh không được để trống.");
            RuleFor(x => x.Address).NotEmpty().WithMessage("Địa chỉ không được để trống.")
              .MaximumLength(200).WithMessage("Địa chỉ không quá 200 ký tự.");

            RuleFor(x => x.Password).NotEmpty().WithMessage("Mật khẩu không được để trống.")
              .MaximumLength(50).WithMessage("Mật khẩu không quá 50 ký tự.");
            RuleFor(x => x.Avatar).NotEmpty().WithMessage("Hình ảnh không được để trống.");
        }
    }
}
