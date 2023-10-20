using MailKit.Net.Smtp;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Commons
{
    public class SendMail
    {
        public bool SendEmailNoBccAsync(string toMail, string subject, string confirmLink)
        {
            var email = new MimeMessage();

            email.From.Add(MailboxAddress.Parse("tramygeo@gmail.com"));
            email.To.Add(MailboxAddress.Parse(toMail));
            email.Subject = subject;

            var builder = new BodyBuilder();

            builder.HtmlBody = confirmLink + "<div style=\"font-weight: bold;\">Trân trọng, <br>\r\n        <div style=\"color: #FF630E;\">Bộ phận Nhân sự TechGenius</div>\r\n    </div>\r\n<br>    <img src=\"cid:image1\" alt=\"\" width=\"200px\">\r\n    <br>\r\n    <br>\r\n    <div>\r\n        Email liên hệ: \r\n    </div>\r\n    <div>Số điện thoại: </div>\r\n</div>";
            // Khởi tạo phần đính kèm của email (ảnh)
            var attachment = builder.LinkedResources.Add("File/Logo/logoWarehouse.png");
            attachment.ContentId = "image1"; // Thiết lập Content-ID cho phần đính kèm

            email.Body = builder.ToMessageBody();
            using var smtp = new MailKit.Net.Smtp.SmtpClient();
            smtp.Connect("smtp.gmail.com", 465, MailKit.Security.SecureSocketOptions.SslOnConnect);
            smtp.Authenticate("tramygeo@gmail.com", "shvmqyxqovhiapgh");
            try
            {
                smtp.Send(email);
            }
            catch (SmtpCommandException ex)
            {
                return false;
            }
            smtp.Disconnect(true);
            return true;
        }

    }
}
