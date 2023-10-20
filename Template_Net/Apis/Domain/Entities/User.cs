namespace Domain.Entities
{
    public class User : BaseEntity
    {
        public string UserName { get; set; }

        public string PasswordHash { get; set; }

        public DateTime DateOfBirth { get; set; }
    }
}
