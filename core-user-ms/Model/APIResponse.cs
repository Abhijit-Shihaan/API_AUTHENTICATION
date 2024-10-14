using System.Net;

namespace UserRegistration_core_ms.Model
{
    public class APIResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public bool IsSuccess { get; set; } = true;
        public List<string> ErrorMessages { get; set; }
        public List<string> Statusmessage { get; set; }
        public object Result { get; set; }
    }
    public class SubsidiaryResponse
    {
        public Guid id { get; set; }
        public string? CompanyName { get; set; }
    }
    public class SubsidiaryUserResponse
    {
        public Guid id { get; set; }
        public string? UserName { get; set; }
        public string? Designation { get; set; }
        public string? Email { get; set; }
        public List<string>? Role { get; set; }
        public Guid? CompanyId { get; set; }
        public string? CompanyName { get; set; }
        public string? ContactNumber { get; set; }
        public bool? IsActive { get; set; }
    }
    
}
