using System;

namespace UserRegistration_core_ms.Model
{
    public class UserModel
    {
        public Guid id { get; set; }
        public Guid? ManagerId { get; set; }
        public string? UserName { get; set; }
        public string? Designation { get; set; }
        public string? Email { get; set; }
        public List<string>? Role { get; set; }
        public string? Password { get; set; }
        public bool? FirstLogin { get; set; }
        public string? Image { get; set; }
        public Guid? CompanyId { get; set; }
        public string? ContactNumber { get; set; }
        public string? ISDCode { get; set; }
        public bool? IsContactVerified { get; set; }
        public bool? IsEmailVerified { get; set; }
        public bool? IsSecondaryEmailVerified { get; set; }
        public string? Country { get; set; }
        public string? City { get; set; }
        public string? SecondaryEmail { get; set; }
        public string? Language { get; set; }
        public string? TimeZone { get; set; }
        public bool? IsLogged { get; set; } = false;
        public List<Guid>? Iamids { get; set; }
        public Organization? UserOrganization { get; set; }
        public Notification? Notification { get; set; }
        public bool? IsActive { get; set; }
        public string? CreatedOn { get; set; }
        public string? CreatedBy { get; set; }
        public string? ModifiedBy { get; set; }
        public string? ModifiedOn { get; set; }
    }

    public class UsersDto
    {
        public Guid? MangerId { get; set; }
        public string? UserName { get; set; }
        public string? Designation { get; set; }
        public string? Email { get; set; }
        public List<string>? Role { get; set; }
        public string? Password { get; set; }
        public bool? FirstLogin { get; set; }
        public string? Image { get; set; }
        public Guid? CompanyId { get; set; }
        public string? ContactNumber { get; set; }
        public string? ISDCode { get; set; }
        public string? Country { get; set; }
        public string? City { get; set; }
        public string? SecondaryEmail { get; set; }
        public string? Language { get; set; }
        public string? TimeZone { get; set; }
        public string? CreatedBy { get; set; }
        public List<Guid>? Iamids { get; set; }
        public Organization? UserOrganization { get; set; }
        public Notification? Notification { get; set; }
    }

    public class UsersUpdateDto
    {
        public Guid id { get; set; }
        public Guid? MangerId { get; set; }
        public string? UserName { get; set; }
        public string? Designation { get; set; }
        public string? Email { get; set; }
        public List<string>? Role { get; set; }
        public bool? FirstLogin { get; set; }
        public string? Image { get; set; }
        public Guid? CompanyId { get; set; }
        public string? ContactNumber { get; set; }
        public string? ISDCode { get; set; }
        public string? Country { get; set; }
        public string? City { get; set; }
        public string? SecondaryEmail { get; set; }
        public string? Language { get; set; }
        public string? TimeZone { get; set; }
        public string? CreatedBy { get; set; }
        public List<Guid>? Iamids { get; set; }
        public Organization? UserOrganization { get; set; }
        public Notification? Notification { get; set; }
    }
    public class ForgotPasswordDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string UserName { get; set; } // Add this line


    }

    public class UpdateUserDataDto
    {
        public string? UserName { get; set; }
        public string? Country { get; set; }
        public string? City { get; set; }
        public string? Image { get; set; }
        public Guid? id { get; set; }




    }

    public class UpdateEmailDto
    {
        public string OldEmail { get; set; }
        public string NewEmail { get; set; }
    }

    public class UpdateContactNumberDto
    {
        public string Email { get; set; }
        public string ContactNumber { get; set; }
    }

    public class UpdateLanguageTimeZoneDto
    {
        public string? Email { get; set; }
        public string? Language { get; set; }
        public string? TimeZone { get; set; }
    }

    public class UpdateOrganizationDto
    {
        public string? Email { get; set; }
        public string? OrgName { get; set; }
        public string? Size { get; set; }
        public string? NoOfSubsidiaries { get; set; }
        public string? Industry { get; set; }
        public string? Website { get; set; }
        public string? HeadQuaterCountry { get; set; }
        public string? HeadQuaterTimeZone { get; set; }
    }

    public class UpdateNotificationDto
    {
        public string Email { get; set; }
        public bool? SubscribedToNewsletter { get; set; }
        public bool? NewLoginAlert { get; set; }
        public bool? ThirdPartyAccess { get; set; }
    }

    public class Organization
    {
        public string? OrgName { get; set; }
        public string? Size { get; set; }
        public string? NoOfSubsidiaries { get; set; }
        public string? Industry { get; set; }
        public string? Website { get; set; }
        public string? HeadQuaterCountry { get; set; }
        public string? HeadQuaterTimeZone { get; set; }
    }

    public class Notification
    {
        public bool? SubscribedToNewsletter { get; set; }
        public bool? NewLoginAlert { get; set; }
        public bool? ThirdPartyAccess { get; set; }
    }

    public class ForgotPasswordWithOldPwdDto
    {
        public string Email { get; set; }
        public string NewPassword { get; set; }
        public string OldPassword { get; set; }


    }

    public class UpdateSecondaryEmailDto
    {
        public Guid id { get; set; }
        public string? SecondaryEmail { get; set; }
    }

    public class UpdateEmailVerifyDto
    {
        public Guid id { get; set; }
        public bool? IsEmailVerified { get; set; }
    }
    public class UpdateSecondaryEmailVerifyDto
    {
        public Guid id { get; set; }
        public bool? IsSecondaryEmailVerified { get; set; }
    }

    public class Company
    {
        public Guid id { get; set; }
        public Guid? ParentCompanyId { get; set; }
        public string? CompanyName { get; set; }
        public string? CompanyShortName { get; set; }
        public string? CompanyAddresss { get; set; }
        public string? NoOfSubsidiaries { get; set; }
        public string? Website { get; set; }
        public string? Email { get; set; }
        public string? ContactNo { get; set; }
        public string? Country { get; set; }
        public string? CINNo { get; set; }
        public string? Image { get; set; }
        public string? Province { get; set; }
        public string? PostalCode { get; set; }
        public string? FiscalYearPeriod { get; set; }
        public string? Timezone { get; set; }
        public bool? IsActive { get; set; }
        public string? CreatedOn { get; set; }
        public string? CreatedBy { get; set; }
        public string? ModifiedBy { get; set; }
        public string? ModifiedOn { get; set; }

    }


    public class SubscribedUserDTo
    {
        public string? UserName { get; set; }
        public string? UserEmail { get; set; }
        public string? CompanyShortName { get; set; }
        public string? Phone { get; set; }
        public string? CompanyName { get; set; }
        public string? NoOfSubsidiaries { get; set; }
        public string? CompanyAddress { get; set; }
        public string? Province { get; set; }
        public string? PostalCode { get; set; }
        public string? Country { get; set; }
        public string? Timezone { get; set; }
        public string? CreatedBy { get; set; }
        public string? ModifiedBy { get; set; }
    }

    public class UserSessionReponse
    {
        public Guid id { get; set; }
        public Guid? ManagerId { get; set; }
        public string? UserName { get; set; }
        public string? Designation { get; set; }
        public string? Email { get; set; }
        public List<string>? Role { get; set; }
        public bool? FirstLogin { get; set; }
        public string? Image { get; set; }
        public Guid? CompanyId { get; set; }
        public string? CompanyName { get; set; }
        public string? CompanyShortName { get; set; }
        public string? FiscalYearPeriod { get; set; }
        public string? ContactNumber { get; set; }
        public string? ISDCode { get; set; }
        public bool? IsContactVerified { get; set; }
        public bool? IsEmailVerified { get; set; }
        public bool? IsSecondaryEmailVerified { get; set; }
        public string? Country { get; set; }
        public string? City { get; set; }
        public string? SecondaryEmail { get; set; }
        public string? Language { get; set; }
        public string? TimeZone { get; set; }

    }
    public class FailedUser
    {
        public int? RowNo { get; set; }
        public string? ErrorMessage { get; set; }
    }
}