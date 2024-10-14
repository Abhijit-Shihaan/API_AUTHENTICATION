using Azure;
using Azure.Storage.Blobs;
using ExcelDataReader;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Cosmos.Linq;
using Microsoft.Azure.Cosmos.Serialization.HybridRow;
using Serilog;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Drawing;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using UserRegistration_core_ms.Model;
using System.Net.Http.Headers;
using System.Web;
using System.Linq;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace UserRegistration_core_ms.Controllers
{
    [Route("/api/user/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        protected APIResponse _response;
        private readonly Container _container;
        private readonly Container _companyContainer;
        private readonly string _databaseName;
        private readonly BlobServiceClient _blobServiceClient;
        private string _baseUrl;
        private string _appName;
        private object subsidiaries;

        public UserController(CosmosClient cosmosClient, List<KeyValuePair<string, string>> keys, BlobServiceClient blobServiceClient)
        {
            _databaseName = keys.FirstOrDefault(k => k.Key == "DBName").Value;
            Database database = cosmosClient.GetDatabase(_databaseName);
            _container = database.GetContainer("users-db");
            _companyContainer = database.GetContainer("companies-db");
            _response = new APIResponse();
            _blobServiceClient = blobServiceClient;
            _baseUrl = keys.FirstOrDefault(k => k.Key == "API_BASE_URL").Value;
            _appName = keys.FirstOrDefault(k => k.Key == "APPNAME").Value;
        }

        /// <summary>
        /// GetHealth
        /// </summary>
        /// <returns></returns>
        [HttpGet(nameof(GetHealth))]
        [Authorize]
        public IActionResult GetHealth()
        {
            try
            {
                bool isHealthy = PerformHealthCheck();
                var timestamp = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(5) + TimeSpan.FromMinutes(30)).ToString("yyyy-MM-ddTHH:mm:sszzz");

                if (isHealthy)
                {
                    Response.Headers.Add("X-Health-Status", "Service is healthy");
                    Response.Headers.Add("X-Health-Timestamp", timestamp);
                    var jsonResponse = new
                    {
                        status = "Service is healthy",
                        timestamp = timestamp
                    };

                    return Ok(jsonResponse);
                }
                else
                {
                    Response.Headers.Add("X-Health-Status", "Service is not healthy");
                    Response.Headers.Add("X-Health-Timestamp", timestamp);
                    var jsonResponse = new
                    {
                        status = "Service is not healthy",
                        timestamp = timestamp
                    };
                    return BadRequest(jsonResponse);
                }


            }
            catch (Exception ex)
            {
                return StatusCode(500, "Service is not healthy: " + ex.Message);
            }
        }
        /// <summary>
        /// Head endpoint for Health
        /// </summary>
        /// <returns></returns>
        [HttpHead(nameof(Health))]
        [Authorize]
        public IActionResult Health()
        {
            try
            {
                bool isHealthy = PerformHealthCheck();
                var timestamp = DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(5) + TimeSpan.FromMinutes(30)).ToString("yyyy-MM-ddTHH:mm:sszzz");

                if (isHealthy)
                {
                    Response.Headers.Add("X-Health-Status", "Service is healthy");
                    Response.Headers.Add("X-Health-Timestamp", timestamp);

                    return Ok();
                }
                else
                {
                    Response.Headers.Add("X-Health-Status", "Service is not healthy");
                    Response.Headers.Add("X-Health-Timestamp", timestamp);
                    return BadRequest();
                }


            }
            catch (Exception ex)
            {
                return StatusCode(500, "Service is not healthy: " + ex.Message);
            }
        }

        private bool PerformHealthCheck()
        {
            try
            {
                if (_container != null && _databaseName != null)
                {
                    return true;
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error connecting to the database: {ex.Message}");
            }

            return false;
        }
        /// <summary>
        /// Get All User Data
        /// </summary>
        /// <returns></returns>
        [HttpGet(nameof(GetAllUserData))]
        [Authorize]

        public async Task<ActionResult<IEnumerable<UserModel>>> GetAllUserData()
        {
            try
            {
                var query = new QueryDefinition("SELECT * FROM c");
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = new List<UserModel>();
                FeedResponse<UserModel> response;
                while (iterator.HasMoreResults)
                {
                    response = await iterator.ReadNextAsync();
                    results.AddRange(response);
                }

                var selectedFields = results.Select(usr => new
                {
                    usr.id,
                    usr.UserName,
                    usr.Email,
                    usr.SecondaryEmail,
                    usr.Role,
                    usr.Image,
                    usr.FirstLogin,
                    usr.CompanyId,
                    usr.ContactNumber,
                    usr.ISDCode,
                    usr.Country,
                    usr.City,
                    usr.Designation,
                    usr.Language,
                    usr.TimeZone,
                    usr.IsActive,
                    usr.IsContactVerified,
                    usr.IsEmailVerified,
                    usr.IsSecondaryEmailVerified,
                    usr.UserOrganization,
                    usr.Notification,
                    usr.Iamids,
                    usr.CreatedBy,
                    usr.CreatedOn
                }).Reverse();

                Log.Information("GetAllUserData()");
                return Ok(selectedFields);
            }
            catch (Exception ex)
            {
                Log.Error("GetAllUserData() => {ex}", ex.Message);
                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// Get All Active User Data
        /// </summary>
        /// <returns></returns>
        [HttpGet(nameof(GetAllActiveUserData))]
        [Authorize]

        public async Task<ActionResult<IEnumerable<UserModel>>> GetAllActiveUserData()
        {
            try
            {
                var query = new QueryDefinition("SELECT * FROM c where c.IsActive = true");

                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = new List<UserModel>();
                FeedResponse<UserModel> response;
                while (iterator.HasMoreResults)
                {
                    response = await iterator.ReadNextAsync();
                    results.AddRange(response);
                }

                var selectedFields = results.Select(usr => new
                {
                    usr.id,
                    usr.UserName,
                    usr.Email,
                    usr.SecondaryEmail,
                    usr.Role,
                    usr.Image,
                    usr.FirstLogin,
                    usr.CompanyId,
                    usr.ContactNumber,
                    usr.ISDCode,
                    usr.Country,
                    usr.City,
                    usr.Designation,
                    usr.Language,
                    usr.TimeZone,
                    usr.IsActive,
                    usr.IsContactVerified,
                    usr.IsEmailVerified,
                    usr.IsSecondaryEmailVerified,
                    usr.UserOrganization,
                    usr.Notification,
                    usr.Iamids,
                    usr.CreatedBy,
                    usr.CreatedOn
                }).Reverse();

                Log.Information("GetAllActiveUserData()");
                return Ok(selectedFields);
            }
            catch (Exception ex)
            {
                Log.Error("GetAllActiveUserData() => {ex}", ex.Message);
                return BadRequest(ex.Message);
            }
        }


        /// <summary>
        /// Get All Active User Data created by Parent admin
        /// </summary>
        [HttpGet(nameof(GetAllActiveUserDataByCompanyID) + "/{compid}")]
        [Authorize]

        public async Task<ActionResult<IEnumerable<SubsidiaryUserResponse>>> GetAllActiveUserDataByCompanyID(Guid compid)
        {
            try
            {
                // Query to get all subsidiaries including the parent company itself
                var subsidiaryQuery = new QueryDefinition(
                    "SELECT c.id, c.CompanyName FROM c WHERE c.id = @companyId OR c.ParentCompanyId = @companyId")
                    .WithParameter("@companyId", compid);

                var subsidiaryIterator = _companyContainer.GetItemQueryIterator<SubsidiaryResponse>(subsidiaryQuery);
                var subsidiaries = new List<SubsidiaryResponse>();
                while (subsidiaryIterator.HasMoreResults)
                {
                    var subResponse = await subsidiaryIterator.ReadNextAsync();
                    subsidiaries.AddRange(subResponse);
                }

                // Extract all company IDs including the parent company and its subsidiaries
                var companyIds = subsidiaries.Select(sub => sub.id).ToList();

                // Query to get all active users within the companies
                var userQuery = new QueryDefinition(
                    "SELECT * FROM c WHERE c.IsActive = true AND ARRAY_CONTAINS(@companyIds, c.CompanyId)")
                    .WithParameter("@companyIds", companyIds);

                var iterator = _container.GetItemQueryIterator<UserModel>(userQuery);
                var results = new List<UserModel>();
                while (iterator.HasMoreResults)
                {
                    var response = await iterator.ReadNextAsync();
                    results.AddRange(response);
                }

                results.Reverse();

                // Map users to SubsidiaryUserResponse
                var subsidiaryUsers = results.Select(usr => new SubsidiaryUserResponse
                {
                    id = usr.id,
                    UserName = usr.UserName,
                    CompanyId = usr.CompanyId,
                    Designation = usr.Designation,
                    Role = usr.Role,
                    CompanyName = subsidiaries.FirstOrDefault(s => s.id == usr.CompanyId)?.CompanyName,
                    Email = usr.Email,
                    ContactNumber = usr.ContactNumber,
                    IsActive = usr.IsActive
                }).ToList();

                Log.Information("GetAllActiveUserDataByCompanyID()");
                return Ok(subsidiaryUsers);
            }
            catch (Exception ex)
            {
                Log.Error("GetAllActiveUserDataByCompanyID() => {ex}", ex.Message);
                return BadRequest(ex.Message);
            }
        }


        /// <summary>
        /// Get All Inactive User Data created by Parent admin
        /// </summary>
        /// <returns></returns>

        [HttpGet(nameof(GetAllInactiveUserDataByCompanyID) + "/{compid}")]
        [Authorize]

        public async Task<ActionResult<IEnumerable<SubsidiaryUserResponse>>> GetAllInactiveUserDataByCompanyID(Guid compid)
        {
            try
            {
                // Query to get all subsidiaries including the parent company itself
                var subsidiaryQuery = new QueryDefinition(
                    "SELECT c.id, c.CompanyName FROM c WHERE c.id = @companyId OR c.ParentCompanyId = @companyId")
                    .WithParameter("@companyId", compid);

                var subsidiaryIterator = _companyContainer.GetItemQueryIterator<SubsidiaryResponse>(subsidiaryQuery);
                var subsidiaries = new List<SubsidiaryResponse>();
                while (subsidiaryIterator.HasMoreResults)
                {
                    var subResponse = await subsidiaryIterator.ReadNextAsync();
                    subsidiaries.AddRange(subResponse);
                }

                // Extract all company IDs including the parent company and its subsidiaries
                var companyIds = subsidiaries.Select(sub => sub.id).ToList();

                // Query to get all inactive users within the companies
                var userQuery = new QueryDefinition(
                    "SELECT * FROM c WHERE c.IsActive = false AND ARRAY_CONTAINS(@companyIds, c.CompanyId)")
                    .WithParameter("@companyIds", companyIds);

                var iterator = _container.GetItemQueryIterator<UserModel>(userQuery);
                var results = new List<UserModel>();
                while (iterator.HasMoreResults)
                {
                    var response = await iterator.ReadNextAsync();
                    results.AddRange(response);
                }

                results.Reverse();

                // Map users to SubsidiaryUserResponse
                var subsidiaryUsers = results.Select(usr => new SubsidiaryUserResponse
                {
                    id = usr.id,
                    UserName = usr.UserName,
                    CompanyId = usr.CompanyId,
                    Designation = usr.Designation,
                    Role = usr.Role,
                    CompanyName = subsidiaries.FirstOrDefault(s => s.id == usr.CompanyId)?.CompanyName,
                    Email = usr.Email,
                    ContactNumber = usr.ContactNumber,
                    IsActive = usr.IsActive
                }).ToList();

                Log.Information("GetAllInactiveUserDataByParentCompanyID()");
                return Ok(subsidiaryUsers);
            }
            catch (Exception ex)
            {
                Log.Error("GetAllInactiveUserDataByParentCompanyID() => {ex}", ex.Message);
                return BadRequest(ex.Message);
            }
        }

        // POST api/values
        /// <summary>
        /// Create User Data
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        [HttpPost(nameof(PostUsersData))]
        [Authorize]

        public async Task<ActionResult<APIResponse>> PostUsersData([FromBody] UsersDto data)
        {
            try
            {
                var query = new QueryDefinition(
               "SELECT * " +
               "FROM c " +
               "WHERE c.Email = @email ")
               .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = new UserModel();
                var key = "b14ca5898a4e4133bbce2ea2315a1916";
                if (!results.Any())
                {
                    Guid newGuid = Guid.NewGuid();
                    UserModel newRec = new UserModel();
                    newRec.id = newGuid;
                    newRec = CopyDtoToUser(data, newRec);
                    newRec.IsActive = true;
                    newRec.IsEmailVerified = false;
                    newRec.Password = EncryptString(key, data.Password);
                    newRec.CreatedOn = DateTime.Now.ToString();
                    newRec.ModifiedOn = DateTime.Now.ToString();
                    ItemResponse<UserModel> response = await _container.CreateItemAsync<UserModel>(newRec);
                    _response.Result = response.Resource;
                    _response.StatusCode = HttpStatusCode.Created;

                    Log.Information("PostUsersData()");
                    return Ok(_response);
                }
                else
                {
                    Log.Information("PostUsersData() => User Exists!");
                    return BadRequest("User Exists! ");
                }
            }
            catch (Exception ex)
            {
                Log.Error("PostUsersData() => Post Failed!!");
                return BadRequest("Post Failed! " + ex.Message);
            }
        }

        [HttpPost(nameof(PostSubscribedUsersData))]
        public async Task<ActionResult<APIResponse>> PostSubscribedUsersData([FromBody] SubscribedUserDTo data)
        {
            try
            {
                var query = new QueryDefinition(
                    "SELECT * FROM c WHERE c.Email = @email")
                    .WithParameter("@email", data.UserEmail);

                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();

                if (results.Any())
                {
                    Log.Information("PostSubscribedUsersData() => User Exists!");
                    return BadRequest("User Exists!");
                }

                Guid FetchedCompanyId = await CreateCompany(data);
                UserModel newUser = CreateNewUser(data, FetchedCompanyId);

                bool isRegisteredInKeycloak = false;
                try
                {
                    // Step 1: Get Admin Access Token
                    var tokenResponse = await GetAdminAccessToken();
                    string adminToken = tokenResponse.access_token;
                    Log.Information(adminToken);

                    // Step 2: Register User in Keycloak
                    isRegisteredInKeycloak = await RegisterUserInKeycloakDirect(data, adminToken);
                }
                catch (Exception ex)
                {
                    Log.Warning($"Failed to register user in Keycloak: {ex.Message}. Proceeding with local registration only.");
                }

                ItemResponse<UserModel> response = await _container.CreateItemAsync<UserModel>(newUser);
                _response.Result = response.Resource;
                _response.StatusCode = HttpStatusCode.Created;

                Log.Information($"PostSubscribedUsersData() - User created successfully. Keycloak registration: {(isRegisteredInKeycloak ? "Successful" : "Failed")}");
                return Ok(_response);
            }
            catch (Exception ex)
            {
                Log.Error($"PostSubscribedUsersData() => Post Failed!! Error: {ex.Message}");
                return BadRequest($"Post Failed! {ex.Message}");
            }
        }

        private async Task<TokenResponse> GetAdminAccessToken()
        {
            var httpClient = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, "https://idp.shihaantech.net/realms/medium-dev/protocol/openid-connect/token");
            var requestBody = new FormUrlEncodedContent(new[]
            {
        new KeyValuePair<string, string>("grant_type", "client_credentials"),
        new KeyValuePair<string, string>("client_id", "shihaantech"),
        new KeyValuePair<string, string>("client_secret", "qpWnsOyEyzKQ8sbFER7KRi27zTyBLpmV")
    });

            request.Content = requestBody;
            var response = await httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<TokenResponse>(content);
        }

        private async Task<bool> RegisterUserInKeycloakDirect(SubscribedUserDTo data, string adminToken)
        {
            var httpClient = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Post, "https://idp.shihaantech.net/admin/realms/medium-dev/users");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
            var keycloakUsername = data.UserName.Replace(" ", "");

            var userBody = new
            {
                attributes = new { attribute_key = "test_value" },
                credentials = new[]
                {
            new
            {
                temporary = false,
                type = "password",
                value = "Admin@1234"
            }
        },
                //username = data.UserName,
                username = keycloakUsername,  // Use the username without spaces
                email = data.UserEmail,
                emailVerified = true,
                enabled = true
            };

            request.Content = new StringContent(JsonConvert.SerializeObject(userBody), Encoding.UTF8, "application/json");
            var response = await httpClient.SendAsync(request);

            return response.IsSuccessStatusCode;
        }

        public class TokenResponse
        {
            public string access_token { get; set; }
        }


        private UserModel CreateNewUser(SubscribedUserDTo data, Guid companyId)
        {
            UserModel newUser = new UserModel
            {
                id = Guid.NewGuid(),
                CompanyId = companyId,
                IsActive = true,
                Email = data.UserEmail,
                IsEmailVerified = false,
                FirstLogin = true,
                Role = new List<string> { "Parent-Admin" },
                CreatedOn = DateTime.Now.ToString(),
                ModifiedOn = DateTime.Now.ToString(),
                UserOrganization = new Organization
                {
                    OrgName = data.CompanyName,
                    HeadQuaterTimeZone = data.Timezone,
                    HeadQuaterCountry = data.Country,
                    NoOfSubsidiaries = data.NoOfSubsidiaries
                }
            };

            // Copy other properties from DTO to User model
            newUser = CopyDtoToUser(data, newUser);

            return newUser;
        }

        private async Task<bool> RegisterUserInKeycloakDirect(SubscribedUserDTo userDto)
        {
            try
            {
                var keycloakUrl = "https://idp.shihaantech.net/auth/admin/realms/medium-dev/users";

                // The user registration data to be sent to Keycloak
                var keycloakUser = new
                {
                    username = userDto.UserEmail,
                    email = userDto.UserEmail,
                    firstName = userDto.UserName,
                    enabled = true,
                    credentials = new[] {
                new {
                    type = "password",
                    value = "HardcodedPredefinedPassword123!", // Use a hardcoded or generated password
                    temporary = true
                }
            }
                };

                using (var httpClient = new HttpClient())
                {
                    // Set the admin token (replace "yourAdminToken" with the actual token)
                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "yourAdminToken");

                    var content = new StringContent(JsonConvert.SerializeObject(keycloakUser), Encoding.UTF8, "application/json");
                    var response = await httpClient.PostAsync(keycloakUrl, content);

                    if (response.IsSuccessStatusCode)
                    {
                        Log.Information("User successfully registered in Keycloak");
                        return true;
                    }
                    else
                    {
                        var errorContent = await response.Content.ReadAsStringAsync();
                        Log.Error($"Failed to register user in Keycloak: {response.StatusCode} - {response.ReasonPhrase}");
                        Log.Error($"Error details: {errorContent}");
                        return false;
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Exception occurred while registering user in Keycloak: {ex.Message}");
                return false;
            }
        }



        [HttpPost("UploadBulkUsers")]
        [Authorize]

        public async Task<IActionResult> UploadBulkUsers(IFormFile file, Guid companyId, string createdBy)
        {
            try
            {
                if (file == null || file.Length == 0)
                    return BadRequest("No file uploaded.");

                using var stream = new MemoryStream();
                await file.CopyToAsync(stream);
                stream.Position = 0;
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

                using var reader = ExcelReaderFactory.CreateReader(stream);
                var result = reader.AsDataSet();

                List<UserModel> userList = new List<UserModel>();
                List<FailedUser> failedUserList = new List<FailedUser>();
                var table = result.Tables[0];

                for (var i = 1; i < table.Rows.Count; i++)
                {
                    string errorMessage = string.Empty;
                    var row = table.Rows[i];
                    string userName = row[0].ToString()?.Trim() + " " + row[1].ToString()?.Trim();
                    string userEmail = row[2].ToString()?.Trim();
                    string contactno = row[3].ToString()?.Trim();
                    string role = row[5].ToString()?.Trim();
                    errorMessage = ValidateUser(userName, userEmail, contactno, role);
                    if (!string.IsNullOrEmpty(errorMessage))
                    {
                        failedUserList.Add(new FailedUser { RowNo = i + 1, ErrorMessage = errorMessage });
                    }
                    else
                    {
                        Organization uo = new Organization();
                        uo = await GetOrganizationInfo(companyId);

                        UserModel usr = new UserModel
                        {
                            UserName = userName,
                            Email = userEmail,
                            ContactNumber = contactno,
                            Designation = row[4].ToString()?.Trim(),
                            Role = role.Split(',').ToList<string>(),
                            CompanyId = companyId,
                            IsActive = true,
                            CreatedBy = createdBy,
                            CreatedOn = DateTime.Now.ToLongDateString(),
                            UserOrganization = uo
                        };

                        Guid newId = Guid.NewGuid();
                        usr.id = newId;
                        userList.Add(usr);

                    }

                }
                foreach (var user in userList)
                {
                    await _container.CreateItemAsync(user);
                    await NotifyUser(user.UserName, user.Email, user.UserOrganization.OrgName);
                }
                Log.Information("UploadBulkSubsidiaries()");
                return Ok(new { Message = "File processed successfully.", UsersAdded = userList.Count, FailedUsers = failedUserList });
            }
            catch (Exception ex)
            {
                Log.Error("UploadBulkSubsidiaries() => {ex}", ex.Message);
                return BadRequest(ex.Message);
            }
        }

        private async Task NotifyUser(string userName, string email, string orgName)
        {
            var url = _baseUrl + "/api/admin/Notification/SetNewInitialPasswordLinkForRecipientEmail?AppName=" + _appName;
            var recipientUserName = userName;
            var recipientEmail = email;
            var companyName = orgName;

            var payload = new
            {
                recipientUserName = recipientUserName,
                recipientEmail = recipientEmail,
                companyName = companyName
            };

            var jsonPayload = System.Text.Json.JsonSerializer.Serialize(payload);
            var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                var response = await client.PostAsync(url, content);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    Console.WriteLine("Success! Response: " + responseContent);
                }
                else
                {
                    Console.WriteLine("Error: " + response.StatusCode);
                }
            }
        }

        private async Task<Organization> GetOrganizationInfo(Guid companyId)
        {
            ItemResponse<Company> response = await _companyContainer.ReadItemAsync<Company>(companyId.ToString(), new PartitionKey(companyId.ToString()));
            Company item = response.Resource;
            Organization org = new Organization();
            org.OrgName = item.CompanyName;
            org.NoOfSubsidiaries = item.NoOfSubsidiaries;
            org.Website = item.Website;
            org.HeadQuaterCountry = item.Country;
            org.HeadQuaterTimeZone = item.Timezone;
            return org;
        }
        private string ValidateUser(string? userName, string? userEmail, string? contactno, string? role)
        {
            string errorMessage = string.Empty;
            if (string.IsNullOrEmpty(userName))
            {
                errorMessage = "Username cannot be blank!\n";
            }
            if (string.IsNullOrEmpty(userEmail))
            {
                errorMessage = "Email cannot be blank!\n";
            }
            else
            {
             var userExists = _container.GetItemLinqQueryable<UserModel>(true)
                        .Where(c => c.Email == userEmail)
                        .AsEnumerable()
                        .Any();

                if (userExists)
                {
                    errorMessage = "Email " + userEmail + " already exist!\n";
                }
            }

            if (string.IsNullOrEmpty(contactno))
            {
                errorMessage = "Contact Number cannot be blank!\n";
            }
            if (string.IsNullOrEmpty(role))
            {
                errorMessage = "Role cannot be blank!\n";
            }
            return errorMessage;
        }


     

        /// <summary>
        /// Get User data by id
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        // GET api/values/5
        [HttpGet(nameof(GetUsersDataById) + "/{id}")]
        [Authorize]

        public async Task<ActionResult<UserModel>> GetUsersDataById(Guid id)
        {
            try
            {
                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(id.ToString(), new PartitionKey(id.ToString()));
                UserModel item = response.Resource;

                if (item != null)
                {
                    var selectedUserData = new
                    {
                        id = item.id,
                        UserName = item.UserName,
                        Email = item.Email,
                        SecondaryEmail = item.SecondaryEmail,
                        Role = item.Role,
                        Image = item.Image,
                        FirstLogin = item.FirstLogin,
                        CompanyId = item.CompanyId,
                        ContactNumber = item.ContactNumber,
                        ISDCode = item.ISDCode,
                        Country = item.Country,
                        City = item.City,
                        Designation = item.Designation,
                        Language = item.Language,
                        TimeZone = item.TimeZone,
                        IsActive = item.IsActive,
                        IsContactVerified = item.IsContactVerified,
                        IsEmailVerified = item.IsEmailVerified,
                        IsSecondaryEmailVerified = item.IsSecondaryEmailVerified,
                        UserOrganization = item.UserOrganization,
                        Notification = item.Notification,
                        Iamids = item.Iamids,
                        CreatedBy = item.CreatedBy,
                        CreatedOn = item.CreatedOn,
                        ModifiedBy = item.ModifiedBy,
                        ModifiedOn = item.ModifiedOn
                    };

                    Log.Information("GetUsersDataById()");
                    return Ok(selectedUserData);
                }
                else
                {
                    Log.Information("GetUsersDataById() => User Not Found!");
                    return BadRequest("User Not Found");
                }
            }
            catch (Exception ex)
            {
                Log.Error("GetUsersDataById() => {ex}", ex.Message);
                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// Get User data by email
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        // GET api/values/5
        [HttpGet(nameof(GetUsersDataByEmail) + "/{Email}")]
        [Authorize]

        public async Task<ActionResult<IEnumerable<object>>> GetUsersDataByEmail(string Email)
        {
            try
            {
                var query = new QueryDefinition("SELECT * FROM c WHERE c.Email = @Email")
                    .WithParameter("@Email", Email);

                var queryResultSetIterator = _container.GetItemQueryIterator<UserModel>(query);

                var results = new List<UserModel>();
                while (queryResultSetIterator.HasMoreResults)
                {
                    var response = await queryResultSetIterator.ReadNextAsync();
                    results.AddRange(response);
                }

                if (results.Count == 0)
                {
                    Log.Information("GetUsersDataByEmail() => Email not found");
                    return NotFound();
                }

                var selectedFields = results.Select(usr => new
                {
                    usr.id,
                    usr.UserName,
                    usr.Email,
                    usr.SecondaryEmail,
                    usr.Role,
                    usr.Image,
                    usr.FirstLogin,
                    usr.CompanyId,
                    usr.ContactNumber,
                    usr.ISDCode,
                    usr.Country,
                    usr.City,
                    usr.Designation,
                    usr.Language,
                    usr.TimeZone,
                    usr.IsActive,
                    usr.IsContactVerified,
                    usr.IsEmailVerified,
                    usr.IsSecondaryEmailVerified,
                    usr.UserOrganization,
                    usr.Notification,
                    usr.Iamids,
                    usr.CreatedBy,
                    usr.CreatedOn
                }).Reverse();

                Log.Information("GetUsersDataByEmail()");

                return Ok(selectedFields);
            }
            catch (Exception ex)
            {
                Log.Error("GetUsersDataByEmail() => {ex}", ex.Message);
                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// Update User Data By Primary Email
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateUserDataByPrimaryEmail))]
        [Authorize]

        public async Task<IActionResult> UpdateUserDataByPrimaryEmail([FromBody] UsersUpdateDto data)
        {
            try
            {
                var query = new QueryDefinition(
                "SELECT * " +
                "FROM c " +
                "WHERE c.Email = @email ")
                .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = new UserModel();
                if (results.Any())
                {
                    foreach (var item in results)
                    {
                        user = item;
                    }
                }
                data.id = user.id;
                user = CopyDtoToUser(data, user);

                user.ModifiedOn = DateTime.Now.ToShortDateString();
                user.ModifiedBy = data.Email;

                ItemResponse<UserModel> response = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = response.Resource;

                Log.Information("UpdateUserDataByPrimaryEmail()");
                return Ok("User Updated!");
            }
            catch (Exception ex)
            {
                Log.Error("UpdateUserDataByPrimaryEmail() => {ex}", ex.Message);
                return BadRequest("User Update Failed! " + ex.Message);
            }
        }

        /// <summary>
        /// Update User Data By UserId
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateUserDataByUserId))]
        [Authorize]

        public async Task<IActionResult> UpdateUserDataByUserId([FromBody] UsersUpdateDto data)
        {
            try
            {
                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(data.id.ToString(), new PartitionKey(data.id.ToString()));
                UserModel user = response.Resource;
                user = CopyDtoToUser(data, user);

                user.ModifiedOn = DateTime.Now.ToShortDateString();
                user.ModifiedBy = data.Email;

                ItemResponse<UserModel> responseResult = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = responseResult.Resource;

                Log.Information("UpdateUserDataByPrimaryEmail()");
                return Ok("User Updated!");
            }
            catch (Exception ex)
            {
                Log.Error("UpdateUserDataByPrimaryEmail() => {ex}", ex.Message);
                return BadRequest("User Update Failed! " + ex.Message);
            }
        }

        /// <summary>
        /// Update UserName Country City By PrimaryEmail
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateUserNameCountryCityByPrimaryEmail))]
        [Authorize]

        public async Task<IActionResult> UpdateUserNameCountryCityByPrimaryEmail([FromBody] UpdateUserDataDto data)
        {
            try
            {

                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(data.id.ToString(), new PartitionKey(data.id.ToString()));
                UserModel user = response.Resource;

                if (user != null)
                {
                    user = CopyDtoToUser(data, user);

                    ItemResponse<UserModel> Uresponse = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                    UserModel updatedItem = Uresponse.Resource;
                    Log.Information("UpdateUserNameCountryCityByPrimaryEmail()");
                    return Ok("User name, country, and city updated!");
                }
                else
                {
                    Log.Information("UpdateUserNameCountryCityByPrimaryEmail() => User not found!");
                    return BadRequest("User not found!");
                }
            }
            catch (Exception ex)
            {
                Log.Error("UpdateUserNameCountryCityByPrimaryEmail() => {ex}", ex.Message);
                return BadRequest("Failed to update user name, country, and city: " + ex.Message);
            }
        }

        /// <summary>
        /// Update Contact Number By Email
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateContactNumberByEmail))]
        [Authorize]

        public async Task<IActionResult> UpdateContactNumberByEmail([FromBody] UpdateContactNumberDto data)
        {
            try
            {
                var query = new QueryDefinition(
                    "SELECT * " +
                    "FROM c " +
                    "WHERE c.Email = @email ")
                    .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                var user = results.FirstOrDefault();
                if (user == null)
                {
                    Log.Information("UpdateContactNumberByEmail() => User not found!");
                    return BadRequest("User not found!");
                }

                user.ModifiedOn = DateTime.UtcNow.ToString();
                user.ModifiedBy = data.Email;
                user = CopyDtoToUser(data, user);

                await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                Log.Information("UpdateContactNumberByEmail() => Contact number updated successfully!");
                return Ok("Contact number updated successfully!");
            }
            catch (Exception ex)
            {
                Log.Information("UpdateContactNumberByEmail() => {ex}", ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error updating contact number: {ex.Message}");
            }
        }

        /// <summary>
        /// Update Language TimeZone By Email
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateLanguageTimeZoneByEmail))]
        [Authorize]

        public async Task<IActionResult> UpdateLanguageTimeZoneByEmail([FromBody] UpdateLanguageTimeZoneDto data)
        {
            try
            {
                var query = new QueryDefinition(
                    "SELECT * " +
                    "FROM c " +
                    "WHERE c.Email = @email ")
                    .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                var user = results.FirstOrDefault();
                if (user == null)
                {
                    Log.Information("UpdateLanguageTimeZoneByEmail() => User not found!");
                    return BadRequest("User not found!");
                }
                user.ModifiedOn = DateTime.UtcNow.ToString();
                user.ModifiedBy = data.Email;
                user = CopyDtoToUser(data, user);
                await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                Log.Information("UpdateLanguageTimeZoneByEmail()");
                return Ok("Language and time zone updated successfully!");
            }
            catch (Exception ex)
            {
                Log.Error("UpdateLanguageTimeZoneByEmail() => {ex}", ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error updating language and time zone: {ex.Message}");
            }
        }

        /// <summary>
        /// Update Organization By Email
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateOrganizationByEmail))]
        [Authorize]

        public async Task<IActionResult> UpdateOrganizationByEmail([FromBody] UpdateOrganizationDto data)
        {
            try
            {
                var query = new QueryDefinition(
                    "SELECT * " +
                    "FROM c " +
                    "WHERE c.Email = @email ")
                    .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                var user = new UserModel();
                if (results.Any())
                {
                    user = results.FirstOrDefault();

                }
                else
                {
                    Log.Information("UpdateOrganizationByEmail() => User not found!");
                    return BadRequest("User not found!");
                }

                if (user.UserOrganization == null)
                {
                    user.UserOrganization = new Organization();
                }
                user.UserOrganization = CopyDtoToOrg(data, user.UserOrganization);

                user.ModifiedOn = DateTime.Now.ToString();
                user.ModifiedBy = data.Email;
                await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());
                Log.Information("UpdateOrganizationByEmail()");
                return Ok("Organization data updated successfully!");
            }
            catch (Exception ex)
            {
                Log.Error("UpdateOrganizationByEmail() => {ex}", ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error updating organization data: {ex.Message}");
            }
        }

        /// <summary>
        /// Update Notification By Email
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateNotificationByEmail))]
        [Authorize]

        public async Task<IActionResult> UpdateNotificationByEmail([FromBody] UpdateNotificationDto data)
        {
            try
            {
                var query = new QueryDefinition(
                    "SELECT * " +
                    "FROM c " +
                    "WHERE c.Email = @email ")
                    .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                var user = results.FirstOrDefault();
                if (user == null)
                {
                    Log.Information("UpdateNotificationByEmail() => User not found!");
                    return BadRequest("User not found!");
                }

                if (user.Notification == null)
                {
                    user.Notification = new Notification();
                }

                user.Notification.SubscribedToNewsletter = data.SubscribedToNewsletter;
                user.Notification.NewLoginAlert = data.NewLoginAlert;
                user.Notification.ThirdPartyAccess = data.ThirdPartyAccess;

                user.ModifiedOn = DateTime.UtcNow.ToShortDateString();
                user.ModifiedBy = data.Email;

                await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());
                Log.Information("UpdateNotificationByEmail()");

                return Ok("Notification settings updated successfully!");
            }
            catch (Exception ex)
            {
                Log.Error("UpdateNotificationByEmail() => {ex}", ex.Message);

                return StatusCode(StatusCodes.Status500InternalServerError, $"Error updating notification settings: {ex.Message}");
            }
        }

        /// <summary>
        /// DeActivate UserData By EmailId
        /// </summary>
        /// <param name="EmailID"></param>
        /// <returns></returns>
        [HttpPut(nameof(DeActivateUserDataByEmailId) + "/{EmailID}")]
        [Authorize]

        public async Task<IActionResult> DeActivateUserDataByEmailId(string EmailID)
        {
            try
            {

                var query = new QueryDefinition(
                "SELECT * " +
                "FROM c " +
                "WHERE c.Email = @email ")
                .WithParameter("@email", EmailID);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = new UserModel();
                if (results.Any())
                {
                    foreach (var item in results)
                    {
                        user = item;
                    }
                }

                user.IsActive = false;
                user.ModifiedOn = DateTime.Now.ToShortDateString();
                user.ModifiedBy = EmailID;

                ItemResponse<UserModel> response = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = response.Resource;
                Log.Information("DeActivateUserDataByEmailId() => User DeActivated");

                return Ok("User DeActivated!");
            }
            catch (Exception ex)
            {
                Log.Error("UpdateNotificationByEmail() => {ex}", ex.Message);

                return BadRequest("User DeActivated Failed! " + ex.Message);

            }
        }

        /// <summary>
        /// GetUsersDataByCompanyId
        /// </summary>
        /// <param name="companyid"></param>
        /// <returns></returns>
        [HttpGet(nameof(GetUsersDataByCompanyId) + "/{companyid}")]
        [Authorize]

        public async Task<ActionResult<UserModel>> GetUsersDataByCompanyId(Guid companyid)
        {
            try
            {
                var query = new QueryDefinition(
                "SELECT * " +
                "FROM c " +
                "WHERE c.CompanyId = @companyid ")
                .WithParameter("@companyid", companyid);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = new List<UserModel>();
                FeedResponse<UserModel> response;
                while (iterator.HasMoreResults)
                {
                    response = await iterator.ReadNextAsync();
                    results.AddRange(response);
                }

                var selectedUserData = results.Select(usr => new

                {
                    usr.id,
                    usr.ManagerId,
                    usr.UserName,
                    usr.Email,
                    usr.SecondaryEmail,
                    usr.Role,
                    usr.Image,
                    usr.IsActive,
                    usr.FirstLogin,
                    usr.CompanyId,
                    usr.ContactNumber,
                    usr.IsContactVerified,
                    usr.Country,
                    usr.City,
                    usr.Language,
                    usr.TimeZone,
                    usr.UserOrganization,
                    usr.Notification,
                    usr.CreatedBy,
                    usr.CreatedOn
                });
                Log.Information("GetUsersDataByCompanyId() ");

                return Ok(selectedUserData);
            }
            catch (Exception ex)
            {
                Log.Error("GetUsersDataByCompanyId() => {ex}", ex.Message);

                return BadRequest(ex.Message);
            }
        }

        /// <summary>
        /// ReActivate User Data By EmailId
        /// </summary>
        /// <param name="EmailID"></param>
        /// <returns></returns>
        [HttpPut(nameof(ReActivateUserDataByEmailId) + "/{EmailID}")]
        [Authorize]

        public async Task<IActionResult> ReActivateUserDataByEmailId(string EmailID)
        {
            try
            {
                var query = new QueryDefinition(
                "SELECT * " +
                "FROM c " +
                "WHERE c.Email = @email ")
                .WithParameter("@email", EmailID);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = new UserModel();
                if (results.Any())
                {
                    foreach (var item in results)
                    {
                        user = item;
                    }
                }
                if (user.IsActive == false)
                {
                    user.IsActive = true;
                    user.ModifiedOn = DateTime.Now.ToShortDateString();
                    user.ModifiedBy = EmailID;
                }

                ItemResponse<UserModel> response = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = response.Resource;

                Log.Information("ReActivateUserDataByEmailId() => User ReActivated!");

                return Ok("User ReActivated!");
            }
            catch (Exception ex)
            {
                Log.Error("ReActivateUserDataByEmailId() => {ex}", ex.Message);

                return BadRequest("User ReActivated Failed! " + ex.Message);

            }
        }

        /// <summary>
        /// Reset Password By EmailId
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(ResetPasswordByEmailId))]
        [Authorize]

        public async Task<IActionResult> ResetPasswordByEmailId([FromBody] ForgotPasswordDto data)
        {
            try
            {
                var query = new QueryDefinition(
                "SELECT * " +
                "FROM c " +
                "WHERE c.Email = @email ")
                .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = new UserModel();
                if (results.Any())
                {
                    foreach (var item in results)
                    {
                        user = item;
                    }
                    var key = "b14ca5898a4e4133bbce2ea2315a1916";
                    var tempPass = EncryptString(key, data.Password);
                    if (tempPass == user.Password)
                    {
                        return BadRequest("Similar Password Exist!");
                    }
                    user.Password = tempPass;
                    user.ModifiedOn = DateTime.Now.ToShortDateString();
                    user.ModifiedBy = data.Email;
                }
                else
                {
                    Log.Information("ResetPasswordByEmailId() => Email not found!");

                    return BadRequest("Email not found!");
                }
                ItemResponse<UserModel> response = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = response;

                Log.Information("ResetPasswordByEmailId() => Password updated!");
                return Ok("Password updated!");
            }
            catch (Exception ex)
            {
                Log.Information("ResetPasswordByEmailId() => {ex}", ex.Message);
                return BadRequest("Password not updated! " + ex.Message);
            }
        }
        [HttpPost(nameof(AuthUser))]
        public async Task<IActionResult> AuthUser([FromBody] ForgotPasswordDto data)
        {
            try
            {
                // Query to get user details by email
                var query = new QueryDefinition(
                    "SELECT * FROM c WHERE c.Email = @email")
                    .WithParameter("@email", data.Email);

                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = results.FirstOrDefault();

                if (user != null)
                {
                    var key = "b14ca5898a4e4133bbce2ea2315a1916";
                    var password = DecryptString(key, user.Password);

                    if (data.Password == password)
                    {
                        // Generate a Keycloak token using the provided Username and Password
                        var token = await GetKeycloakToken(data.UserName, data.Password);

                        if (token != null)
                        {
                            var userSession = new UserSessionReponse
                            {
                                id = user.id,
                                ManagerId = user.ManagerId,
                                UserName = user.UserName,
                                Designation = user.Designation,
                                Email = user.Email,
                                Role = user.Role,
                                FirstLogin = user.FirstLogin,
                                Image = user.Image,
                                CompanyId = user.CompanyId,
                                ContactNumber = user.ContactNumber,
                                ISDCode = user.ISDCode,
                                IsContactVerified = user.IsContactVerified,
                                IsEmailVerified = user.IsEmailVerified,
                                IsSecondaryEmailVerified = user.IsSecondaryEmailVerified,
                                Country = user.Country,
                                City = user.City,
                                SecondaryEmail = user.SecondaryEmail,
                                Language = user.Language,
                                TimeZone = user.TimeZone
                            };

                            // Fetch company details
                            var companyResponse = await _companyContainer.ReadItemAsync<Company>(user.CompanyId.ToString(), new PartitionKey(user.CompanyId.ToString()));
                            var company = companyResponse.Resource;
                            userSession.CompanyName = company.CompanyName;
                            userSession.CompanyShortName = company.CompanyShortName;
                            userSession.FiscalYearPeriod = company.FiscalYearPeriod;

                            Log.Information("AuthUser() - User authenticated and token retrieved");

                            // Set the token in response headers
                            HttpContext.Response.Headers.Add("Authorization", $"Bearer {token}");

                            // Return the user session in the response body
                            return Ok(new { userSession });
                        }
                        else
                        {
                            Log.Warning("AuthUser() - Failed to retrieve Keycloak token");
                            return BadRequest("Failed to retrieve Keycloak token");
                        }
                    }
                    else
                    {
                        Log.Warning("AuthUser() - Password not matched");
                        return BadRequest("Password not matched!");
                    }
                }
                else
                {
                    Log.Warning("AuthUser() - Email not found");
                    return BadRequest("Email not found!");
                }
            }
            catch (Exception ex)
            {
                Log.Error("AuthUser() - Error: {ex}", ex.Message);
                return BadRequest("An error occurred: " + ex.Message);
            }
        }

        private async Task<string> GetKeycloakToken(string username, string password)
        {
            var tokenUrl = "https://idp.shihaantech.net/realms/medium-dev/protocol/openid-connect/token";
            var clientId = "shihaantech";
            var clientSecret = "qpWnsOyEyzKQ8sbFER7KRi27zTyBLpmV";

            using (var httpClient = new HttpClient())
            {
                var content = new FormUrlEncodedContent(new[]
                {
            new KeyValuePair<string, string>("grant_type", "password"),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("username", username),
            new KeyValuePair<string, string>("password", password)
        });

                var response = await httpClient.PostAsync(tokenUrl, content);

                if (response.IsSuccessStatusCode)
                {
                    var jsonContent = await response.Content.ReadAsStringAsync();
                    var tokenResponse = JsonConvert.DeserializeObject<Dictionary<string, string>>(jsonContent);
                    return tokenResponse["access_token"];
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    Log.Error($"Failed to get Keycloak token: {response.StatusCode} - {response.ReasonPhrase}");
                    Log.Error($"Error details: {errorContent}");
                    return null;
                }
            }
        }





        /// <summary>
        /// Upload File
        /// </summary>
        /// <param name="file"></param>
        /// <param name="userid"></param>
        /// <returns></returns>
        [HttpPost(nameof(UploadUserImage))]
        [Authorize]

        public async Task<ActionResult> UploadUserImage(IFormFile file, Guid userid)
        {
            try
            {
                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(userid.ToString(), new PartitionKey(userid.ToString()));
                UserModel item = response.Resource;

                string extension = file.FileName.Substring(file.FileName.LastIndexOf(".") + 1);
                string systemFileName = userid.ToString() + "." + extension;
                string blobFilePath = string.Empty;

                var containerName = "registered-users";
                var containerClient = _blobServiceClient.GetBlobContainerClient(containerName);


                await containerClient.DeleteBlobIfExistsAsync(systemFileName);

                await using (var stream = new MemoryStream())
                {
                    await file.CopyToAsync(stream);
                    stream.Position = 0;
                    await containerClient.DeleteBlobIfExistsAsync(systemFileName);
                    await containerClient.UploadBlobAsync(systemFileName, stream);
                }
                blobFilePath = Path.Join(containerClient.Uri.AbsoluteUri, systemFileName);
                blobFilePath = blobFilePath.Replace("\\", "/");
                item.Image = blobFilePath;

                await _container.ReplaceItemAsync<UserModel>(item, item.id.ToString());
                item.Password = null;
                Log.Information("UploadUserImage()");
                return Ok(item);
            }
            catch (Exception ex)
            {
                Log.Error("AuthUser() => {ex}", ex.Message);
                return Ok(ex.Message + ": File upload failed");
            }
        }

        /// <summary>
        /// Reset Password By EmailId
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(ResetPasswordByEmailIdAndOldPwd))]
        [Authorize]

        public async Task<IActionResult> ResetPasswordByEmailIdAndOldPwd([FromBody] ForgotPasswordWithOldPwdDto data)
        {
            try
            {

                var query = new QueryDefinition(
                "SELECT * " +
                "FROM c " +
                "WHERE c.Email = @email ")
                .WithParameter("@email", data.Email);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = new UserModel();
                if (results.Any())
                {
                    foreach (var item in results)
                    {
                        user = item;
                    }
                    var key = "b14ca5898a4e4133bbce2ea2315a1916";
                    var oldPasswordDecrypt = DecryptString(key, user.Password);
                    if (data.OldPassword == oldPasswordDecrypt)
                    {
                        user.Password = EncryptString(key, data.NewPassword);
                        user.ModifiedOn = DateTime.Now.ToShortDateString();
                        user.ModifiedBy = data.Email;
                    }
                    else
                    {
                        Log.Information("ResetPasswordByEmailIdAndOldPwd() => Old password is incorrect!");
                        return BadRequest("Old password is incorrect!");
                    }
                }
                else
                {
                    Log.Information("ResetPasswordByEmailIdAndOldPwd() => Email not found!");
                    return BadRequest("Email not found!");
                }
                ItemResponse<UserModel> response = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = response;

                Log.Information("ResetPasswordByEmailIdAndOldPwd()");
                return Ok("Password updated!");
            }
            catch (Exception ex)
            {
                Log.Information("ResetPasswordByEmailIdAndOldPwd() => {ex} ", ex.Message);
                return BadRequest("Password not updated! " + ex.Message);
            }
        }


        /// <summary>
        /// Update Seccondary Email By Email
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(UpdateSecondaryEmail))]
        [Authorize]

        public async Task<IActionResult> UpdateSecondaryEmail([FromBody] UpdateSecondaryEmailDto data)
        {
            try
            {
                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(data.id.ToString(), new PartitionKey(data.id.ToString()));
                UserModel item = response.Resource;
                if (item != null)
                {
                    item.SecondaryEmail = data.SecondaryEmail;
                    item.ModifiedBy = data.id.ToString();
                    item.ModifiedOn = DateTime.UtcNow.ToShortDateString();
                    item = CopyDtoToUser(data, item);

                    await _container.ReplaceItemAsync<UserModel>(item, item.id.ToString());
                }
                else
                {
                    Log.Information("UpdateSecondaryEmail() => User Not Found");
                    return BadRequest("User Not Found");
                }

                Log.Information("UpdateSecondaryEmail()");
                return Ok("Secondary Email updated successfully!");
            }
            catch (Exception ex)
            {
                Log.Error("UpdateSecondaryEmail() => {ex}", ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error updating secondary Email: {ex.Message}");
            }
        }

        /// <summary>
        /// Update Is Email Verified By Email
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        [HttpPut(nameof(SecondaryEmailVerify))]
        [Authorize]

        public async Task<IActionResult> SecondaryEmailVerify([FromBody] UpdateSecondaryEmailVerifyDto data)
        {
            try
            {
                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(data.id.ToString(), new PartitionKey(data.id.ToString()));
                UserModel item = response.Resource;

                if (item == null)
                {
                    Log.Information("SecondaryEmailVerify() => User not found");
                    return BadRequest("User not found");
                }

                if (item.SecondaryEmail != null)
                {
                    item.IsEmailVerified = data.IsSecondaryEmailVerified;
                    item.ModifiedBy = data.id.ToString();
                    item.ModifiedOn = DateTime.UtcNow.ToShortDateString();
                    item = CopyDtoToUser(data, item);

                    await _container.ReplaceItemAsync<UserModel>(item, item.id.ToString());
                }
                else
                {
                    Log.Information("SecondaryEmailVerify() => Secondary Email not found!");
                    return BadRequest("Secondary Email not found!");
                }

                Log.Information("SecondaryEmailVerify()");
                return Ok("Secondary Email verified successfully!");
            }
            catch (Exception ex)
            {
                Log.Error("SecondaryEmailVerify() => {ex}", ex.Message);
                return StatusCode(StatusCodes.Status500InternalServerError, $"Error verified Secondary Email: {ex.Message}");
            }
        }


        /// <summary>
        /// Change User status Online Or Offline By UserId
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpPut(nameof(UserOnlineOrOfflineByUserId))]
        [Authorize]

        public async Task<IActionResult> UserOnlineOrOfflineByUserId(Guid id, bool? IsLogged)
        {
            try
            {
                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(id.ToString(), new PartitionKey(id.ToString()));
                UserModel user = response.Resource;
                if (user == null)
                {
                    Log.Information("UserOnlineOrOfflineByUserId() => User not found!");
                    return BadRequest("User not found!");
                }
                else if (user.IsActive == true)
                {
                    user.IsLogged = IsLogged;
                }
                else
                {
                    Log.Information("UserOnlineOrOfflineByUserId() => User is not active!");
                    return BadRequest("User is not active!");
                }

                ItemResponse<UserModel> UserResponse = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = UserResponse.Resource;

                Log.Information("UserOnlineOrOfflineByUserId()");

                return Ok("User Logged Status changed!");
            }
            catch (Exception ex)
            {
                Log.Error("UserOnlineOrOfflineByUserId() => {ex}", ex.Message);

                return BadRequest("User Logged Status change Failed! " + ex.Message);
            }
        }


        /// <summary>
        /// Change User status Online Or Offline By UserId
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpPut(nameof(IsVerifiedByEmailId))]
        [Authorize]

        public async Task<IActionResult> IsVerifiedByEmailId(string emailId)
        {
            try
            {
                var query = new QueryDefinition(
                "SELECT * " +
                "FROM c " +
                "WHERE c.Email = @email ")
                .WithParameter("@email", emailId);
                var iterator = _container.GetItemQueryIterator<UserModel>(query);
                var results = await iterator.ReadNextAsync();
                UserModel user = new UserModel();
                if (results.Any())
                {
                    foreach (var item in results)
                    {
                        user = item;
                    }
                }
                if (user == null)
                {
                    Log.Information("IsVerifiedByEmailId() => User not found!");
                    return BadRequest("User not found!");
                }
                else if (user.IsActive == true)
                {
                    user.IsEmailVerified = true;
                }
                else
                {
                    Log.Information("IsVerifiedByEmailId() => User is not active!");
                    return BadRequest("User is not active!");
                }

                ItemResponse<UserModel> UserResponse = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = UserResponse.Resource;

                Log.Information("IsVerifiedByEmailId()");

                return Ok("User IsVerified changed!");
            }
            catch (Exception ex)
            {
                Log.Error("IsVerifiedByEmailId() => {ex}", ex.Message);

                return BadRequest("User IsVerified change Failed! " + ex.Message);
            }
        }


        /// <summary>
        /// Setup User First Login By UserId
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        [HttpPut(nameof(SetupUserFirstLoginByUserId) + "/{id}")]
        [Authorize]

        public async Task<IActionResult> SetupUserFirstLoginByUserId(Guid id)
        {
            try
            {
                ItemResponse<UserModel> response = await _container.ReadItemAsync<UserModel>(id.ToString(), new PartitionKey(id.ToString()));
                UserModel user = response.Resource;

                if (user.IsActive == true)
                {
                    user.FirstLogin = false;
                    user.ModifiedOn = DateTime.Now.ToShortDateString();
                    user.ModifiedBy = user.Email;
                }

                ItemResponse<UserModel> responseResult = await _container.ReplaceItemAsync<UserModel>(user, user.id.ToString());

                UserModel updatedItem = responseResult.Resource;

                Log.Information("SetupUserFirstLoginByUserId()");

                return Ok("User FirstLogin setup done!");
            }
            catch (Exception ex)
            {
                Log.Error("SetupUserFirstLoginByUserId() => {ex}", ex.Message);

                return BadRequest("User FirstLogin setup Failed! " + ex.Message);

            }
        }

        private static string EncryptString(string key, string plainText)
        {
            byte[] iv = new byte[16];
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        private static string DecryptString(string key, string cipherText)
        {
            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        private static UserModel CopyDtoToUser<T>(T dto, UserModel user) where T : class
        {
            Type dtoType = typeof(T);
            Type userType = typeof(UserModel);

            PropertyInfo[] dtoProperties = dtoType.GetProperties();
            PropertyInfo[] userProperties = userType.GetProperties();

            foreach (PropertyInfo dtoProperty in dtoProperties)
            {
                PropertyInfo userProperty = Array.Find(userProperties, p => p.Name == dtoProperty.Name);
                if (userProperty != null && userProperty.CanWrite)
                {
                    object? value = dtoProperty.GetValue(dto);
                    if (value != null)
                    {
                        userProperty.SetValue(user, value);
                    }
                }
            }

            return user;
        }

        private static UsersUpdateDto CopyDtoToUser<T>(T dto, UsersUpdateDto user) where T : class
        {
            Type dtoType = typeof(T);
            Type userType = typeof(UsersUpdateDto);

            PropertyInfo[] dtoProperties = dtoType.GetProperties();
            PropertyInfo[] userProperties = userType.GetProperties();

            foreach (PropertyInfo dtoProperty in dtoProperties)
            {
                PropertyInfo userProperty = Array.Find(userProperties, p => p.Name == dtoProperty.Name);
                if (userProperty != null && userProperty.CanWrite)
                {
                    object? value = dtoProperty.GetValue(dto);
                    if (value != null)
                    {
                        userProperty.SetValue(user, value);
                    }
                }
            }

            return user;
        }
        private static Organization CopyDtoToOrg<T>(T dto, Organization org)
        {
            Type dtoType = typeof(T);
            Type orgType = typeof(Organization);

            PropertyInfo[] dtoProperties = dtoType.GetProperties();
            PropertyInfo[] orgProperties = orgType.GetProperties();

            foreach (PropertyInfo dtoProperty in dtoProperties)
            {
                PropertyInfo orgProperty = Array.Find(orgProperties, p => p.Name == dtoProperty.Name);
                if (orgProperty != null && orgProperty.CanWrite)
                {
                    object? value = dtoProperty.GetValue(dto);
                    if (value != null)
                    {
                        orgProperty.SetValue(org, value);
                    }
                }
            }

            return org;
        }

        private async Task<Guid> CreateCompany(SubscribedUserDTo data)
        {
            var query2 = new QueryDefinition(
              "SELECT * " +
              "FROM c " +
              "WHERE c.CompanyName = @CompanyName ")
              .WithParameter("@CompanyName", data.CompanyName);
            var iterator2 = _companyContainer.GetItemQueryIterator<Company>(query2);
            var results2 = await iterator2.ReadNextAsync();

            if (results2.Resource.Count() == 0)
            {
                Guid newCompanyGuid = Guid.NewGuid();
                Company newCompanyRec = new Company();
                newCompanyRec.id = newCompanyGuid;
                newCompanyRec.ParentCompanyId = newCompanyGuid;
                newCompanyRec.CompanyName = data.CompanyName;
                newCompanyRec.NoOfSubsidiaries = data.NoOfSubsidiaries;
                newCompanyRec.CompanyAddresss = data.CompanyAddress;
                newCompanyRec.Province = data.Province;
                newCompanyRec.Country = data.Country;
                newCompanyRec.PostalCode = data.PostalCode;
                newCompanyRec.Timezone = data.Timezone;
                newCompanyRec.CompanyShortName = data.CompanyShortName == null ? GetShortName(data.CompanyName) : data.CompanyShortName;
                newCompanyRec.CreatedBy = data.CreatedBy;
                newCompanyRec.CreatedOn = DateTime.Now.ToShortDateString();
                newCompanyRec.ModifiedOn = DateTime.Now.ToShortDateString();
                newCompanyRec.IsActive = true;
                ItemResponse<Company> CompanyResponse = await _companyContainer.CreateItemAsync<Company>(newCompanyRec);
                return newCompanyRec.id;
            }
            else
            {
                return results2.Resource.FirstOrDefault().id;
            }

        }

        private string? GetShortName(string? companyName)
        {
            string shortName = companyName.Trim();

            if (companyName.Contains(" "))
            {
                List<string> ShortNames = companyName.Trim().Split(" ").ToList<string>();

                shortName = string.Empty;
                foreach (string name in ShortNames)
                {
                    shortName += name.Substring(0, 1).ToUpper();
                }

            }
            return shortName;
        }
    }
}
