using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OpenIdDict.IdentityProvider.Data;
using OpenIdDict.IdentityProvider.Models;
using System.Text;

namespace OpenIddict.IdentityProvider.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class Fido2Controller : ControllerBase
{
    private readonly IFido2 _fido2;
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<Fido2Controller> _logger;

    public Fido2Controller(
        IFido2 fido2,
        ApplicationDbContext context,
        UserManager<ApplicationUser> userManager,
        ILogger<Fido2Controller> logger)
    {
        _fido2 = fido2;
        _context = context;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpPost("makeCredentialOptions")]
    public async Task<IActionResult> MakeCredentialOptions([FromForm] string username, [FromForm] string displayName, [FromForm] string attType, [FromForm] string authType, [FromForm] bool requireResidentKey, [FromForm] string userVerification)
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            // Get existing credentials for this user
            var existingKeys = await _context.FidoStoredCredentials
                .Where(c => c.UserId == user.Id)
                .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
                .ToListAsync();

            var authenticatorSelection = new AuthenticatorSelection
            {
                RequireResidentKey = requireResidentKey,
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            var exts = new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                UserVerificationMethod = true,
            };

            var userHandle = Encoding.UTF8.GetBytes(user.Id);

            var fido2User = new Fido2User
            {
                DisplayName = displayName ?? user.UserName,
                Name = user.UserName,
                Id = userHandle
            };

            var options = _fido2.RequestNewCredential(fido2User, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);

            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            return Ok(options);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error creating credential options");
            return BadRequest(new { error = e.Message });
        }
    }

    [HttpPost("makeCredential")]
    public async Task<IActionResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            var credentialMakeResult = await _fido2.MakeNewCredentialAsync(attestationResponse, options, async (args, cancellationToken) =>
            {
                var credentialIdString = Base64Url.Encode(args.CredentialId);
                var existingCred = await _context.FidoStoredCredentials
                    .AnyAsync(c => c.UserId == user.Id && c.CredentialId == args.CredentialId, cancellationToken);
                
                return !existingCred;
            });

            if (credentialMakeResult.Result != null)
            {
                var credential = new FidoStoredCredential
                {
                    UserId = user.Id,
                    UserHandle = options.User.Id,
                    PublicKey = credentialMakeResult.Result.PublicKey,
                    CredentialId = credentialMakeResult.Result.CredentialId,
                    SignatureCounter = credentialMakeResult.Result.Counter,
                    CredType = credentialMakeResult.Result.CredType,
                    RegistrationDate = DateTime.UtcNow,
                    AaGuid = credentialMakeResult.Result.Aaguid.ToString(),
                    Description = attestationResponse.Response.AttestationObject != null ? "Security Key" : "Platform Authenticator"
                };

                _context.FidoStoredCredentials.Add(credential);
                await _context.SaveChangesAsync();

                // Enable FIDO2 for the user
                user.Fido2Enabled = true;
                await _userManager.UpdateAsync(user);

                return Ok(new
                {
                    status = "ok",
                    errorMessage = "",
                    result = credentialMakeResult
                });
            }

            return BadRequest(new { status = "error", errorMessage = credentialMakeResult.ErrorMessage });
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error creating credential");
            return BadRequest(new { status = "error", errorMessage = e.Message });
        }
    }

    [HttpPost("assertionOptions")]
    [AllowAnonymous]
    public async Task<IActionResult> AssertionOptions([FromForm] string username, [FromForm] string userVerification)
    {
        try
        {
            ApplicationUser user = null;
            List<PublicKeyCredentialDescriptor> existingCredentials = new List<PublicKeyCredentialDescriptor>();

            if (!string.IsNullOrEmpty(username))
            {
                user = await _userManager.FindByNameAsync(username);
                if (user != null)
                {
                    existingCredentials = await _context.FidoStoredCredentials
                        .Where(c => c.UserId == user.Id)
                        .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId))
                        .ToListAsync();
                }
            }

            var exts = new AuthenticationExtensionsClientInputs
            {
                UserVerificationMethod = true
            };

            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            var options = _fido2.GetAssertionOptions(
                existingCredentials,
                uv,
                exts
            );

            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            return Ok(options);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error creating assertion options");
            return BadRequest(new { error = e.Message });
        }
    }

    [HttpPost("makeAssertion")]
    [AllowAnonymous]
    public async Task<IActionResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse assertionResponse)
    {
        try
        {
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
            var options = Fido2NetLib.AssertionOptions.FromJson(jsonOptions);

            var credential = await _context.FidoStoredCredentials
                .FirstOrDefaultAsync(c => c.CredentialId == assertionResponse.Id);

            if (credential == null)
            {
                return BadRequest(new { status = "error", errorMessage = "Unknown credentials" });
            }

            var user = await _userManager.FindByIdAsync(credential.UserId);
            if (user == null)
            {
                return BadRequest(new { status = "error", errorMessage = "Unknown user" });
            }

            var assertionVerificationResult = await _fido2.MakeAssertionAsync(
                assertionResponse,
                options,
                credential.PublicKey,
                credential.SignatureCounter,
                async (args, cancellationToken) =>
                {
                    var cred = await _context.FidoStoredCredentials
                        .FirstOrDefaultAsync(c => c.UserHandle.SequenceEqual(args.UserHandle), cancellationToken);
                    return cred?.UserId == user.Id;
                });

            if (assertionVerificationResult.Status == "ok")
            {
                // Update signature counter
                credential.SignatureCounter = assertionVerificationResult.Counter;
                await _context.SaveChangesAsync();

                // Sign in the user
                await _userManager.UpdateSecurityStampAsync(user);
                
                return Ok(new
                {
                    status = "ok",
                    errorMessage = "",
                    userId = user.Id,
                    userName = user.UserName
                });
            }

            return BadRequest(new { status = "error", errorMessage = assertionVerificationResult.ErrorMessage });
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Error making assertion");
            return BadRequest(new { status = "error", errorMessage = e.Message });
        }
    }

    [HttpGet("credentials")]
    public async Task<IActionResult> GetCredentials()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return BadRequest("User not found");
        }

        var credentials = await _context.FidoStoredCredentials
            .Where(c => c.UserId == user.Id)
            .Select(c => new
            {
                c.Id,
                c.Description,
                c.RegistrationDate,
                c.AaGuid
            })
            .ToListAsync();

        return Ok(credentials);
    }

    [HttpDelete("credentials/{id}")]
    public async Task<IActionResult> DeleteCredential(int id)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return BadRequest("User not found");
        }

        var credential = await _context.FidoStoredCredentials
            .FirstOrDefaultAsync(c => c.Id == id && c.UserId == user.Id);

        if (credential == null)
        {
            return NotFound();
        }

        _context.FidoStoredCredentials.Remove(credential);
        await _context.SaveChangesAsync();

        // Check if user has any remaining credentials
        var hasCredentials = await _context.FidoStoredCredentials
            .AnyAsync(c => c.UserId == user.Id);

        if (!hasCredentials)
        {
            user.Fido2Enabled = false;
            await _userManager.UpdateAsync(user);
        }

        return Ok();
    }
}