using System.ComponentModel.DataAnnotations;

namespace OpenIdDict.IdentityProvider.Models;

public class FidoStoredCredential
{
    [Key]
    public int Id { get; set; }
    
    [Required]
    public string UserId { get; set; } = string.Empty;
    
    [Required]
    public byte[] UserHandle { get; set; } = Array.Empty<byte>();
    
    [Required]
    public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    
    [Required]
    public byte[] CredentialId { get; set; } = Array.Empty<byte>();
    
    public uint SignatureCounter { get; set; }
    
    public string CredType { get; set; } = string.Empty;
    
    public DateTime RegistrationDate { get; set; }
    
    public string? AaGuid { get; set; }
    
    public string? Description { get; set; }
}