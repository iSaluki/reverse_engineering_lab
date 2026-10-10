// Deliberately vulnerable fixture for tests/smoke.sh (vuln-scan semgrep rules). Not real code.
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

public class Updater {
    private static readonly string EncryptionKey = "s3cr3t-k3y-2024!";   // dotnet-hardcoded-key-material-field
    private const string RegistryKey = "Software\\Acme";                // must NOT match
    public object Load(Stream s) {
        var f = new BinaryFormatter();
        return f.Deserialize(s);                                   // dotnet-insecure-deserializer
    }
    public void Run(string arg) {
        ServicePointManager.ServerCertificateValidationCallback = (a, b, c, d) => true; // cert validation off
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }; // typenamehandling
        Process.Start("updater.exe", "--pkg " + arg);              // dotnet-process-start
        Process.Start("notepad.exe");                              // constant: must NOT match
        Assembly.LoadFrom(arg);                                    // dotnet-assembly-load-bytes
        var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef");      // dotnet-hardcoded-key
        aes.Mode = CipherMode.ECB;                                 // dotnet-weak-crypto
        var js = new JavaScriptSerializer(new SimpleTypeResolver()); // dotnet-javascriptserializer-typeresolver
        var cmd = new SqlCommand("SELECT * FROM t WHERE n='" + arg + "'", conn); // dotnet-sql-concat
        var cmd2 = new SqlCommand("SELECT 1", conn);                // constant: must NOT match
        var rs = new XmlReaderSettings();
        rs.DtdProcessing = DtdProcessing.Parse;                    // dotnet-xxe
        var xs = new XsltSettings(true, true);                     // dotnet-xslt-script
    }
}
