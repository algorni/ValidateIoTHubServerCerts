using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace ValidateIoTHubServerCerts
{
    class Program
    {
        private const string BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
        private const string END_CERTIFICATE = "-----END CERTIFICATE-----";


        static async Task Main(string[] args)
        {
            Console.WriteLine("Hello Certs!");

            if (args.Count() != 1)
            {
                Console.WriteLine("This tool requires 1 parameter:\n ValidateIoTHubServerCerts <iot hub name>");
                return;
            }

            string myIoTHubName = args.First();

            Console.WriteLine($"Reaching out to an endpoint of your IoT Hub: {myIoTHubName}");

            string iotHubFullUrl = $"https://{myIoTHubName}.azure-devices.net/statistics/service?api-version=2020-05-31-preview";


            // Create an HttpClientHandler object and set to use default credentials
            HttpClientHandler handler = new HttpClientHandler();

            // Set custom server validation callback
            handler.ServerCertificateCustomValidationCallback = ServerCertificateCustomValidation;

            // Create an HttpClient object
            HttpClient client = new HttpClient(handler);

            // Call asynchronous network methods in a try/catch block to handle exceptions
            try
            {
                HttpResponseMessage response = await client.GetAsync( iotHubFullUrl );

                //response.EnsureSuccessStatusCode();

                //string responseBody = await response.Content.ReadAsStringAsync();
                //Console.WriteLine($"Read {responseBody.Length} characters");
            }
            catch (HttpRequestException e)
            {
                Console.WriteLine("\nException Caught!");
                Console.WriteLine($"Message: {e.Message} ");
            }

            // Need to call dispose on the HttpClient and HttpClientHandler objects
            // when done using them, so the app doesn't leak resources
            handler.Dispose();
            client.Dispose();
        }



        private static bool ServerCertificateCustomValidation(HttpRequestMessage requestMessage, X509Certificate2 certificate, 
            X509Chain chain, SslPolicyErrors sslErrors)
        {
            // It is possible inpect the certificate provided by server
            Console.WriteLine($"\nRequested URI: {requestMessage.RequestUri}\n");
            Console.WriteLine($"Subject: {certificate.Subject}");
            Console.WriteLine($"Effective date: {certificate.GetEffectiveDateString()}");
            Console.WriteLine($"Exp date: {certificate.GetExpirationDateString()}");
            Console.WriteLine($"Issuer: {certificate.Issuer}");
           

            var intermediateCert = chain.ChainElements[1].Certificate;

            Console.WriteLine($"\nIntermediate Cert");
            Console.WriteLine($"Subject: {intermediateCert.Subject}");
            Console.WriteLine($"Effective date: {intermediateCert.GetEffectiveDateString()}");
            Console.WriteLine($"Exp date: {intermediateCert.GetExpirationDateString()}");
            Console.WriteLine($"Issuer: {intermediateCert.Issuer}");
            

            //calculate the CN of the intermediate
            var subjectSplited = intermediateCert.Subject.Split(",");

            string intermediateName = subjectSplited[0].Replace("CN=",string.Empty);


            var certFilePath = $"./data/{intermediateName}.cer";

            //check if we have a copy of the cert here to check against
            if (!File.Exists(certFilePath))
            {
                Console.WriteLine("\nIntermediate cert not found locally!");
                //the intermediate cert is not trusted
                return false;
            }
            else 
            {
                Console.WriteLine("\nIntermediate cert found locally! Loading and comparing thumbprints.");
            }

            //load the trusted intermediate locally
            var trustedIntermediateCertPem = File.ReadAllText(certFilePath);

            var trustedIntermediateCertPemBase64 = trustedIntermediateCertPem.Replace(BEGIN_CERTIFICATE, string.Empty).Replace(END_CERTIFICATE, string.Empty);

            var trustedIntermediateCert = new X509Certificate2(Convert.FromBase64String(trustedIntermediateCertPemBase64));

            //just check if the thumbrint is equivalent

            //Based on the custom logic it is possible to decide whether the client considers certificate valid or not
            Console.WriteLine($"Errors: {sslErrors}");

            if ((intermediateCert.Thumbprint == trustedIntermediateCert.Thumbprint) && (sslErrors == SslPolicyErrors.None))
            {
                //ok intermediated is validated (it's one of the Microsoft owned and trusted)

                Console.WriteLine("\nAll fine! The intermediate certs is one of the trusted and thumbprints matches!");

                return true;
            }
            else
            {
                Console.WriteLine("There was an issue in the intermediate cert!");

                return false;
            }
        }



    }
}
