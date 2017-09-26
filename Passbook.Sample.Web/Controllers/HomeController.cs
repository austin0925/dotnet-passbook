using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace Passbook.Sample.Web.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
      
        public string token() {

            Task<string> tokenTask = GetPhoneIdAsync("0975660363");

            return tokenTask.GetAwaiter().GetResult();
        }

        public string police() {

            string msg = "iPolice訊息推播測試(1)";
            msg = "106年度建置「智慧影像分析人臉辨識系統」相關軟、硬體設備案(6)";
            int count = 1;

            //ipolice-謝股長
            sendMsgPolice(msg, count, "72c663393e5c31e5d9c932577688d7207a868648241ec83a1c440d4eb333e548");

            //ipolice-test2
            sendMsgPolice(msg, count, "22ff5353ec239f2615f3a45859ef416c3610421b247970a1589d45902d983b1e");

            //ipolice-test3
            sendMsgPolice(msg, count, "1c8aaca9411e7ed048f1ef38562d800decb541b4c33fad52fb4aeb21d19549bb");

            //ipolice-hubert
            sendMsgPolice(msg, count, "9730b76c009c40ec77bbfc7d03b77e4ed33029e82ae2fc101b8be18e2b983498");

            //ipolice-austin
            sendMsgPolice(msg, count, "9712ef6ba7195542295b15c239e28ba1817bf9c70bb7e65003edd454d7ec4016");

            return count +">>>推播["+msg+ "]到iPolice: hubert, austin, test2";
        }

        /// <summary>
        /// 測試用的方法，如果再取得采威的deviceToken之前可以使用。
        /// 此方法所使用的憑證和passphase都是EMIC專案用的「災情報報APP」
        /// </summary>
        public string disaster()
        {
            ///災情報報
            sendMsgDisaster("災情報報防災推播訊息測試", 1,"76063b35708f2aed0576235c739faba3f9555825548b5c7e091614e03659f059");

            return "推播訊息給hubert[災情報報防災推播訊息測試]";
        }


        /// <summary>
        /// 使用消防署專案的推播憑證進行推播
        /// APPLE PUSHNOTATION SERVICE for token on 2014.07.01
        /// </summary>
        /// <param name="msgContent">訊息內容</param>
        /// <param name="msgCount">訊息累積數量</param>
        /// <param name="devicetocken">手機的代碼</param>
        protected void sendMsgDisaster(String msgContent, int msgCount, string devicetocken) {
            sendMsg(msgContent, msgCount, devicetocken, "/CertfileKeyFile/tw.gov.nfa.InformDisaster.pns.p12", "/CertfileKeyFile/disaster.txt");
        }

        protected void sendMsgPolice(String msgContent, int msgCount, string devicetocken)
        {
            sendMsg(msgContent, msgCount, devicetocken, "/CertfileKeyFile/aps_formal_identity.p12", "/CertfileKeyFile/police.txt");
        }

        protected void sendMsgPoliceDev(String msgContent, int msgCount, string devicetocken)
        {
            sendMsg(msgContent, msgCount, devicetocken, "/CertfileKeyFile/aps_developer_identity_iscom.p12", "/CertfileKeyFile/policeDev.txt");
        }

        /// <summary>
        /// 呼叫蘋果的推播方法
        /// reference from comezon/dotnet-passbook
        /// </summary>
        /// <param name="devicetocken">裝置的Token, deviceToken</param>
        /// <param name="certPath">憑證的路徑</param>
        /// <param name="pwdPath">憑證的PASSPHASE路徑</param>
        protected void sendMsg(String msgContent, int msgCount, string devicetocken, string certPath, string pwdPath)
        {
            //string devicetocken = "76063b35708f2aed0576235c739faba3f9555825548b5c7e091614e03659f059";
            //"7a7c4d3a0342b213718ccece131a51906f748a87eb8ccae6b35f757814bb96d7";//  iphone device token

            int port = 2195;
            //String hostname = "gateway.sandbox.push.apple.com";
            String hostname = "gateway.push.apple.com";

            string certificatePath = Server.MapPath(certPath);//"/tw.gov.nfa.InformDisaster.pns.p12");

            string certificatePassword = "123";

            certificatePassword = System.IO.File.ReadAllText(Server.MapPath(pwdPath));

            X509Certificate2 clientCertificate = new X509Certificate2(certificatePath, certificatePassword, X509KeyStorageFlags.MachineKeySet);
            X509Certificate2Collection certificatesCollection = new X509Certificate2Collection(clientCertificate);

            TcpClient client = new TcpClient(hostname, port);
            SslStream sslStream = new SslStream(
                            client.GetStream(),
                            false,
                            new RemoteCertificateValidationCallback(ValidateServerCertificate),
                            null
            );

            try
            {
                sslStream.AuthenticateAsClient(hostname, certificatesCollection, SslProtocols.Default, false);
            }
            catch (AuthenticationException ex)
            {
                Console.WriteLine("Authentication failed");
                client.Close();
                Request.SaveAs(Server.MapPath("/Authenticationfailed.txt"), true);
                return;
            }


            //// Encode a test message into a byte array.
            MemoryStream memoryStream = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(memoryStream);

            writer.Write((byte)0);  //The command
            writer.Write((byte)0);  //The first byte of the deviceId length (big-endian first byte)
            writer.Write((byte)32); //The deviceId length (big-endian second byte)

            byte[] b0 = HexString2Bytes(devicetocken);
            WriteMultiLineByteArray(b0);

            writer.Write(b0);
            String payload;
            string strmsgbody = "";
            int totunreadmsg = msgCount;//20;
            strmsgbody = msgContent;// "防";
            //strmsgbody = "EMIC CALL!!";
            //strmsgbody = "Hey Aashish!";

            Debug.WriteLine("during testing via device!");
            Request.SaveAs(Server.MapPath("/APNSduringdevice.txt"), true);

            payload = "{\"aps\":{\"alert\":\"" + strmsgbody + "\",\"badge\":" + totunreadmsg.ToString() + ",\"sound\":\"mailsent.wav\"},\"acme1\":\"bar\",\"acme2\":42}";

            writer.Write((byte)0); //First byte of payload length; (big-endian first byte)
            //writer.Write((byte)payload.Length+10);     //payload length (big-endian second byte)
            writer.Write((byte)Encoding.GetEncoding("utf-8").GetBytes(payload).Length);     //Non-English word should count by String

            byte[] b1 = System.Text.Encoding.UTF8.GetBytes(payload);
            //byte[] b1 = System.Text.UnicodeEncoding.Unicode.GetBytes(payload);
            writer.Write(b1);
            writer.Flush();

            byte[] array = memoryStream.ToArray();
            Debug.WriteLine("This is being sent...\n\n");
            Debug.WriteLine(array);
            try
            {
                sslStream.Write(array);
                sslStream.Flush();

            }
            catch
            {
                Debug.WriteLine("Write failed buddy!!");
                Request.SaveAs(Server.MapPath("/Writefailed.txt"), true);
            }

            client.Close();
            Debug.WriteLine("Client closed.");
            Request.SaveAs(Server.MapPath("/APNSSuccess.txt"), true);
        }
        /// <summary>
        /// 提供給上傳PNS的sendMsg方法使用
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        private byte[] HexString2Bytes(string hexString)
        {
            //check for null
            if (hexString == null) return null;
            //get length
            int len = hexString.Length;
            if (len % 2 == 1) return null;
            int len_half = len / 2;
            //create a byte array
            byte[] bs = new byte[len_half];
            try
            {
                //convert the hexstring to bytes
                for (int i = 0; i != len_half; i++)
                {
                    bs[i] = (byte)Int32.Parse(hexString.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber);
                }
            }
            catch (Exception ex)
            {
                //MessageBox.Show("Exception : " + ex.Message);
            }
            //return the byte array
            return bs;
        }

        /// <summary>
        /// The following method is invoked by the RemoteCertificateValidationDelegate.
        /// 提供給sendMsg()方法所使用
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="certificate"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns></returns>
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
        /// <summary>
        /// 提供給sendMsg方法所使用，可以快速列印出byte的內容(DEBUG用)
        /// </summary>
        /// <param name="bytes"></param>
        public static void WriteMultiLineByteArray(byte[] bytes)
        {
            const int rowSize = 20;
            int iter;

            Console.WriteLine("initial byte array");
            Console.WriteLine("------------------");

            for (iter = 0; iter < bytes.Length - rowSize; iter += rowSize)
            {
                Console.Write(
                    BitConverter.ToString(bytes, iter, rowSize));
                Console.WriteLine("-");
            }

            Console.WriteLine(BitConverter.ToString(bytes, iter));
            Console.WriteLine();
        }

        private static async Task<string> GetPhoneIdAsync(String phoneNumber) {

            var client = new HttpClient();
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Accept.Add(
                new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/vnd.gihub.v3+json"));
            //client.DefaultRequestHeaders.Accept.Add(
            //    new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json; charset=utf-8"));
            client.DefaultRequestHeaders.Add("User-Agent", ".NET Foundation Repository Reporter");

            String urlString = "https://https://app2.ntpd.gov.tw/Develop/GetAppUser?PhoneNo=" + phoneNumber;

            Console.WriteLine(urlString);

            var stringTask = client.GetStringAsync(urlString);
            var msg = await stringTask;
            Console.WriteLine(msg);

            return msg;
        }
    }

    public class AppUser
    {
        public string PUserNo { set; get; }
        public string PhoneNo { set; get; }
        public string OSType { set; get; }
        public string UserKey { set; get; }
        public string PhoneId { set; get; }
        public string CreateDT { set; get; }
        public string LastDT { get; set; }
        public string VerifyCode { get; set; }
        public string isVerify { get; set; }
    }
}