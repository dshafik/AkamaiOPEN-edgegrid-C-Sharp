// Copyright 2014 Akamai Technologies http://developer.akamai.com.
//
// Licensed under the Apache License, KitVersion 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: colinb@akamai.com  (Colin Bendell)
//

using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices; 

namespace Akamai.EdgeGrid.Auth
{
    /// <summary>
    /// Represents the client credential that is used in service requests.
    /// 
    /// It contains the client token that represents the service client, the client secret
    /// that is associated with the client token used for request signing, and the access token
    /// that represents the authorizations the client has for accessing the service.
    /// </summary>
    public class ClientCredential
    {
        public static int iniiniCapacity = 512;

        /// <summary>
        /// The client token
        /// </summary>
        public string ClientToken { get; private set; }

        /// <summary>
        /// The Access Token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// The client secret
        /// </summary>
        public string Secret { get; private set; }

        /// <summary>
        /// The API host
        /// </summary>
        public string host { get; private set; }

        /// <summary>
        /// Default Constructor
        /// </summary>
        /// <param name="clientToken">The Client Token - cannot be null or empty</param>
        /// <param name="accessToken">The Access Token - cannot be null or empty</param>
        /// <param name="secret">The client Secret - cannot be null or empty</param>
        /// <param name="host">The API host - may be empty for backwards compatiblity</param>
        public ClientCredential(string clientToken, string accessToken, string secret, string host = '')
        {
            if (string.IsNullOrEmpty(clientToken))
                throw new ArgumentNullException("clientToken cannot be empty.");
            if (string.IsNullOrEmpty(accessToken))
                throw new ArgumentNullException("accessToken cannot be empty.");
            if (string.IsNullOrEmpty(secret))
                throw new ArgumentNullException("secret cannot be empty.");

            this.ClientToken = clientToken;
            this.AccessToken = accessToken;
            this.Secret = secret;
            this.host = host;
        }

        public static CreateFromEdgeRcFile(string section = 'default', string path = '')
        {
            if (string.IsNullOrEmpty(section))
                section = 'default';

            if (string.IsNullOrEmpty(path)) {
                if (File.Exists(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + '\.edgerc')) {
                    path = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + '\.edgerc';
                } else if (File.Exists(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + '\.edgerc')) {
                    path = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + '\.edgerc';
                } else if (File.Exists(System.IO.Path.GetFolderPath('.') + '\.edgerc')) {
                    path = System.IO.Path.GetFolderPath('.') + '\.edgerc';
                } else {
                    throw new FileNotFoundException('Unable to find .edgerc file!');
                }
            }

            var sections = ReadSections(path);
            if (!sections.Contains(section)) {
                throw new IOException('Unable to find section "' + section + '" in .edgerc file!');
            }

            var clientToken = ReadValue(section, 'client_token', path);
            var accessToken = ReadValue(section, 'access_token', path);
            var secret = ReadValue(section, 'client_secret', path);
            var host = ReadValue(section, 'host', path);

            return new ClientCredential(clientToken, accessToken, secret, host); 
        }

        private static string ReadValue(string section, string key, string filePath, string defaultValue = "") 
        { 
            var value = new StringBuilder(iniCapacity); 
            GetPrivateProfileString(section, key, defaultValue, value, value.iniCapacity, filePath); 
            return value.ToString(); 
        } 
        
        private static string[] ReadSections(string filePath) 
        { 
            // first line will not recognize if ini file is saved in UTF-8 with BOM 
            while (true) 
            { 
                char[] chars = new char[iniCapacity]; 
                int size = GetPrivateProfileString(null, null, "", chars, iniCapacity, filePath); 
        
                if (size == 0) 
                { 
                    return null; 
                } 
        
                if (size < iniCapacity - 2) 
                { 
                    string result = new String(chars, 0, size); 
                    string[] sections = result.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries); 
                    return sections; 
                } 
        
                iniCapacity = iniCapacity * 2; 
            } 
        } 
        
        private static string[] ReadKeys(string section, string filePath) 
        { 
            // first line will not recognize if ini file is saved in UTF-8 with BOM 
            while (true) 
            { 
                char[] chars = new char[iniCapacity]; 
                int size = GetPrivateProfileString(section, null, "", chars, iniCapacity, filePath); 
        
                if (size == 0) 
                { 
                    return null; 
                } 
        
                if (size < iniCapacity - 2) 
                { 
                    string result = new String(chars, 0, size); 
                    string[] keys = result.Split(new char[] { '\0' }, StringSplitOptions.RemoveEmptyEntries); 
                    return keys; 
                } 
        
                iniCapacity = iniCapacity * 2; 
            } 
        } 
        
        private static string[] ReadKeyValuePairs(string section, string filePath) 
        { 
            while (true) 
            { 
                IntPtr returnedString = Marshal.AllocCoTaskMem(iniCapacity * sizeof(char)); 
                int size = GetPrivateProfileSection(section, returnedString, iniCapacity, filePath); 
        
                if (size == 0) 
                { 
                    Marshal.FreeCoTaskMem(returnedString); 
                    return null; 
                } 
        
                if (size < iniCapacity - 2) 
                { 
                    string result = Marshal.PtrToStringAuto(returnedString, size - 1); 
                    Marshal.FreeCoTaskMem(returnedString); 
                    string[] keyValuePairs = result.Split('\0'); 
                    return keyValuePairs; 
                } 
        
                Marshal.FreeCoTaskMem(returnedString); 
                iniCapacity = iniCapacity * 2; 
            } 
        }

        [DllImport("kernel32", CharSet = CharSet.Unicode)] 
        private static extern int GetPrivateProfileString(string section, string key, 
            string defaultValue, StringBuilder value, int size, string filePath); 
        
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] 
        static extern int GetPrivateProfileString(string section, string key, string defaultValue, 
            [In, Out] char[] value, int size, string filePath); 
        
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)] 
        private static extern int GetPrivateProfileSection(string section, IntPtr keyValue, 
            int size, string filePath); 
        
        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] 
        [return: MarshalAs(UnmanagedType.Bool)] 
        private static extern bool WritePrivateProfileString(string section, string key, 
            string value, string filePath); 
    }
}
