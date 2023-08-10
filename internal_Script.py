# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2019, Gluu
#
# Author: Jose Gonzalez
# Author: Yuriy Movchan
#

# code optimization by keeping the reusable codes in the methods - V1
# multiple MFA possibilities implementation complete - V2 
# Integrating UAEPass with Internal Script complete - V3
# Added Email OTP HTML Template - V4
# Adding HTML file instead of hardcoded HTML Content in message - V5


from org.gluu.jsf2.service import FacesService
from org.gluu.jsf2.message import FacesMessages

from org.gluu.oxauth.model.common import User, WebKeyStorage
from org.gluu.oxauth.model.configuration import AppConfiguration
from org.gluu.oxauth.model.crypto import CryptoProviderFactory
from org.gluu.oxauth.model.jwt import Jwt, JwtClaimName
from org.gluu.oxauth.model.util import Base64Util
from org.gluu.oxauth.service import AppInitializer, AuthenticationService, UserService
from org.gluu.oxauth.service.net import HttpService
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.config.oxtrust import LdapOxPassportConfiguration
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.persist import PersistenceEntryManager
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from java.util import ArrayList, Arrays, Collections, Properties
from org.gluu.model.ldap import GluuLdapConfiguration
from org.gluu.oxauth.service import SessionIdService
from org.gluu.oxauth.service.common import UserService, EncryptionService

from CRYPTOCard.API import CRYPTOCardAPI
from java.lang.reflect import Array
from java.lang import String, Integer
from java.lang import UnsatisfiedLinkError

from javax.faces.application import FacesMessage
from javax.faces.context import FacesContext

from javax.naming import Context
from java.util import Hashtable
from javax.naming.directory import InitialDirContext, SearchControls

from org.apache.http.util import EntityUtils
from org.apache.http.entity import ContentType, StringEntity

from org.apache.http.impl.client import  HttpClients
from org.apache.http.client.methods import  HttpPost

from java.util import Properties
from javax.mail import Session
from javax.mail.internet import MimeMessage
from javax.mail.internet import InternetAddress
from java.io import File

from javax.mail import Message, internet

import os
import json
import sys
import random
import re
import datetime
import java
import hashlib


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
        self.identity = CdiUtil.bean(Identity)
        self.challenge = None

        self.user_fullName = None

        #For Gemalto MFA
        self.user_name = None

        #For Email MFA
        self.user_email = None
        #For SMS MFA
        self.user_mobile = None
        
        # SMTP Connection Strings
        self.SMTP_HOSTNAME = None
        self.SMTP_PORT=None
        
        #SMS Connection Strings
        self.API_KEY = None
        self.TRANSACTION_ID = None
        self.SMS_API_URL = None

    def init(self, configurationAttributes):
        print ("Passport. init called")

        self.extensionModule = self.loadExternalModule(configurationAttributes.get("extension_module"))
        extensionResult = self.extensionInit(configurationAttributes)
        if extensionResult != None:
            return extensionResult

        print ("Passport. init. Behaviour is social")
        success = self.processKeyStoreProperties(configurationAttributes)

        if success:
            self.providerKey = "provider"
            self.customAuthzParameter = self.getCustomAuthzParameter(configurationAttributes.get("authz_req_param_provider"))
            self.passportDN = self.getPassportConfigDN()
            print ("Passport. init. Initialization success")
        else:
            print ("Passport. init. Initialization failed")
        #return success

        #----------
        self.url= None
        self.ctx= None
        self.srch = None
        self.results = None
        self.loginChannel = None
        self.userType = None
        self.ui_locales = None
        self.ldapExtendedEntryManagers = None
        self.automation_key = None
        self.noc_automation_key = None
        self.login_page = None


        #-------------------------
        authConfigurationFile = configurationAttributes.get("auth_configuration_file").getValue2()
        authConfiguration = self.loadAuthConfiguration(authConfigurationFile)
        if (authConfiguration == None):
            print ("Passport. File with authentication configuration should be not empty")
            return False
        
        self.noc_automation_key = configurationAttributes.get("noc_automation_key").getValue2()


        validationResult = self.validateAuthConfiguration(authConfiguration)
        if (not validationResult):
            return False

        # ldapExtendedEntryManagers = self.createLdapExtendedEntryManagers(authConfiguration)
        # if (ldapExtendedEntryManagers == None):
        #     return False
        
        self.ldapExtendedEntryManagers = authConfiguration["ldap_configuration"]

        print ("Passport. Initialized successfully")

        # Get Custom Properties

        try:
                self.SMTP_HOSTNAME = configurationAttributes.get("smtp_hostname").getValue2()
        except:
                print('Email OTP, Missing required configuration attribute "smtp_hostname"')

        try:
            self.SMTP_PORT = configurationAttributes.get("smtp_port").getValue2()
        except:
            print('Email OTP, Missing required configuration attribute "smtp_port"')

        if None in (self.SMTP_HOSTNAME,self.SMTP_PORT):
            print ("smtp_hostname, smtp_port is empty ... returning False")
            return False

        print ("===EMAIL INITIALIZATION DONE PROPERLY=====")

        try:
            self.API_KEY = configurationAttributes.get("api_key").getValue2()
        except:
            print ('SMSOTP, Missing required configuration attribute "api_key"')

        try:
            self.TRANSACTION_ID = configurationAttributes.get("transaction_id").getValue2()
        except:
            print('SMSOTP, Missing required configuration attribute "transaction_id"')

        try:
            self.SMS_API_URL = configurationAttributes.get("sms_api_url").getValue2()
        except:
            print('SMSOTP, Missing required configuration attribute "sms_api_url"')

        if None in (self.API_KEY, self.TRANSACTION_ID, self.SMS_API_URL):
            print ("api_key, transaction_id, sms_api_url is empty ... returning False")
            return False


        print ("===SMS OTP INITIALIZATION DONE PROPERLY=====") 

        return True


    def destroy(self, configurationAttributes):
        print ("Passport. destroy called")
        print ("Passport. Destroyed successfully")
        return True


    def getApiVersion(self):
        return 2


    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True


    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None


    def authenticate(self, configurationAttributes, requestParameters, step):

        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        sessionIdService = CdiUtil.bean(SessionIdService)
        sessionId = sessionIdService.getSessionId()

        session_attributes = self.identity.getSessionId().getSessionAttributes()

        if(self.challenge != None):
                print("self.challenge != None ")
                resendOTP = ServerUtil.getFirstValue(requestParameters, "OtpEmailloginForm:resendOtp")
                print("Resend OTP Status  ",resendOTP)
                if(resendOTP == "true"):
                    self.loadEmailMFAConfigs(sessionId,session_attributes)
                    print("Email ReSent ")
                    return ''


        extensionResult = self.extensionAuthenticate(configurationAttributes, requestParameters, step)
        if extensionResult != None:
            return extensionResult

        print ("Passport. authenticate for step %s called" % str(step))
        identity = CdiUtil.bean(Identity)

        if step == 1:
            # Get JWT token
            jwt_param = ServerUtil.getFirstValue(requestParameters, "user")

            if jwt_param != None:
                print ("Passport. authenticate for step 1. JWT user profile token found")

                # Parse JWT and validate
                jwt = Jwt.parse(jwt_param)
                if not self.validSignature(jwt):
                    return False

                if self.jwtHasExpired(jwt):
                    return False

                (user_profile, jsonp) = self.getUserProfile(jwt)
                if user_profile == None:
                    return False

                return self.attemptAuthentication(identity, user_profile, jsonp)

            #See passportlogin.xhtml
            provider = ServerUtil.getFirstValue(requestParameters, "loginForm:provider")
            print("provider +++++++++++++",provider)

            self.userType = ServerUtil.getFirstValue(requestParameters, "loginForm:platform")
            print("self.userType ++++++++++++++++++",self.userType)
            #Added to integrate  UAEPass
            if not self.userType:
                self.userType = ServerUtil.getFirstValue(requestParameters, "loginForm_emp:platform")
            if StringHelper.isEmpty(provider):

                #it's username + passw auth
                print ("Passport. authenticate for step 1. Basic authentication detected")
                logged_in = False

                credentials = identity.getCredentials()
                user_name = credentials.getUsername()
                self.user_name=user_name
                user_password = credentials.getPassword()

                ## Sun LDAP Authentication
                print ("-----------------------------------Start---------------------------------------------")
                user_exist =  self.ldap_login(user_name, user_password)
                if user_exist:
                    authenticationService = CdiUtil.bean(AuthenticationService)
                    logged_in = authenticationService.authenticate(user_name)
                
                print ("-----------------------------------Sun LDAP Authentication Complete---------------------------------------------")
                if(self.challenge == "2f01"):
                    self.loadSMSMFAConfigs(sessionIdService,facesMessages,session_attributes)
                   
                
                if(self.challenge == "2f02"):
                    self.loadEmailMFAConfigs(sessionId,session_attributes)

                if(self.challenge == "mf04"):
                    self.loadSMSMFAConfigs(sessionIdService,facesMessages,session_attributes)

                if(self.challenge == "mf05"):
                    self.loadSMSMFAConfigs(sessionIdService,facesMessages,session_attributes)

                if(self.challenge == "mf06"):
                    self.loadEmailMFAConfigs(sessionId,session_attributes)

                if(self.challenge == "mf07"):
                    self.loadSMSMFAConfigs(sessionIdService,facesMessages,session_attributes)

                
                    
                    
                return logged_in
                

            elif provider in self.registeredProviders:
                #it's a recognized external IDP
                print("provider elif provider in self.registeredProviders ",provider)
                identity.setWorkingParameter("selectedProvider", provider)
                print ("Passport. authenticate for step 1. Retrying step 1")
                #see prepareForStep (step = 1)
                return True
        
        if step == 2:
    
            if(self.challenge == "2f01"):
                return self.initiateSMSMFA(session_attributes,requestParameters,sessionIdService,facesMessages)
                
            
            if(self.challenge == "2f02"):
                return self.initiateEmailMFA(sessionId,session_attributes,requestParameters,facesMessages)

                

            if(self.challenge == "2f03"):
                return self.initiateGemaltoMFA(requestParameters,configurationAttributes)
            

            if(self.challenge == "mf04"):
                isSMSMFAComplete = self.initiateSMSMFA(session_attributes,requestParameters,sessionIdService,facesMessages)
                if(isSMSMFAComplete):
                    self.loadEmailMFAConfigs(sessionId,session_attributes)
                    return isSMSMFAComplete
                else:
                    return False
                
            if(self.challenge == "mf05"):
                isSMSMFAComplete = self.initiateSMSMFA(session_attributes,requestParameters,sessionIdService,facesMessages)
                if(isSMSMFAComplete):
                    return isSMSMFAComplete
                else:
                    return False
                
            if(self.challenge == "mf06"):
                isEmailMFAComplete = self.initiateEmailMFA(sessionId,session_attributes,requestParameters,facesMessages)
                if(isEmailMFAComplete):
                    return isEmailMFAComplete
                else:
                    return False
                
            if(self.challenge == "mf07"):
                isSMSMFAComplete = self.initiateSMSMFA(session_attributes,requestParameters,sessionIdService,facesMessages)
                if(isSMSMFAComplete):
                    self.loadEmailMFAConfigs(sessionId,session_attributes)
                    return isSMSMFAComplete
                else:
                    return False
                    
            
            
        if step == 3:
    
            if(self.challenge == "mf04"):
                return self.initiateEmailMFA(sessionId,session_attributes,requestParameters,facesMessages)
            if(self.challenge == "mf05"):
                return self.initiateGemaltoMFA(requestParameters,configurationAttributes)
            if(self.challenge == "mf06"):
                return self.initiateGemaltoMFA(requestParameters,configurationAttributes)
            if(self.challenge == "mf07"):
                isEmailMFAComplete = self.initiateEmailMFA(sessionId,session_attributes,requestParameters,facesMessages)
                if(isEmailMFAComplete):
                    return isEmailMFAComplete
                else:
                    return False
                
        if step == 4:
            if(self.challenge == "mf07"):
                return self.initiateGemaltoMFA(requestParameters,configurationAttributes)
            else:
                return False
                
            
            
                

        if step == 5:
            mail = ServerUtil.getFirstValue(requestParameters, "loginForm:email")
            jsonp = identity.getWorkingParameter("passport_user_profile")

            if mail == None:
                self.setMessageError(FacesMessage.SEVERITY_ERROR, "Email was missing in user profile")
            elif jsonp != None:
                # Completion of profile takes place
                user_profile = json.loads(jsonp)
                user_profile["mail"] = mail

                return self.attemptAuthentication(identity, user_profile, jsonp)

            print ("Passport. authenticate for step 2. Failed: expected mail value in HTTP request and json profile in session")
            return False
        
    
        
    def initiateEmailMFA(self,sessionId,session_attributes,requestParameters,facesMessages):
        print ("==Email OTP STEP 2==")
        emailpasscode = ServerUtil.getFirstValue(requestParameters, "emailpasscode")
        print("Email OTP Form Passcode is :%s"%emailpasscode)
        code = session_attributes.get("emailcode")
        print ('=======> Session code is "%s"' % str(code))
        # fetch from persistence
        code = sessionId.getSessionAttributes().get("emailcode")
        print ('=======> Database code is "%s"' % str(code))
        self.identity.setSessionId(sessionId)
        
        print ("Email OTP. Code: %s" % str(code))
    
        if code is None:
            print ("Email OTP. Failed to find previously sent code")
            return False

        if emailpasscode is None:
            print ("Email OTP. Passcode is empty")
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Incorrect Email OTP code, please try again.")
            return False

        if len(emailpasscode) != 6:
            print ("Email OTP. Passcode from response is not 6 digits: %s" % emailpasscode)
            return False

        if str(emailpasscode) == str(code):
            print ("Email OTP, SUCCESS! User entered the same code!")
        
            print ("===Email OTP SECOND STEP DONE PROPERLY")
        
            return True

        print ("Email OTP. FAIL! User entered the wrong code! %s != %s" % (emailpasscode, code))
        
        facesMessages.add(FacesMessage.SEVERITY_ERROR, "Incorrect Email OTP code, please try again.")
    
        print ("===Email OTP SECOND STEP FAILED: INCORRECT CODE")
        
        return False

        
    def initiateSMSMFA(self,session_attributes,requestParameters,sessionIdService,facesMessages):
        print ("=SMS OTP STEP 2 ==")
        smspasscode = ServerUtil.getFirstValue(requestParameters, "smspasscode")
        print("SMS OTP Form Passcode is :%s"%smspasscode)
        code = session_attributes.get("smscode")
        print ('=======> Session code is "%s"' % str(code))
        sessionId = sessionIdService.getSessionId() 
        # fetch from persistence
        code = sessionId.getSessionAttributes().get("smscode")
        print ('=======> Database code is "%s"' % str(code))
        self.identity.setSessionId(sessionId)
    
        print ("SMSOTP. Code: %s" % str(code))
    
        if code is None:
            print ("SMSOTP. Failed to find previously sent code")
            return False

        if smspasscode is None:
            print ("SMSOTP. Passcode is empty")
            return False

        if len(smspasscode) != 6:
            print ("SMSOTP. Passcode from response is not 6 digits: %s" % smspasscode)
            return False

        if str(smspasscode) == str(code):
            print ("SMSOTP, SUCCESS! User entered the same code!")
        
            print ("===SMS OTP SECOND STEP DONE PROPERLY")
            
            return True

    
        print ("SMSOTP. FAIL! User entered the wrong code! %s != %s" % (smspasscode))
    
        facesMessages.add(FacesMessage.SEVERITY_ERROR, "Incorrect SMS OTP code, please try again.")
    
        print ("===SMS OTP SECOND STEP FAILED: INCORRECT CODE")
    
        return False
    
    def initiateGemaltoMFA(self,requestParameters,configurationAttributes):
        print ("Gemalto MFA. Authenticate for Step 2")
        try:
                            
            gemaltopasscode = ServerUtil.getFirstValue(requestParameters, "gemaltopasscode")
            print("MobilePass+ OTP Form Passcode is :%s"%gemaltopasscode)
            AUTH_FAILURE = 0
            AUTH_SUCCESS = 1
            CHALLENGE = 2
            
            ini_file_path = configurationAttributes.get("ini_file_path").getValue2()

            if os.path.exists(ini_file_path):
                print("ini File Path is Valid.")
            
                try:
                    cryptocardApi = CRYPTOCardAPI.getInstance()
                    cryptocardApi.setINIPath(ini_file_path)
                    cryptocardApi.LoadJNILibrary()

                    print("Loading and Initialization of Gemalto Libraries OK")
                    
                    arrData = Array.newInstance(String, 11)

                    arrData[0] = self.user_name
                    arrData[1] = ""
                    arrData[2] = gemaltopasscode
                    arrData[3] = ""
                    arrData[4] = ""
                    arrData[5] = ""
                    arrData[6] = ""
                    arrData[7] = ""
                    arrData[8] = ""
                    arrData[9] = ""
                    arrData[10] = ""

                    print ('Below are the parameters passed to SAS Server for the authentication request')
                    print ('Username is %s ' % (arrData[0]))
                    print ('Entered Gemalto passcode is %s ' % (gemaltopasscode))
                    
                    print("Gemalto SAS Authentication Initiating")
                    cryptocardApi.Authenticate(arrData)
                    print("Gemalto SAS Authentication Initiated")

                    auth_result = Integer.parseInt(arrData[7])

                    if auth_result == AUTH_SUCCESS:
                        print("Authentication Successful")
                        return True
                    elif auth_result == AUTH_FAILURE:
                        print("Authentication FAILED")
                        return False
                    elif auth_result == CHALLENGE:
                        print("Authentication Challenge")
                        print("Returned Challenge:")
                        print(arrData[3])
                        print("Returned State:")
                        print(arrData[4])
                        print("Returned Challenge Data:")
                        print(arrData[5])
                        print("Returned User Message appended with Challenge:")
                        print(arrData[6])
                        return False
                    else:
                        print("Returned Code:")
                        print(arrData[7])
                        return False
                
                except (NameError, UnsatisfiedLinkError, Exception) as e:
                    print("Error in Gemalto Authentication: %s"%str(e))
                    return False
            else:
                print("ini File Path is invalid.")
                return False
            
        except Exception as e:
            print(str(e))
            return False


    def loadEmailMFAConfigs(self, sessionId, session_attributes):
        # Generate Random six digit code and store it
        code = random.randint(100000, 999999)

        # Get code and save it in LDAP temporarily with special session entry
        self.identity.setWorkingParameter("emailcode", code)
        
        # fetch from persistence
        sessionId.getSessionAttributes().put("emailcode", code)

        # Email configuration & SMTP server configuration
        sender_email = ""
        receiver_email = self.user_email
        subject = 'Your OTP to login into DM Account'

        

        # Read the HTML template from the file
        with open('/opt/gluu/jetty/oxauth/custom/pages/email_otp_template.html', 'r') as template_file:
            html_template = template_file.read()
        
        # Replace placeholders with dynamic values
        html_content = html_template.replace('%user_fullName%', self.user_fullName)
        html_content = html_content.replace('%OTP%', str(session_attributes.get("emailcode")))


        smtp_server = self.SMTP_HOSTNAME
        smtp_port = self.SMTP_PORT

        # Login credentials
        username = ""
        password = ""

        # Create properties
        props = Properties()
        props.setProperty("mail.smtp.host", smtp_server)
        props.setProperty("mail.smtp.port", smtp_port)
        props.setProperty("mail.smtp.auth", "true")
        props.setProperty("mail.smtp.starttls.enable", "true")

        # Create session
        session = Session.getInstance(props, None)

        # Construct the email message
        email_message = MimeMessage(session)
        email_message.setFrom(sender_email)

        # Create a recipient address
        recipient = internet.InternetAddress(receiver_email)

        # Set the recipient using the setRecipient() method
        email_message.setRecipient(Message.RecipientType.TO, recipient)
        email_message.setSubject(subject)

        # Set HTML content
        email_message.setContent(html_content, "text/html")

        # Send email & Connect to the mail server
        transport = session.getTransport("smtp")
        transport.connect(smtp_server, Integer.parseInt(self.SMTP_PORT), username, password)
        transport.sendMessage(email_message, email_message.getAllRecipients())
        transport.close()

        print("Email Sent Successfully to User %s" % receiver_email)
    
    def loadSMSMFAConfigs(self,sessionIdService,facesMessages,session_attributes):
        # Generate Random six digit code and store it in array
        code = random.randint(100000, 999999)

        # Get code and save it in LDAP temporarily with special session entry
        self.identity.setWorkingParameter("smscode", code)
        sessionId = sessionIdService.getSessionId() # fetch from persistence
        sessionId.getSessionAttributes().put("smscode", code)
        print("Random OTP Generated : %s'" % (code))

        try:
            transaction_id = self.TRANSACTION_ID
            to_number = self.user_mobile  

            otpMessage = "This message is a simple text %s SMS from VM Mobile Services. This is a testing message please do not reply to this testing message. Thanks. End Of Message-VECTRA"%(session_attributes.get("smscode"))

            #otpMessage='OTP is : %s' % (code)
            
            print ('SMSOTP, User phone: %s' % (to_number))
        
            client = HttpClients.createDefault()

            request = HttpPost(self.SMS_API_URL)

            request.setHeader("Content-Type", "application/json")
            request.setHeader("x-Gateway-APIKey", self.API_KEY)

            
            
            jsonBody = "{\r\n \"TransactionID\": \"" + transaction_id + "\",\r\n \"Recipients\": [ \"" + to_number + "\" ],\r\n \"Message\": \"" + otpMessage + "\"\r\n }"
            requestEntity = StringEntity(jsonBody, ContentType.APPLICATION_JSON)
        
            request.setEntity(requestEntity)
            
            print('API Call Initiating')
            response = client.execute(request)
            print('API Call Initiated')

            statusLine = response.getStatusLine()
            responseStatusCode = statusLine.getStatusCode()
            print("Response Status Code : %s" %str(responseStatusCode))
            if responseStatusCode == 200 or responseStatusCode == 201:
                responseEntity = response.getEntity()
                responseBody = EntityUtils.toString(responseEntity)
                print(responseBody)
                EntityUtils.consume(responseEntity)
                response.close()
                client.close()
            
                print ("===SMS OTP SENT TO USER SUCCESSFULLY==")

                return True
            else:
                responseEntity = response.getEntity()
                responseBody = EntityUtils.toString(responseEntity)
                print(responseBody)
                EntityUtils.consume(responseEntity)
                
                print ("===SENDING SMS OTP FAILED==")
            
                response.close()
                client.close()
                facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to send message to mobile phone, Server Response Code %s"%responseStatusCode)
                return False

        except Exception as ex:
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to send message to mobile phone")
            print ("SMSOTP. Error sending message")
            print ("SMSOTP. Unexpected error:", ex)
            return False


    def ldap_login(self, user_name, user_password):
        
        userService = CdiUtil.bean(UserService)

        settings = Hashtable()
        settings.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory")
        settings.put(Context.SECURITY_AUTHENTICATION, "simple")

        for ldap_server in self.ldapExtendedEntryManagers:
            self.loginChannel = ldap_server['configId']
            
            self.url="ldap://%s:389" % ldap_server['server']
            bindDN = ldap_server['bindDN']
            # bindDN = "CN=DevGlue1,CN=Users,DC=TEX,DC=AE"
            bindPassword = ldap_server['bindPassword']
            print("self ldap url: %s"%self.url)
            print("self ldap bindDN: %s"%bindDN)
            print("self ldap password: %s"%bindPassword)

            settings.put(Context.SECURITY_PRINCIPAL, bindDN)
            settings.put(Context.SECURITY_CREDENTIALS, bindPassword)

            self.srch = SearchControls()
            self.srch.setSearchScope(SearchControls.SUBTREE_SCOPE)

            try:
                settings.put(Context.PROVIDER_URL, self.url)
                self.ctx = InitialDirContext(settings)
                
                filter = '(&(samAccountName='+ user_name +'))'                
                results = self.ctx.search(ldap_server['searchBase'], filter, self.srch)
            except:
                print ("Error connecting LDAP server %s .Trying next server in the list"% ldap_server['server'])
                print ("Exception: ", sys.exc_info()[1])
                continue
            finally:
                self.ctx.close()

            if results is None: 
                print ("Failed to obtain any user from LDAP server %s .Trying next server in the list"% ldap_server['server'])
                continue
                
            distinguishedName = ""
            for result in results:
                print ("Found entry in LDAP server %s"%ldap_server['server'])

                attrs= result.getAttributes()

                print ("-------------------Attr-------------------------")
                print (attrs)
                print ("-------------------Attr-------------------------")

                try:
                    distinguishedName = attrs.get("distinguishedName").get()
                    print ("Authenticate for DN: %s"% distinguishedName)
                except:
                    pass
            print("Before AD Authentication")
            print("distinguishedName %s"%distinguishedName)
            print("ldap_server %s"%ldap_server)
            users = self.authenticateAD(user_name, user_password, distinguishedName, ldap_server)
            
            if users is None: 
                print ("Authentication failed in LDAP server %s ."% ldap_server['server'])
                continue
            
            for user in users:
                print ("Authenticated in LDAP server %s"%ldap_server['server'])

                attrs= user.getAttributes()

                try:
                    _uid = attrs.get("samAccountName").get()
                    profile = self.getActiveDirectoryProfile(attrs)

                    foundUser = userService.getUserByAttribute("oxExternalUid", _uid)

                    if foundUser != None:
                        print ("Updating User..")
                        self.updateUser(foundUser, profile, userService)
                        return True
                    else:
                        print ("Adding User..")
                        self.addUser(_uid, profile, userService)
                        return True

                except:
                    pass
            
        print ("No entries found!Tried all LDAP server.Failing.")
        return False


    def authenticateAD(self, user_name, user_password, distinguishedName, ldap_server):
        print ("Active Directory Authentication")

        settings = Hashtable()
        settings.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory")
        settings.put(Context.SECURITY_AUTHENTICATION, "simple")
        settings.put(Context.SECURITY_PRINCIPAL, distinguishedName)
        settings.put(Context.SECURITY_CREDENTIALS, user_password)

        self.srch = SearchControls()
        self.srch.setSearchScope(SearchControls.SUBTREE_SCOPE)

        self.url="ldap://%s:389" % ldap_server['server']

        try:
            settings.put(Context.PROVIDER_URL, self.url)
            self.ctx = InitialDirContext(settings)
            
            filter = '(&(samAccountName='+ user_name +'))'                
            results = self.ctx.search(ldap_server['searchBase'], filter, self.srch)
        except:
            print ("Exception: ", sys.exc_info()[1])
            results = None
        finally:
            self.ctx.close()

        return results


    def getActiveDirectoryProfile(self, attrs):
        profile = dict()

        profile["uid"] = [attrs.get("samAccountName").get()]
        profile["oxExternalUid"] = [attrs.get("samAccountName").get()]
        if attrs.get("userPrincipalName"):
            profile["userPrincipal"] = [attrs.get("userPrincipalName").get()]
        if attrs.get("givenName"):
            profile["givenname"] = [attrs.get("givenName").get()]
        if attrs.get("displayname"):
            profile["displayname"] = [attrs.get("displayname").get()]
        if attrs.get("cn"):
            profile["cn"] = [attrs.get("cn").get()]
            self.user_fullName = [attrs.get("cn").get()][0]
        if attrs.get("department"):
            profile["departmentNumber"] = [attrs.get("department").get()]
        if attrs.get("ExtensionAttribute1"):
            profile["employeeId"] = [attrs.get("ExtensionAttribute1").get()]
        if attrs.get("title"):
            profile["title"] = [attrs.get("title").get()]
        if attrs.get("telephoneNumber"):
            profile["telephoneNumber"] = [attrs.get("telephoneNumber").get()]

            self.user_mobile=[attrs.get("telephoneNumber").get()][0]
            # Remove any plus (+) or minus (-) signs from the input string
            cleaned_string = re.sub(r'[+-]', '', self.user_mobile)
    
            # Extract the numerical value from the cleaned string
            numeric_value = re.findall(r'\d+', cleaned_string)
    
            # Join the digits to form a single string
            self.user_mobile = ''.join(numeric_value)

            print("user mobile no is :%s"%self.user_mobile)
        if attrs.get("mobile"):
            profile["mobile"] = [attrs.get("mobile").get()]
            self.user_mobile=[attrs.get("mobile").get()][0]
            
            # Remove any plus (+) or minus (-) signs from the input string
            cleaned_string = re.sub(r'[+-]', '', self.user_mobile)
    
            # Extract the numerical value from the cleaned string
            numeric_value = re.findall(r'\d+', cleaned_string)
    
            # Join the digits to form a single string
            self.user_mobile = ''.join(numeric_value)

            print("user mobile no is :%s"%self.user_mobile)
            

        if attrs.get("mail"):
            profile["mail"] = [attrs.get("mail").get()]
            self.user_email=[attrs.get("mail").get()][0]
            #self.user_email= "jogeshd@centroxy.com"
            print("user email is :%s"%self.user_email)

        if attrs.get("facsimileTelephoneNumber"):
            profile["facsimileTelephoneNumber"] = [attrs.get("facsimileTelephoneNumber").get()]
        if attrs.get("physicalDeliveryOfficeName"):
            profile["adPhysicalAddress"] = [attrs.get("physicalDeliveryOfficeName").get()]
        
                            
        profile["loginChannel"] = [self.loginChannel]

        return profile

    def prepareForStep(self, configurationAttributes, requestParameters, step):

        extensionResult = self.extensionPrepareForStep(configurationAttributes, requestParameters, step)
        if extensionResult != None:
            return extensionResult

        print ("Passport. prepareForStep called %s"  % str(step))
        identity = CdiUtil.bean(Identity)

        if step == 1:
            #re-read the strategies config (for instance to know which strategies have enabled the email account linking)
            self.parseProviderConfigs()
            identity.setWorkingParameter("externalProviders", json.dumps(self.registeredProviders))

            providerParam = self.customAuthzParameter
            url = None

            sessionAttributes = identity.getSessionId().getSessionAttributes()
            self.skipProfileUpdate = StringHelper.equalsIgnoreCase(sessionAttributes.get("skipPassportProfileUpdate"), "true")

            #this param could have been set previously in authenticate step if current step is being retried
            provider = identity.getWorkingParameter("selectedProvider")
            if provider != None:
                url = self.getPassportRedirectUrl(provider)
                print("Passport Redirect Url ",url)
                identity.setWorkingParameter("selectedProvider", None)
                self.loginChannel = provider

            elif providerParam != None:
                paramValue = sessionAttributes.get(providerParam)

                if paramValue != None:
                    print ("Passport. prepareForStep. Found value in custom param of authorization request: %s" % paramValue)
                    provider = self.getProviderFromJson(paramValue)

                    if provider == None:
                        print ("Passport. prepareForStep. A provider value could not be extracted from custom authorization request parameter")
                    elif not provider in self.registeredProviders:
                        print ("Passport. prepareForStep. Provider '%s' not part of known configured IDPs/OPs" % provider)
                    else:
                        url = self.getPassportRedirectUrl(provider)

            if url == None:
                print ("Passport. prepareForStep. A page to manually select an identity provider will be shown")
            else:
                facesService = CdiUtil.bean(FacesService)
                facesService.redirectToExternalURL(url)

        return True

    def getAuthenticationMethodClaims(self):
        print ("Passport. Get Authentication Method Claims")
        params = dict()
        params["loginChannel"] = self.loginChannel
        # index = 1
        # for amr in self.amr_values:
        #     params["amr"+str(index)] = str(amr)
        #     index += 1

        print ("--------------AMR---------------")
        print (str(params["loginChannel"]))
        print ("--------------AMR---------------")
        return params

    def getExtraParametersForStep(self, configurationAttributes, step):
        print ("Passport. getExtraParametersForStep called")
        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()
        sessionAttributes.put("login_channel", self.loginChannel)
        sessionAttributes.put("user_type", self.userType)
        if step == 1:
            return Arrays.asList("selectedProvider", "externalProviders")
        elif step == 2:
            if(self.challenge == "2f01"):
                print("get extra parameter for step 2 - sms MFA")
                return Arrays.asList("code")
            elif(self.challenge == "2f02"):
                print("get extra parameter for step 2 - email MFA")
                return Arrays.asList("code")
            elif(self.challenge == "2f03"):
                print("get extra parameter for step 2 - Gemalto MFA")
                return Arrays.asList("otp")
            elif(self.challenge == "mf04"):
                print("get extra parameter for step 2 - SMS MFA")
                return Arrays.asList("code")
            elif(self.challenge == "mf05"):
                print("get extra parameter for step 2 - SMS MFA")
                return Arrays.asList("code")
            elif(self.challenge == "mf06"):
                print("get extra parameter for step 2 - email MFA")
                return Arrays.asList("code")
            elif(self.challenge == "mf07"):
                print("get extra parameter for step 2 - SMS MFA")
                return Arrays.asList("code")
            
            
            else:
                return None  
        elif step == 3:
            if(self.challenge == "mf04"):
                print("get extra parameter for step 3 - email MFA")
                return Arrays.asList("code")
            elif(self.challenge == "mf05"):
                print("get extra parameter for step 3 - Gemalto MFA")
                return Arrays.asList("otp")
            elif(self.challenge == "mf06"):
                print("get extra parameter for step 3 - Gemalto MFA")
                return Arrays.asList("otp")
            if(self.challenge == "mf07"):
                print("get extra parameter for step 3 - email MFA")
                return Arrays.asList("code")
            else:
                return None 
            
        elif step == 4:
            if(self.challenge == "mf07"):
                print("get extra parameter for step 4 - Gemalto MFA")
                return Arrays.asList("otp")
            else:
                return None 
            
        
            
        elif step == 5:
            return Arrays.asList("passport_user_profile")
        return None


    def getCountAuthenticationSteps(self, configurationAttributes):
        print ("Passport. getCountAuthenticationSteps called")
        # TO DO: Only keep this section for dynamic scope
        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()
        sessionAttributes.put("login_channel", self.loginChannel)
        sessionAttributes.put("user_type", self.userType)
        identity = CdiUtil.bean(Identity)
        # if(self.challenge!=None):
        #     if identity.getWorkingParameter("passport_user_profile") != None:
        #         return 3
        #     return 2
        # else:
        #     if identity.getWorkingParameter("passport_user_profile") != None:
        #         return 2
        #     return 1

        if(self.challenge!=None):
            if(self.challenge == "2f01" or self.challenge == "2f02" or self.challenge == "2f03"):
                if identity.getWorkingParameter("passport_user_profile") != None:
                        return 3
                return 2
            elif(self.challenge == "mf04" or self.challenge == "mf05" or self.challenge == "mf06"):
                if identity.getWorkingParameter("passport_user_profile") != None:
                    return 4
                return 3
            
            elif(self.challenge == "mf07"):
                if identity.getWorkingParameter("passport_user_profile") != None:
                        return 5
                return 4
            
            
        else:
            if identity.getWorkingParameter("passport_user_profile") != None:
                return 2
            return 1







    def getPageForStep(self, configurationAttributes, step):
        self.automation_key= None
        self.login_page= None

        print ("Passport. getPageForStep called")

        extensionResult = self.extensionGetPageForStep(configurationAttributes, step)
        if extensionResult != None:
            return extensionResult
        
        ## TO DO: change the hard code value later
        self.userType = "individual"

        request = FacesContext.getCurrentInstance().getExternalContext().getRequest()
        
        print (request.getParameter('ui_locales'))
        # print request.getParameter('user_type')
        

        if(step ==1):
            self.challenge=None

        if request.getParameter('challenge'):
            self.challenge = request.getParameter('challenge')
            print("MFA type is  %s"%self.challenge)

        

        # if self.mfa_type not in ['email', 'sms','gemalto',None]:
        if self.challenge not in ['2f02', '2f01','2f03','mf04','mf05','mf06','mf07',None]:
            
            print("Redirecting to error page because %s is not a registered challenge in Gluu" %self.challenge)
            return "/error.xhtml"
        
        
        if request.getParameter('ui_locales'):
            self.ui_locales = request.getParameter('ui_locales')

             ## Parameter for login page selection
        if request.getParameter('page'):
            self.login_page = request.getParameter('page')
		
        
        if request.getParameter('automation_key'):
            self.automation_key= request.getParameter('automation_key')
			
        if not self.ui_locales:
            print ("Language parameter not found")
            self.ui_locales = "en"

            
        
        if step == 1:
            if self.automation_key == self.noc_automation_key:
                return "/auth/passport/internal_en_noc.xhtml"
                
            if self.ui_locales == "ar":
                if self.login_page == "iot":
                    return "/auth/passport/iot_internal_ar.xhtml"
                else:
                    return "/auth/passport/internal_ar_uae.xhtml"
            
            else:
                if self.login_page == "iot":
                    return "/auth/passport/iot_internal_en.xhtml"
                else:
                    # return "/auth/passport/internal_en.xhtml"
                    return "/auth/passport/internal_en_uae.xhtml"
                    # return "/auth/passport/ex_captcha.xhtml"
        
        if(step ==2):
            print("Getting page for step 2")

            if(self.challenge == "2f01"):
                return "/auth/2fa/sms_otp.xhtml"
            elif(self.challenge == "2f02"):
                return "/auth/2fa/email_resend_otp.xhtml"
            elif(self.challenge == "2f03"):
                return "/auth/2fa/gemalto_otp.xhtml"
            elif(self.challenge == "mf04"):
                return "/auth/2fa/sms_otp.xhtml"
            elif(self.challenge == "mf05"):
                return "/auth/2fa/sms_otp.xhtml"
            elif(self.challenge == "mf06"):
                return "/auth/2fa/email_otp.xhtml"
            elif(self.challenge == "mf07"):
                return "/auth/2fa/sms_otp.xhtml"
            else:
                return "" 
            
        if(step ==3):
            print("Getting page for step 3")

            if(self.challenge == "mf04"):
                return "/auth/2fa/email_otp.xhtml"
            elif(self.challenge == "mf05"):
                return "/auth/2fa/gemalto_otp.xhtml"
            elif(self.challenge == "mf06"):
                return "/auth/2fa/gemalto_otp.xhtml"
            elif(self.challenge == "mf07"):
                return "/auth/2fa/email_otp.xhtml"
            else:
                return ""
            
        if(step ==4):
            print("Getting page for step 4")

            if(self.challenge == "mf07"):
                return "/auth/2fa/gemalto_otp.xhtml"
            else:
                return ""
        
        return "/auth/passport/passportpostlogin.xhtml"


    def getNextStep(self, configurationAttributes, requestParameters, step):

        if step == 1:
            identity = CdiUtil.bean(Identity)
            provider = identity.getWorkingParameter("selectedProvider")
            if provider != None:
                return 1

        return -1


    def logout(self, configurationAttributes, requestParameters):
        return True

# Extension module related functions

    def extensionInit(self, configurationAttributes):

        if self.extensionModule == None:
            return None
        return self.extensionModule.init(configurationAttributes)


    def extensionAuthenticate(self, configurationAttributes, requestParameters, step):

        if self.extensionModule == None:
            return None
        return self.extensionModule.authenticate(configurationAttributes, requestParameters, step)


    def extensionPrepareForStep(self, configurationAttributes, requestParameters, step):

        if self.extensionModule == None:
            return None
        return self.extensionModule.prepareForStep(configurationAttributes, requestParameters, step)


    def extensionGetPageForStep(self, configurationAttributes, step):

        if self.extensionModule == None:
            return None
        return self.extensionModule.getPageForStep(configurationAttributes, step)

# Initalization routines

    def loadExternalModule(self, simpleCustProperty):

        if simpleCustProperty != None:
            print ("Passport. loadExternalModule. Loading passport extension module...")
            moduleName = simpleCustProperty.getValue2()
            try:
                module = __import__(moduleName)
                return module
            except:
                print ("Passport. loadExternalModule. Failed to load module %s" % moduleName)
                print ("Exception: ", sys.exc_info()[1])
                print ("Passport. loadExternalModule. Flow will be driven entirely by routines of main passport script")
        return None


    def loadAuthConfiguration(self, authConfigurationFile):
        authConfiguration = None

        # Load authentication configuration from file
        f = open(authConfigurationFile, 'r')
        try:
            authConfiguration = json.loads(f.read())
        except:
            print ("Passport. Load auth configuration. Failed to load authentication configuration from file:", authConfigurationFile)
            return None
        finally:
            f.close()
        
        return authConfiguration

    def validateAuthConfiguration(self, authConfiguration):
        isValid = True

        if (not ("ldap_configuration" in authConfiguration)):
            print ("Passport. Validate auth configuration. There is no ldap_configuration section in configuration")
            return False
        
        idx = 1
        for ldapConfiguration in authConfiguration["ldap_configuration"]:
            if (not self.containsAttributeString(ldapConfiguration, "configId")):
                print ("Passport. Validate auth configuration. There is no 'configId' attribute in ldap_configuration section #" + str(idx))
                return False

            configId = ldapConfiguration["configId"]

            if (not self.containsAttributeString(ldapConfiguration, "server")):
                print ("Passport. Validate auth configuration. Property 'server' in configuration '" + configId + "' is invalid")
                return False

            if (self.containsAttributeString(ldapConfiguration, "bindDN")):
                if (not self.containsAttributeString(ldapConfiguration, "bindPassword")):
                    print ("Passport. Validate auth configuration. Property 'bindPassword' in configuration '" + configId + "' is invalid")
                    return False

            if (not self.containsAttributeString(ldapConfiguration, "useSSL")):
                print ("Passport. Validate auth configuration. Property 'useSSL' in configuration '" + configId + "' is invalid")
                return False

            if (not self.containsAttributeString(ldapConfiguration, "maxConnections")):
                print ("Passport. Validate auth configuration. Property 'maxConnections' in configuration '" + configId + "' is invalid")
                return False
                
            if (not self.containsAttributeString(ldapConfiguration, "baseDN")):
                print ("Passport. Validate auth configuration. Property 'baseDN' in configuration '" + configId + "' is invalid")
                return False

            if (not self.containsAttributeString(ldapConfiguration, "loginAttributes")):
                print ("Passport. Validate auth configuration. Property 'loginAttributes' in configuration '" + configId + "' is invalid")
                return False

            if (not self.containsAttributeString(ldapConfiguration, "localLoginAttributes")):
                print ("Passport. Validate auth configuration. Property 'localLoginAttributes' in configuration '" + configId + "' is invalid")
                return False

            if (len(ldapConfiguration["loginAttributes"]) != len(ldapConfiguration["localLoginAttributes"])):
                print ("Passport. Validate auth configuration. The number of attributes in 'loginAttributes' and 'localLoginAttributes' isn't equal in configuration '" + configId + "'")
                return False

            idx += 1

        return True

    def createLdapExtendedEntryManagers(self, authConfiguration):
        ldapExtendedConfigurations = self.createLdapExtendedConfigurations(authConfiguration)
        
        appInitializer = CdiUtil.bean(AppInitializer)

        ldapExtendedEntryManagers = []
        for ldapExtendedConfiguration in ldapExtendedConfigurations:
            ldapEntryManager = appInitializer.createLdapAuthEntryManager(ldapExtendedConfiguration["ldapConfiguration"])
            ldapExtendedEntryManagers.append({ "ldapConfiguration" : ldapExtendedConfiguration["ldapConfiguration"], "loginAttributes" : ldapExtendedConfiguration["loginAttributes"], "localLoginAttributes" : ldapExtendedConfiguration["localLoginAttributes"], "ldapEntryManager" : ldapEntryManager })
        
        return ldapExtendedEntryManagers

    def createLdapExtendedConfigurations(self, authConfiguration):
        ldapExtendedConfigurations = []

        for ldapConfiguration in authConfiguration["ldap_configuration"]:
            configId = ldapConfiguration["configId"]
            
            server = ldapConfiguration["server"]

            bindDN = None
            bindPassword = None
            useAnonymousBind = True
            if (self.containsAttributeString(ldapConfiguration, "bindDN")):
                useAnonymousBind = False
                bindDN = ldapConfiguration["bindDN"]
                bindPassword = ldapConfiguration["bindPassword"]

            useSSL = ldapConfiguration["useSSL"]
            maxConnections = ldapConfiguration["maxConnections"]
            baseDN = ldapConfiguration["baseDN"]
            loginAttributes = ldapConfiguration["loginAttributes"]
            localLoginAttributes = ldapConfiguration["localLoginAttributes"]
            
            ldapConfiguration = GluuLdapConfiguration(configId, bindDN, bindPassword, Arrays.asList(server),
                                                      maxConnections, useSSL, Arrays.asList(baseDN),
                                                      loginAttributes[0], localLoginAttributes[0], useAnonymousBind)
            ldapExtendedConfigurations.append({ "ldapConfiguration" : ldapConfiguration, "loginAttributes" : loginAttributes, "localLoginAttributes" : localLoginAttributes })
        
        return ldapExtendedConfigurations

    def containsAttributeString(self, dictionary, attribute):
        return ((attribute in dictionary) and StringHelper.isNotEmptyString(dictionary[attribute]))

    def containsAttributeArray(self, dictionary, attribute):
        return ((attribute in dictionary) and (len(dictionary[attribute]) > 0))



    def processKeyStoreProperties(self, attrs):
        file = attrs.get("key_store_file")
        password = attrs.get("key_store_password")

        if file != None and password != None:
            file = file.getValue2()
            password = password.getValue2()

            if StringHelper.isNotEmpty(file) and StringHelper.isNotEmpty(password):
                self.keyStoreFile = file
                self.keyStorePassword = password
                return True

        print ("Passport. readKeyStoreProperties. Properties key_store_file or key_store_password not found or empty")
        return False


    def getCustomAuthzParameter(self, simpleCustProperty):

        customAuthzParameter = None
        if simpleCustProperty != None:
            prop = simpleCustProperty.getValue2()
            if StringHelper.isNotEmpty(prop):
                customAuthzParameter = prop

        if customAuthzParameter == None:
            print ("Passport. getCustomAuthzParameter. No custom param for OIDC authz request in script properties")
            print ("Passport. getCustomAuthzParameter. Passport flow cannot be initiated by doing an OpenID connect authorization request")
        else:
            print ("Passport. getCustomAuthzParameter. Custom param for OIDC authz request in script properties: %s" % customAuthzParameter)

        return customAuthzParameter

# Configuration parsing

    def getPassportConfigDN(self):

        try:
            f = open('/etc/gluu/conf/gluu.properties', 'r')
            for line in f:
                prop = line.split("=")
                if prop[0] == "oxpassport_ConfigurationEntryDN":
                    prop.pop(0)
                    break
        except:
            return None
        finally:
            f.close()
            
        return "=".join(prop).strip()


    def parseAllProviders(self):

        registeredProviders = {}
        print ("Passport. parseAllProviders. Adding providers")
        entryManager = CdiUtil.bean(PersistenceEntryManager)

        config = LdapOxPassportConfiguration()
        config = entryManager.find(config.getClass(), self.passportDN).getPassportConfiguration()
        config = config.getProviders() if config != None else config

        if config != None and len(config) > 0:
            for prvdetails in config:
                if prvdetails.isEnabled():
                    registeredProviders[prvdetails.getId()] = {
                        "emailLinkingSafe": prvdetails.isEmailLinkingSafe(),
                        "requestForEmail" : prvdetails.isRequestForEmail(),
                        "logo_img": prvdetails.getLogoImg(),
                        "displayName": prvdetails.getDisplayName(),
                        "type": prvdetails.getType()
                    }

        return registeredProviders


    def parseProviderConfigs(self):

        registeredProviders = {}
        try:
            registeredProviders = self.parseAllProviders()
            toRemove = []

            for provider in registeredProviders:
                if registeredProviders[provider]["type"] == "saml":
                    toRemove.append(provider)
                else:
                    registeredProviders[provider]["saml"] = False

            for provider in toRemove:
                registeredProviders.pop(provider)

            if len(registeredProviders.keys()) > 0:
                print ("Passport. parseProviderConfigs. Configured providers:", registeredProviders)
            else:
                print ("Passport. parseProviderConfigs. No providers registered yet")
        except:
            print ("Passport. parseProviderConfigs. An error occurred while building the list of supported authentication providers", sys.exc_info()[1])

        self.registeredProviders = registeredProviders

# Auxiliary routines

    def getProviderFromJson(self, providerJson):

        provider = None
        try:
            obj = json.loads(Base64Util.base64urldecodeToString(providerJson))
            provider = obj[self.providerKey]
        except:
            print ("Passport. getProviderFromJson. Could not parse provided Json string. Returning None")

        return provider


    def getPassportRedirectUrl(self, provider):

        # provider is assumed to exist in self.registeredProviders
        url = None
        try:
            facesContext = CdiUtil.bean(FacesContext)
            tokenEndpoint = "https://%s/passport/token" % facesContext.getExternalContext().getRequest().getServerName()

            httpService = CdiUtil.bean(HttpService)
            httpclient = httpService.getHttpsClient()

            print ("Passport. getPassportRedirectUrl. Obtaining token from passport at %s" % tokenEndpoint)
            resultResponse = httpService.executeGet(httpclient, tokenEndpoint, Collections.singletonMap("Accept", "text/json"))
            httpResponse = resultResponse.getHttpResponse()
            bytes = httpService.getResponseContent(httpResponse)

            response = httpService.convertEntityToString(bytes)
            print ("Passport. getPassportRedirectUrl. Response was %s" % httpResponse.getStatusLine().getStatusCode())

            tokenObj = json.loads(response)
            url = "/passport/auth/%s/%s" % (provider, tokenObj["token_"])
        except:
            print ("Passport. getPassportRedirectUrl. Error building redirect URL: ", sys.exc_info()[1])

        return url


    def validSignature(self, jwt):

        print ("Passport. validSignature. Checking JWT token signature")
        valid = False

        try:
            appConfiguration = AppConfiguration()
            appConfiguration.setWebKeysStorage(WebKeyStorage.KEYSTORE)
            appConfiguration.setKeyStoreFile(self.keyStoreFile)
            appConfiguration.setKeyStoreSecret(self.keyStorePassword)
            appConfiguration.setKeyRegenerationEnabled(False)

            cryptoProvider = CryptoProviderFactory.getCryptoProvider(appConfiguration)
            valid = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), jwt.getHeader().getKeyId(),
                                                        None, None, jwt.getHeader().getSignatureAlgorithm())
        except:
            print ("Exception: ", sys.exc_info()[1])

        print ("Passport. validSignature. Validation result was %s" % valid)
        return valid



    def jwtHasExpired(self, jwt):
        # Check if jwt has expired
        jwt_claims = jwt.getClaims()

        try:
            print("JWT Claims:", jwt_claims)
            exp_date_timestamp = float(jwt_claims.getClaimAsString(JwtClaimName.EXPIRATION_TIME))
            exp_date = datetime.datetime.fromtimestamp(exp_date_timestamp)
            hasExpired = exp_date < datetime.datetime.now()
        except:
            print("Exception: The JWT does not have '%s' attribute" % JwtClaimName.EXPIRATION_TIME)
            return False

        return hasExpired


    def getUserProfile(self, jwt):
        # Check if there is user profile
        jwt_claims = jwt.getClaims()
           
        user_profile_json = None

        try:
            user_profile_json = CdiUtil.bean(EncryptionService).decrypt(jwt_claims.getClaimAsString("data"))
            user_profile = json.loads(user_profile_json)
            print("user_profile %s"%user_profile)
        except:
            print ("Passport. getUserProfile. Problem obtaining user profile json representation")

        return (user_profile, user_profile_json)


    def attemptAuthentication(self, identity, user_profile, user_profile_json):

        uidKey = "uid"
        if not self.checkRequiredAttributes(user_profile, [uidKey, self.providerKey]):
            return False

        provider = user_profile[self.providerKey]
        if not provider in self.registeredProviders:
            print ("Passport. attemptAuthentication. Identity Provider %s not recognized" % provider)
            return False

        uid = user_profile[uidKey][0]
        externalUid = "passport-%s:%s" % (provider, uid)

        userService = CdiUtil.bean(UserService)
        userByUid = userService.getUserByAttribute("oxExternalUid", externalUid)

        email = None
        if "mail" in user_profile:
            email = user_profile["mail"]
            if len(email) == 0:
                email = None
            else:
                email = email[0]
                user_profile["mail"] = [ email ]

        user_profile["loginChannel"] = self.loginChannel
        # user_profile["userType"] = self.userType

        if email == None and self.registeredProviders[provider]["requestForEmail"]:
            print ("Passport. attemptAuthentication. Email was not received")

            if userByUid != None:
                # This avoids asking for the email over every login attempt
                email = userByUid.getAttribute("mail")
                if email != None:
                    print ("Passport. attemptAuthentication. Filling missing email value with %s" % email)
                    user_profile["mail"] = [ email ]

            if email == None:
                # Store user profile in session and abort this routine
                identity.setWorkingParameter("passport_user_profile", user_profile_json)
                return True

        userByMail = None if email == None else userService.getUserByAttribute("mail", email)

        # Determine if we should add entry, update existing, or deny access
        doUpdate = False
        doAdd = False
        if userByUid != None:
            print ("User with externalUid '%s' already exists" % externalUid)
            if userByMail == None:
                doUpdate = True
            else:
                if userByMail.getUserId() == userByUid.getUserId():
                    doUpdate = True
                else:
                    print ("Updating User with externalUid '%s' and mail '%s' " % (externalUid, email))
                    doUpdate = True
                    # print "Users with externalUid '%s' and mail '%s' are different. Access will be denied. Impersonation attempt?" % (externalUid, email)
                    # self.setMessageError(FacesMessage.SEVERITY_ERROR, "Email value corresponds to an already existing provisioned account")
        else:
            if userByMail == None:
                doAdd = True
            elif self.registeredProviders[provider]["emailLinkingSafe"]:

                tmpList = userByMail.getAttributeValues("oxExternalUid")
                tmpList = ArrayList() if tmpList == None else ArrayList(tmpList)
                tmpList.add(externalUid)
                userByMail.setAttribute("oxExternalUid", tmpList)

                userByUid = userByMail
                print ("External user supplying mail %s will be linked to existing account '%s'" % (email, userByMail.getUserId()))
                doUpdate = True
            else:
                print ("Adding another account with existing mail id")
                doAdd = True
                # print "An attempt to supply an email of an existing user was made. Turn on 'emailLinkingSafe' if you want to enable linking"
                # self.setMessageError(FacesMessage.SEVERITY_ERROR, "Email value corresponds to an already existing account. If you already have a username and password use those instead of an external authentication site to get access.")

        username = None
        try:
            if doUpdate:
                username = userByUid.getUserId()
                print ("Passport. attemptAuthentication. Updating user %s" % username)
                self.updateUser(userByUid, user_profile, userService)
            elif doAdd:
                print ("Passport. attemptAuthentication. Creating user %s" % externalUid)
                newUser = self.addUser(externalUid, user_profile, userService)
                username = newUser.getUserId()
        except:
            print ("Exception: ", sys.exc_info()[1])
            print ("Passport. attemptAuthentication. Authentication failed")
            return False

        if username == None:
            print ("Passport. attemptAuthentication. Authentication attempt was rejected")
            return False
        else:
            logged_in = CdiUtil.bean(AuthenticationService).authenticate(username)
            print ("Passport. attemptAuthentication. Authentication for %s returned %s" % (username, logged_in))
            return logged_in


    def setMessageError(self, msg, severity):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(severity, msg)


    def checkRequiredAttributes(self, profile, attrs):

        for attr in attrs:
            if (not attr in profile) or len(profile[attr]) == 0:
                print ("Passport. checkRequiredAttributes. Attribute '%s' is missing in profile" % attr)
                return False
        return True


    def addUser(self, externalUid, profile, userService):

        try:
            newUser = User()
            #Fill user attrs
            newUser.setAttribute("oxExternalUid", externalUid)
            self.fillUser(newUser, profile)
            newUser = userService.addUser(newUser, True)
            return newUser
        except:
            print ("Exception: ", sys.exc_info()[1])


    def updateUser(self, foundUser, profile, userService):

        # when this is false, there might still some updates taking place (e.g. not related to profile attrs released by external provider)
        try:
            if (not self.skipProfileUpdate):
                self.fillUser(foundUser, profile)
            userService.updateUser(foundUser)
            print ("User Updated")
        except:
            print ("Exception: ", sys.exc_info()[1])


    def fillUser(self, foundUser, profile):

        try:
            for attr in profile:
                # "provider" is disregarded if part of mapping
                if attr != self.providerKey:
                    values = profile[attr]
                    print ("%s = %s" % (attr, values))
                    foundUser.setAttribute(attr, values)

                    if attr == "mail":
                        oxtrustMails = []
                        for mail in values:
                            oxtrustMails.append('{"value":"%s","primary":false}' % mail)
                        foundUser.setAttribute("oxTrustEmail", oxtrustMails)
        except:
            print ("Exception: ", sys.exc_info()[1])
