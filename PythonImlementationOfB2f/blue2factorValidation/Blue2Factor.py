'''
Created on Mar 4, 2021

@author: cjm
'''


import jwt
import logging
import traceback
import requests

#    Usage;
#
#    b2f = Blue2factor()
#    if b2f.isAuthenticated(jwt):
#        #show your page
#    else:
#        url = urllib.parse.quote(currentUrl)
#        # redirect to b2f.failureUrl + "?url=" + url

class Blue2factor():
    # get these values from your Blue2factor company page at https://secure.blue2factor.com
    myLoginUrl = "LOGIN_URL"  # CHANGE
    myCompanyID = "COMPANY_ID"  # CHANGE
    
    # do not change these values
    secureUrl = "https://secure.blue2factor.com"
    endpoint = secureUrl + "/SAML2/SSO/" + myCompanyID + "/Token"
    failureUrl = secureUrl + "/f2Failure"
    SUCCESS = 0
        
    def isAuthentcated(self, jwToken):
        #Checks the token, if it's not successful then gets a new token
        success = False
        try:
            if self.isTokenValid(jwToken):
                success = True
            else:
                logging.warn("token wasn't valid, will attempt to get a new one")
                success = self.getNewToken(jwToken) != None
        except:
            logging.error(traceback.format_exc())
        return success
    
    def isTokenValid(self, jwtoken):
        #Is the current token still valid?
        valid = False
        if jwtoken is not None:
            try:
                headers = jwt.get_unverified_header(jwtoken)
                url = headers.get("x5u")
                publicKey = self.getPublicKeyFromUrl(url)
                if publicKey is not None:
                    decoded = jwt.decode(
                        jwtoken,
                        publicKey,
                        issuer=self.secureUrl,
                        audience=self.myLoginUrl,
                        algorithms=["RS256"])
                    valid = True
            except jwt.ExpiredSignatureError:
                logging.error("signature expired")
            except jwt.InvalidIssuerError:
                logging.error("invalid issuer")
            except Exception as e:
                logging.error("invalid jwt")
                logging.error(str(e))
        else:
            logging.error("token was null")
        return valid
    
    def getNewToken(self, jwToken):
        #Gets a new token if the user is authenticated and then validates it
        newToken = None
        try:
            response = requests.get(url=self.endpoint, auth=BearerAuth(jwToken))
            logging.error("response: " + str(response.status_code))
            if response.status_code == 200:
                jsonResponse = response.json()
                logging.error(jsonResponse)
                if jsonResponse is not None:
                    logging.error("success: " + str(jsonResponse["outcome"]))
                    if int(jsonResponse["outcome"]) == self.SUCCESS:
                        if self.tokenIsValid(jsonResponse["token"]):
                            newToken = jsonResponse["token"]
                            #Save the token somewhere so you can use it next time
        except Exception as e:
            logging.error(traceback.format_exc())
            logging.error(str(e))
        return newToken
    
    
    def getPublicKeyFromUrl(self, url):
        #Gets the public key from the URL in the header of the JWT. The public key can be cached as it
        #does not change often
        publicKey = None
        resp = requests.get(url)
        if resp.status_code == 200:
            publicKey = ("-----BEGIN PUBLIC KEY-----\n" + self.addNewLinesToKeyString(resp.text) + 
                   "\n-----END PUBLIC KEY-----")
        else:
            logging.warn("status code: " + str(resp.status_code))
        return publicKey
    
    def addNewLinesToKeyString(self, keyStr):
        #format the public key string
        lines = []
        for i in range(0, len(keyStr), 64):
            lines.append(str(keyStr[i:i + 64]))
        return '\n'.join(lines)
