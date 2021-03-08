# Blue2FactorPythonImplementation

## Blue2Factor is passwordless first and second factor authentication

To learn about this product, please see https://www.blue2factor.com.

To use Blue2Factor, place this code at the top of each page you would like protected:


```
   b2f = Blue2factor()
   redirect = b2f.b2fRedirect(jwt, currentUrl)
   if redirect:
      #redirect to url: redirect
   else:
      #show your page
```
    
Please contact us at help@blue2factor.com or use the contact info at https://www.blue2factor.com/contactUs.

We are here to help!
