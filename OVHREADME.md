Configuration
==============
Within the configuration file you assign to wildcert, you will need to configure OVH's connection just like other plugins. There are some specific parameters for OVH.
```
{
    appKey: //A key specific to wildcert. The one provided in the example is usable.
    appSecret: //A secret specific to wildcert. The one provided in the example is usable.
    consumerKey: //Following authentication of the key, you must take the consumerKey from the response then add it here. See below.
    endpoint: //There's a few different OVH endpoints which can be used depending on your locality. See the available endpoints below
}
```
OVH Endpoints
==============
The plugin uses the [OVH node project](https://github.com/ovh/node-ovh). At present the supported endpoints are as follows:

OVH Europe: ovh-eu (default)
OVH US: ovh-us
OVH North-America: ovh-ca
RunAbove: runabove-ca
SoYouStart Europe: soyoustart-eu
SoYouStart North-America: soyoustart-ca
Kimsufi Europe: kimsufi-eu
Kimsufi North-America: kimsufi-ca

Getting and Authenticating the consumerKey
==============
1. Run the following in your terminal if you reside in the EU. The URL might differ depending on your location although this is untested:
```
curl -X POST -H "Content-Type: application/json" -H "X-Ovh-Application:Nr5oddsUpxCi9IEi" -d '{"accessRules": [{"method": "GET","path": "/domain"},{"method": "GET","path": "/domain/zone/*"},{"method": "POST","path": "/domain/zone/*"},{"method": "DELETE","path": "/domain/zone/*"}]}' https://eu.api.ovh.com/1.0/auth/credential
```
2. The returned data should contain a consumerKey and validation URL. Take note of the consumer key then visit the URL in the address bar.
3. Enter your account username and password for OVH along wiht a length of time to keep that consumerKey alive for. These details will be used to access the application. The consumerKey from earlier will now be authenticated.