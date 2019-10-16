WildCert
========

WildCert is a wrapper for [Greenlock](https://git.coolaj86.com/coolaj86/greenlock.js) that supports the automatic requesting of wilcard certificates from LetsEncrypt by automatically updating DNS and using the DNS authorisation challenge.

Greenlock / Acme.js Warning
===========================
Let’s Encrypt will STOP WORKING with Greenlock and ACME.js at the end of Oct 2019. WITHOUT YOUR HELP we won’t get the next release out in time.

If Greenlock (or ACME.js) has saved you time and money, and taken stress out of your life, or you just love it, please reach out to return the favor today:

SAVE GREENLOCK / ACME.js: [https://indiegogo.com/at/greenlock](https://indiegogo.com/at/greenlock)

It is unclear at this time if the breaking changes will effect Wildcert.

Prerequisites
=============

- Node.JS v8.x or above with NPM
- Only Linux is supported at this time. Not tested on MacOS/BSD

Installation
============

To install WildCert simply run the following command on your server:

`$ sudo npm install -g wildcert`

DNS Plugins
===========

The following providers are supported for automatic DNS updates. You will likely need to generate API keys in order to use one of these plugins. 
- Godaddy : [Example](https://github.com/spuddleziz/wildcert/blob/master/examples/godaddy.json)
- OVH : [Example](https://github.com/spuddleziz/wildcert/blob/master/examples/ovh.json)

Server Plugins
==============

After a successful certificate gernation/renewal WildCert can reload the web server for you.

At the moment only HaProxy is supported support for Nginx and Apache is planned. 

Configuration Files
===================

```
{
  "domains": ["*.example.com", "*.foo.com"], 
  //request multiple wilcard certificates in one request on one certificate. 
  //Both domains must be managed by the same DNS provider.
  
  "email": "someone@domain.com", //email used for renewal emails sent from LetsEncrypt
  
  "expiryThreshold": 5, //the number of days before actual certificate expiry when the renewal should occur
  
  //  GREENLOCK CONFIGURATION
  "greenlock": {
  
    "production": true, //set to false to use the staging API for testing.
    
    "rsaKeySize": 2048, //keysize for certificate must be 2048 or larger and a multiple of 512 e.g 2048, 4096, 2560
    
    // The Greenlock store configuration... le-store-certbot is installed for you but any store plugin can be used. 
    //Search NPM for le-store for other available plugins.
    "store": {
    
      "plugin": "le-store-certbot", //the node.js plugin to use...
    
      // PLUGIN CONFIGURATION
      "config": {
        "debug": false,
        "configDir": "/etc/letsencrypt"   //the directory to store the LetsEncrypt data
      }
    
    },
    
    //When requesting wildcard certificates one can only use the DNS challenge. 
    //Wildcert work by intercepting the LetsEncrypt response and updating DNS using the configured plugin.
    //Search NPM for le-challenge to use other plugins for any type of challenge
    "challenges": {
      "dns-01": "wildcert"  //Setting this to wildcert allows WildCert to intercept the DNS challenge response
    },
    "debug": false
    
  },
  "dns": {
    "plugin": "godaddy",  //The DNS Update Plugin to use...
    "config": {
       "apikey": "", //The GoDaddy API key
       "secret": ""  //The GoDaddy API Secret
    },
    "setIP": true, //if set the DNS plugin will automatically set the A and AAAA records for the appropriate domains
    "ip4List": [/*An array of IPV4 addresses to set*/],
    "ip6List": [/*An array of IPV6 addresses to set*/]
  },
  "server": {
    "plugin": "haproxy",  //The WildCert webserver management plugin to use 
    "config": {
      "certpath": "/etc/haproxy/certs/fullchain.pem", 
      //haproxy requires a full chain style certificate file. 
      // This is the path wheere that key will be written to.
      
      "reload": true 
      //Setting this to true will issue a systemctl reload haproxy.service
      //    after the certificate has been successfuly written to the above path.
    
    }
  }
}
```


Using WildCert
==============

1. Create a configuration file and save it somewhere. E.g. /etc/wildcert/example.com.json
2. Run `$ sudo wildcert /etc/wildcert/example.com.json` to request your certificate.
3. Run `$ sudo nano /etc/cron.daily/wildcert`
4. Create the Daily Cron file like below:
```bash
#!/bin/sh

wildcert /etc/wildcert/example.com.json
```

Now wildcert will run daily and check to see if the threshold set in the configuration file has been reached and renew the certificate.

It is possible to have multiple WildCert configuration files, if you do just add all the renewals you wish to happen to this cron file.

LICENSE
=======

Please see package.json for included modules and see NPM or the Source for the Licenses for those included modules.

Dual-licensed MIT and Apache-2.0

See LICENSE
