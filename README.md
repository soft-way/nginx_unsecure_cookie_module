The Nginx module for removing "Secure" cookie flag
==========

[![License](http://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/Airis777/nginx_cookie_flag_module/blob/master/LICENSE)

The Nginx module for removing "Secure" cookie flag

## Dependencies
* [nginx](http://nginx.org)

## Compatibility
* 1.11.x (last tested: 1.11.2)

Earlier versions is not tested.

## Installation

1. Clone the git repository.

  ```
  git clone git@github.com:yumauri/nginx_unsecure_cookie_module.git
  ```

2. Add the module to the build configuration by adding
  `--add-module=/path/to/nginx_unsecure_cookie_module`
   or
  `--add-dynamic-module=/path/to/nginx_unsecure_cookie_module`

3. Build the nginx binary.

4. Install the nginx binary.

## Synopsis

```Nginx
location / {
    unsecure_cookie Secret;
    unsecure_cookie *;
    unsecure_cookie SessionID;
    unsecure_cookie SiteToken;
}
```

## Description
This module for Nginx removes flag "**Secure**" from cookies in the "*Set-Cookie*" upstream response headers.
It is possible to set a default value using symbol "*". In this case "Secure" flag will be removed from all cookies.

## Directives

### unsecure_cookie

-| -
--- | ---
**Syntax**  | **unsecure_cookie** \<cookie_name\|*\>;
**Default** | -
**Context** | server, location

Description: Removes "Secure" flag from desired cookie.

## Docker

If you want to have Docker image with this module, you can take [this snippet](https://gist.github.com/yumauri/2c93e727ee15f32529da351b030e1190) as starting point.<br>
Or, take [this Docker image](https://hub.docker.com/r/boly38/unginx), made by [Brice Vandeputte](https://github.com/boly38), at your own risk.

## Author

Author of original module [nginx_cookie_flag_module](https://github.com/AirisX/nginx_cookie_flag_module) is<br>
Anton Saraykin [<Airisenator@gmail.com>]

I just put my dirty hands on his code :)
