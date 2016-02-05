mod_url for Apache & lighttpd module
==========

mod_url rewrites uri that fix mismatched URL encoding between server and client.


## License

 * For apache modules, GPL2
 * For lighttpd modules, BSD 2-clause

## Compatibility

 * apache 1.3
 * apache 2
 * lighttpd
 * nginx use vozlts/nginx-module-url#1

## Installation

  * For Apache
  
    ```Shell
    shell> apxs -i -c mod_url.c
    ```
  * For lighttpd
  
    See also [README](https://github.com/Joungkyun/mod_url/blob/master/lighttpd/README) of lighttpd mod_url directory
