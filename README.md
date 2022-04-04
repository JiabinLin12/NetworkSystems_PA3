# NetworkSystems_PA3 - Proxy Server

## 
  * Implement a proxy server that connects the HTTP server and client
  * Acts as a relay to forward, cache, filter, and prefetching information
  * Main Funtionality:
    * Relay http packets
    * Cache HTTP packets and set timeout for cached information
    * DNS cache
    * Blacklist website
    * Link Prefetch
 * Useage: 
    * run ```make``` to build the file
    * by default make also run the program ```./webproxy 8888 60``` where 8888 is port number and 60 is the number of second the program is timeouted
    * Adding a blacklist:
      * open ```blacklist``` file and insert the website in the next line       
