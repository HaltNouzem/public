function FindProxyForURL(url, host)
{

   /* Normalize the URL for pattern matching */
   url = url.toLowerCase();
   host = host.toLowerCase();






   var hostOrDomainIs = function(host, val) {
      return (host === val) || dnsDomainIs(host, '.' + val);
   };

   var hostIs = function(host, val) {
      return (host === val);
   };

   /* Don't proxy local hostnames */
   if (isPlainHostName(host))
   {
      return 'DIRECT';
   }



    /* Don't check IPv6 addresses */
   if (isResolvable(host))
   {
      var hostIP = dnsResolve(host);
      if (!shExpMatch(hostIP, "*:*"))
      {
        /* Don't proxy non-routable addresses (RFC 3330) */
        if (isInNet(hostIP, '0.0.0.0', '255.0.0.0') ||
        isInNet(hostIP, '10.0.0.0', '255.0.0.0') ||
        isInNet(hostIP, '127.0.0.0', '255.0.0.0') ||
        isInNet(hostIP, '169.254.0.0', '255.255.0.0') ||
        isInNet(hostIP, '172.16.0.0', '255.240.0.0') ||
        isInNet(hostIP, '192.0.2.0', '255.255.255.0') ||
        isInNet(hostIP, '192.88.99.0', '255.255.255.0') ||
        isInNet(hostIP, '192.168.0.0', '255.255.0.0') ||
        isInNet(hostIP, '198.18.0.0', '255.254.0.0') ||
        isInNet(hostIP, '224.0.0.0', '240.0.0.0') ||
        isInNet(hostIP, '240.0.0.0', '240.0.0.0'))
        {
           return 'DIRECT';
        }
      }
   }






   /* All other service traffic goes through proxy */
   if ( dnsDomainIs(host, "devatron.net") )
   {
      return 'PROXY proxy0-test-14vpc138067.devatron.net:6001; DIRECT';
   }



   /* List all default domains */

   if ( hostOrDomainIs(host, "netflix.com") ||
	hostOrDomainIs(host, "netflix.net") ||
	hostOrDomainIs(host, "nflximg.com") ||
	hostOrDomainIs(host, "nflximg.net") ||
	hostOrDomainIs(host, "nflxvideo.net") ||
	hostOrDomainIs(host, "nflxext.com") ||
	hostOrDomainIs(host, "nflximg.com.edgesuite.net") ||
	isInNet(host, "216.21.170.128","255.255.255.240") ||
	isInNet(host, "192.173.64.0","255.255.192.0") ||
	isInNet(host, "198.45.48.0","255.255.240.0") ||
	isInNet(host, "216.21.170.96","255.255.255.240") ||
	isInNet(host, "108.175.32.0","255.255.240.0") ||
	isInNet(host, "198.38.96.0","255.255.224.0") ||
	isInNet(host, "192.119.16.224","255.255.255.240") ||
	isInNet(host, "216.21.170.144","255.255.255.240") ||
	isInNet(host, "23.246.0.0","255.255.192.0") ||
	isInNet(host, "37.77.184.0","255.255.255.0") ||
	isInNet(host, "37.77.185.0","255.255.255.0") ||
	isInNet(host, "37.77.188.0","255.255.255.0") ||
	isInNet(host, "37.77.189.0","255.255.255.0") ||
	isInNet(host, "37.77.190.0","255.255.255.0") ||
	isInNet(host, "37.77.191.0","255.255.255.0") ||
	isInNet(host, "69.53.229.0","255.255.255.0") ||
	isInNet(host, "185.2.220.0","255.255.255.0") ||
	isInNet(host, "185.2.221.0","255.255.255.0") ||
	isInNet(host, "185.2.222.0","255.255.255.0") ||
	isInNet(host, "185.2.223.0","255.255.255.0") ||
	isInNet(host, "185.9.188.0","255.255.255.0") ||
	isInNet(host, "192.173.80.0","255.255.192.0") ||
	isInNet(host, "192.173.96.0","255.255.192.0"))
   {
      return 'DIRECT';
   }
   


   if ( hostOrDomainIs(host, "ipv6.msftconnecttest.com") ||
	hostOrDomainIs(host, "www.msftconnecttest.com"))
   {
      return 'DIRECT';
   }




   if ( url.substring(0, 6) === 'https:' )
   {
      return 'PROXY proxy0-test-14vpc138067.devatron.net:6001; DIRECT';
   }


   if ( url.substring(0, 5) === 'http:' )
   {
      return 'PROXY proxy0-test-14vpc138067.devatron.net:6001; DIRECT';
   }

   return 'DIRECT';
}
