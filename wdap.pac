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
   if ( dnsDomainIs(host, "menlosecurity.com") )
   {
      return 'PROXY safeview-3dnhg195499.devatron.net:3129; PROXY safeview-3dnhg195499.devatron.net:3129; DIRECT';
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
   


   if ( hostOrDomainIs(host, "eperformax-messaging.azurewebsites.net") ||
	hostOrDomainIs(host, "res.cloudinary.com") ||
	hostOrDomainIs(host, "ps8.pndsn.com") ||
	hostOrDomainIs(host, "kustomer-appcues.s3.amazonaws.com") ||
	hostOrDomainIs(host, "viomes.kustomerapp.com") ||
	hostOrDomainIs(host, "buy.viome.com") ||
	hostOrDomainIs(host, "openai.com") ||
	hostOrDomainIs(host, "kustomerapp.com") ||
	hostOrDomainIs(host, "viome.api.kustomerapp.com") ||
	hostOrDomainIs(host, "viome.kustomerapp.com") ||
	hostOrDomainIs(host, "viomecx.my.connect.aws") ||
	hostOrDomainIs(host, "app.getsentry.com") ||
	hostOrDomainIs(host, "s3.amazonaws.com") ||
	hostOrDomainIs(host, "awsapps.com") ||
	hostOrDomainIs(host, "connect.aws") ||
	hostOrDomainIs(host, "eperformax.com") ||
	hostOrDomainIs(host, "eperformax.certpointsystems.com") ||
	hostOrDomainIs(host, "rum.browser-intake-datadoghq.com") ||
	hostOrDomainIs(host, "www.datadoghq-browser-agent.com") ||
	hostOrDomainIs(host, "cdn.statuspage.io") ||
	hostOrDomainIs(host, "cdnappcues.kustomerapp.com") ||
	hostOrDomainIs(host, "app.getbeamer.com") ||
	hostOrDomainIs(host, "o185886.ingest.sentry.io") ||
	hostOrDomainIs(host, "cdnapps.kustomerapp.com") ||
	hostOrDomainIs(host, "lhn2sb4njk08.statuspage.io") ||
	hostOrDomainIs(host, "cdn.segment.com") ||
	hostOrDomainIs(host, "cdn.heapanalytics.com") ||
	hostOrDomainIs(host, "app.launchdarkly.com") ||
	hostOrDomainIs(host, "heapanalytics.com") ||
	hostOrDomainIs(host, "api.segment.io") ||
	hostOrDomainIs(host, "backend.getbeamer.com") ||
	hostOrDomainIs(host, "push.getbeamer.com") ||
	hostOrDomainIs(host, "realtime.getbeamer.com") ||
	hostOrDomainIs(host, "ps9.pndsn.com") ||
	hostOrDomainIs(host, "ps10.pndsn.com") ||
	hostOrDomainIs(host, "events.launchdarkly.com") ||
	hostOrDomainIs(host, "ps.pndsn.com") ||
	hostOrDomainIs(host, "kustomer.pubnubapi.com") ||
	hostOrDomainIs(host, "ps14.pndsn.com"))
   {
      return 'DIRECT';
   }




   if ( url.substring(0, 6) === 'https:' )
   {
      return 'PROXY safeview-3dnhg195499.devatron.net:3129; PROXY safeview-3dnhg195499.devatron.net:3129; DIRECT';
   }


   if ( url.substring(0, 5) === 'http:' )
   {
      return 'PROXY safeview-3dnhg195499.devatron.net:3129; PROXY safeview-3dnhg195499.devatron.net:3129; DIRECT';
   }

   return 'DIRECT';
}
