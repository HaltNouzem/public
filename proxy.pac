// IWSVA pac file

function islocalip(ip) {
	return isInNet(ip, "127.0.0.0", "255.0.0.0") ||
        isInNet(ip, "10.0.0.0", "255.0.0.0") ||
        isInNet(ip, "169.254.0.0", "255.255.0.0") ||
        isInNet(ip, "172.16.0.0", "255.240.0.0") ||
        isInNet(ip, "192.168.0.0", "255.255.0.0");
}

function FindProxyForURL(url, host) 
{

    var ml_proxy = "PROXY proxy-rc-2890-b.surfcrew.com:6001; DIRECT";
    var target_ip = dnsResolve(host);

    if (islocalip(target_ip)) { return 'DIRECT'; } 
    if (isPlainHostName(host)) { return 'DIRECT'; }
    if (dnsDomainIs(host, "m1adfs.m1.com.sg") ||
        dnsDomainIs(host, "mivpn.m1.com.sg")) 
		{
		return 'DIRECT';
		}
		// IP and Domain  Bypassing Segment to Direct
	if (isInNet(host, "13.107.64.0", "255.255.192.0") ||        //Team subnet Bypass
		isInNet(host, "52.112.0.0", "255.252.0.0") ||			//Team subnet Bypass
		isInNet(host, "52.120.0.0", "255.252.0.0") ||			//Team subnet Bypass
		isInNet(host, "18.136.62.233", "255.255.255.255") ||		//Amazon CCP
		isInNet(host, "52.76.249.216", "255.255.255.255") ||		//Amazon CCP
		isInNet(host, "143.204.253.179", "255.255.255.255") ||	//Amazon CCP
		isInNet(host, "143.204.253.114", "255.255.255.255") ||	//Amazon CCP
		isInNet(host, "143.204.253.192", "255.255.255.255") ||	//Amazon CCP
		isInNet(host, "143.204.253.82", "255.255.255.255") ||	//Amazon CCP
		isInNet(host, "101.127.192.170", "255.255.255.255") ||
        isInNet(host, "119.73.168.219", "255.255.255.0") ||
        isInNet(host, "124.155.212.7", "255.255.255.0") ||
        isInNet(host, "129.126.134.55", "255.255.255.0") ||
        isInNet(host, "195.190.8.39", "255.255.255.0") ||
        isInNet(host, "195.190.8.40", "255.255.255.0") ||
        isInNet(host, "203.125.245.122", "255.255.255.0") ||
	isInNet(host, "49.128.58.76", "255.255.255.255") ||
        dnsDomainIs(host, "sslvpn.m1remit.com.sg") ||
	dnsDomainIs(host, "sm-v4-030-a-gtm.pr.go-esim.com") ||
 	dnsDomainIs(host, "sm-v4-030-ppa-gtm.pr.go-esim.com") ||
        dnsDomainIs(host, "vault.capitaland.com.sg") ||
        dnsDomainIs(host, "sdp.mobileone.net.sg") ||	 		
	  dnsDomainIs(host, "m1uat-bluesky.m1.com.sg") ||
        dnsDomainIs(host, "loginuat.m1.com.sg") ||
        dnsDomainIs(host, "m1.thoughtspot.cloud") ||
	  dnsDomainIs(host, "www.tcbs.com.sg") ||
	  dnsDomainIs(host, "m1limited.us-4.evergage.com") ||
	  dnsDomainIs(host, "kms.m1.com.sg") ||
        shExpMatch(host, "*keppel-prod.custhelp.com") ||
        dnsDomainIs(host, "pasprdirtew02.m1.csg-carrier.com") ||
        dnsDomainIs(host, "route.m1.csg-carrier.com") ||
            dnsDomainIs(host, "m2mportal.m1net.com.sg") ||
            dnsDomainIs(host, "ipv6.msftconnecttest.com") ||
            dnsDomainIs(host, "www.msftconnecttest.com"))
    {
        return 'DIRECT';
    }
    
    if (url.substring(0, 5) == 'http:') {return ml_proxy; }
    if (url.substring(0, 6) == 'https:') {return ml_proxy; }
    if (url.substring(0, 4) == 'wss:') {return ml_proxy; }

}
