#!/usr/bin/perl

# by Jan-Piet Mens
# 2010-02-01 initial dirty version
# 2010-02-02 continues being dirty; added NS glue and CNAMEs

use strict;

my $words = '/usr/share/dict/words';
my $ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';

my @wl = slurpwords($words);
my @cnames = (qw(google.com yahoo.de cnn.com powerdns.org isc.org nlnetlabs.nl));
my $n = 0;
my %unique;

srand (time ^ $$ ^ unpack "%L*", `ps axww | gzip -f`);

soa();

glue();

while ($n < 1000000) {

	my $domain = @wl[ int(rand($#wl)) ];

	next if defined($unique{$domain});
	$unique{$domain} = 1;

	if (!($n % 14)) {
		printf "%-40s IN CNAME  %s.\n", $domain, $cnames[ int(rand($#cnames)) ];
		$n++;
		next; # no cname and other data...
	}

	printf '%-40s IN A ', $domain;
	$,=".";
	print map int rand 256,1..4;
	print  "\n";

	printf "%-40s IN TXT \"zone %07d\"\n", "", $n;

	if (!($n % 5)) {
		printf "%-40s IN MX  10 xs.powerdns.com.\n", "";
		printf "%-40s IN AAAA  2001:1178:6bf::422:9871:1034:1fdb\n", "";
		printf "%-40s IN TXT \"%s\"\n", "", fortune();
	}

	if (!($n % 9)) {
		printf "%-40s IN LOC 37 23 30.900 N 121 59 19.000 W 7.00m 100.00m 100.00m 2.00m\n", "";
		printf "%-40s IN SSHFP 2 1 e3db90da2bbd6ef25fdb63a4e892a3cfd6e3ea50\n", "";
		printf "%-40s IN SSHFP 1 1 7bad41a65aa0c86a07900b74a3c48fb80834efa7\n", "";
	}

	if (!($n % 25)) {
		printkeys($domain);
	}

	if (!($n % 30)) {
		printcert();
	}
	
	$n++;
}

print "jp-was-here IN TXT \"end-of-file\"\n";

sub soa {
	print <<END;
\$TTL 600        ; 10 minutes
@                       IN SOA  ns.big.aa. hostmaster.big.aa. (
                                3         ; serial
                                7200       ; refresh (2 hours)
                                300        ; retry (5 minutes)
                                10800      ; expire (3 hours)
                                600        ; minimum (10 minutes)
                                )
                        NS      localhost.big.aa.
localhost.big.aa.                       A       127.0.0.1
END
}

sub slurpwords {
	my ($file) = @_;
	my @list;
	my $w;

	# add more words by pushing in -0 -1, ...
	open(WORDS, $file) or die "Can't open words at $file: $!\n";
	while (<WORDS>) {
		next unless (/^[a-z-]+$/i);
		chomp;
		$w = lc;
		push(@list, $w);
		push(@list, "$w-0");
		push(@list, "$w-1");
		push(@list, "$w-2");
		push(@list, "$w-3");
		push(@list, "$w-aa");
		push(@list, "$w-ab");
		push(@list, "$w-jp");
		push(@list, "$w-ah");
		push(@list, "$w-44");
		push(@list, "$w-54");

	}
	close(WORDS);

	return @list;
}

sub printkeys {
	my ($domain) = @_;

	print <<END;
$domain	 7200	IN KEY  512 3 3 CL4RffcIPWv3HBEl3kmxSMTjE9+rvbIxRep36OirNyONLynrrts2bUs8 u3EnMkEi6Y8niIJG2A7aHWuzerJJ3elq/QDUTUkRxZyod3aY8Fsz/dgr +kLrqdd9NY3OWgRlN+MKODIbm4TZDpcZ/zooWC+jt3HOvEBIPL+GTOeo yzycxECCnM9g6G3qCgqvFrECVI+VfjN2CPC17qUGfiVQgfRsSjLynL0t SqpihGs/rHH7fii1mQ6907sWqcmT3OJF+T50lCc5KMhuTt0/dtnLzioy QbixLKHRylrwbRHW7vgQrOzqHAXCY6O6DpW6QzJ0v6IyBouHD/Gz5L4C byAeHfjICH5yQaitmIMI6CizFGbL7fSVB64T/DwyDlpcYNuTG0GhXbDI G5CaCRcjNnOUyVdair5RQvK7LUaNwAMnupetRX9mx2TyW5MjTdKsJd47 grwrzeS4uY8TvL5N7wwAxHtaGzWq/rzlYQIVEspaPZizXplcQivZ+mE3 sRkv/UP8yzzc+g6WFmBWkleiHKIichl+zc5t
$domain	 7200 IN KEY  512 3 1 AwEAAazIX+Ywi7HM6ciZXDR4ACLW0tviuUbP6qnavvSQRaBQMURthX5h OHIdRqbRwi1uXfSpWkrL0yQAzF1H4uW17RP9/PPULNzVY256FSctOrXt 4AmMgtJeLCKxqUjmIrJceEjt+G4Ujwuwzy0fX/Nvj/V2kGMIfJ/dWNDt DcM/eTg1
END
}

sub printcert()
{
	print <<END;
	CERT 1298 0003 0000 00 9901A20439D8DAF1110400F770EC6AA006076334BEC6DB6FBB237DC194BC0AB8302C8953F04C28FC2085235D4F10EFA027234FBD63D142CCADD5213AD2B79A22C89ED9B4138370D8220D0F987F993A5364A4A7AC3D42F3765C38471DDD0FF3372E4AE6F7BEE1E18EF464A0BEB5BBE860A08238891455EBE7CB53D567E981F78ADBD263206B0493ADCB74DD00A0FF0E9A1CD245415ECEF59435162AFCE4CDD14BC70400EA38FF501256E773DEA299404854D99F4EDB2757AA911A9C77C68AB8D6622E517A556C43D21F0523C568F016CD0DB89EF435F0D53B4E07434213F899E6578955DC2C147931E7B6901C9FD8A02705417D69A879B3CC196D2AC2EAEF311192EE89ABAF5A60942167B4625735FCBDFB5DE0E3AC1236A53FA4D7CDD7D75F5DE85AF50400867D9546B28B79AF10541053CF4AB06A6171BFD21458BFD12AF1AE2B2401CAD8851661F8AF6602F80EDAC99C79616BE1F910F4156242003779C68D7A079A8B18F89DD293E1B247E7420471300A4A0730AA61DE281CCC211FC405A0A8A79877999FF9042AD892AB927DA371E8883BBB370AB7A97841408C3486BB18598CF2559BB42844616E69656C20502E204D61686F6E6579203C64616E6D407072696D652E67757368692E6F72673E884E04101102000E050239D8DAF1040B030102021901000A0910FBBE5A30624BB249FA2E009B057503ED498695AE5ED73CA1B98EBAEE13F717E500A0921E0D92724459100266FEBBC29E911C8B0F530BB43244616E69656C204D61686F6E657920285365636F6E6461727920456D61696C29203C67757368694067757368692E6F72673E8860041311020020050245D49FD7021B23060B090807030204150208030416020301021E01021780000A0910FBBE5A30624BB249158400A082C8AF43DA8B85F740D6B1A6E9FF0B4490520B8C00A08F77D21FBF86C842963E8090DC0646D1DD7F95C9B9020D0439D8DAF4100800F64257B7087F081772A2BAD6A942F305E8F95311394FB6F16EB94B3820DA01A756A314E98F4055F3D007C6CB43A994ADF74C648649F80C83BD65E917D4A1D350F8F5595FDC76524F3D3D8DDBCE99E1579259CDFDB8AE744FC5FC76BC83C5473061CE7CC966FF15F9BBFD915EC701AAD35B9E8DA0A5723AD41AF0BF4600582BE5F488FD584E49DBCD20B49DE49107366B336C380D451D0F7C88B31C7C5B2D8EF6F3C923C043F0A55B188D8EBB558CB85D38D334FD7C175743A31D186CDE33212CB52AFF3CE1B1294018118D7C84A70A72D686C40319C807297ACA950CD9969FABD00A509B0246D3083D66A45D419F9C7CBD894B221926BAABA25EC355E9320B3B00020207FF5E1A3CC5DA00E1E94EC8EF6C7FE9B49D944C71D8BBC817DD8E64A7344B9E48392E0B833B3B1DB7E6D5A38BE2826DEF0060F78C6417871EAF1CFBCBC47D27E93718D975E0A3A36D868C021D6B771740CE2918307D69D614BBF0632DC31932EA31397A7F3B04618C9A76C2F38265C7037E303EDD8AEF03D069208E3FE9C4EA77D83E6311ED36C013D58C54E914B263A459E22D463A0288510C4752B99C163EEA0A55686979691AB0D9F9AA0C06C834446D7A723EC534D819301382621ACF8930C74E9FD28C8797718AEC2C30CF601E24194B799234104A3D6239657B1D4AD545BDAA637F61541435CB51B4D138FBF55E1A9FD2EED860E4459D6795B6FCCA23155A8846041811020006050239D8DAF4000A0910FBBE5A30624BB249415A009E37BCFDC64E76CBF6A8682B85EA161BD1DFB793DF00A0C471BC7B9723535CD855D8FF1EB93F01E251B698
END
}

sub fortune {
	# http://fortunes.pbworks.com/w/page/14107107/computers
	my @list = (
'A formal parsing algorithm should not always be used.',
'A Fortran compiler is the hobgoblin of little minis.',
'A hacker does for love what others would not do for money.',
'A language that doesnt affect the way you think about programming is not worth knowing.',
'A rolling disk gathers no MOS.',
'A sheet of paper crossed my desk the other day and as I read it',
'JCL support as alternative to system menu.',
	);

	return $list[ int(rand($#list)) ];
}

sub glue {
	print <<ENDGLUE;
rootae.ns			IN 	A	198.41.0.4
rootaf.ns			IN 	A	198.41.0.4
rootar.ns			IN 	AAAA	2001:503:ba3e::2:30
rootbe.ns			IN 	A	192.228.79.201
rootbg.ns			IN 	A	192.33.4.12
rootbj.ns			IN 	A	128.8.10.90
rootca.ns			IN 	A	192.203.230.10
rootch.ns			IN 	A	192.5.5.241
rootcl.ns			IN 	AAAA	2001:500:2f::f
rootcn.ns			IN 	A	192.112.36.4
rootco.ns			IN 	A	128.63.2.53
rootcr.ns			IN 	A	198.41.0.4
rootde.ns			IN 	A	198.41.0.4
rootdj.ns			IN 	A	198.41.0.4
rootdk.ns			IN 	AAAA	2001:503:ba3e::2:30
rootdo.ns			IN 	A	192.228.79.201
rootee.ns			IN 	A	192.33.4.12
rootes.ns			IN 	A	128.8.10.90
rootet.ns			IN 	A	192.203.230.10
rooteu.ns			IN 	A	192.5.5.241
rootfi.ns			IN 	AAAA	2001:500:2f::f
rootfr.ns			IN 	A	192.112.36.4
rootgr.ns			IN 	A	128.63.2.53
roothu.ns			IN 	A	192.36.148.17
rootid.ns			IN 	A	192.58.128.30
rootie.ns			IN 	A	193.0.14.129
rootil.ns			IN 	AAAA	2001:7fd::1
rootin.ns			IN 	A	199.7.83.42
rootiq.ns			IN 	AAAA	2001:503:ba3e::2:30
rootis.ns			IN 	A	192.228.79.201
rootit.ns			IN 	A	192.33.4.12
rootjp.ns			IN 	A	128.8.10.90
rootkr.ns			IN 	A	192.203.230.10
rootkw.ns			IN 	A	192.5.5.241
rootla.ns			IN 	AAAA	2001:500:2f::f
rootlb.ns			IN 	A	192.112.36.4
rootlt.ns			IN 	A	128.63.2.53
rootlu.ns			IN 	A	192.36.148.17
rootlv.ns			IN 	A	192.58.128.30
rootly.ns			IN 	A	193.0.14.129
rootmg.ns			IN 	AAAA	2001:7fd::1
rootmx.ns			IN 	A	199.7.83.42
rootmy.ns			IN 	AAAA	2001:503:ba3e::2:30
rootne.ns			IN 	A	192.228.79.201
rootng.ns			IN 	A	192.33.4.12
rootni.ns			IN 	A	128.8.10.90
rootnl.ns			IN 	A	192.203.230.10
rootno.ns			IN 	A	192.5.5.241
rootpa.ns			IN 	AAAA	2001:500:2f::f
rootpe.ns			IN 	A	192.112.36.4
rootph.ns			IN 	A	128.63.2.53
rootpk.ns			IN 	A	192.36.148.17
rootpl.ns			IN 	A	192.58.128.30
rootpr.ns			IN 	A	193.0.14.129
rootps.ns			IN 	AAAA	2001:7fd::1
rootqa.ns			IN 	A	199.7.83.42
rootro.ns			IN 	A	192.36.148.17
rootru.ns			IN 	A	192.58.128.30
rootrw.ns			IN 	A	193.0.14.129
rootsa.ns			IN 	AAAA	2001:7fd::1
rootsd.ns			IN 	A	199.7.83.42
rootse.ns			IN 	AAAA	2001:503:ba3e::2:30
rootsg.ns			IN 	A	192.228.79.201
rootsl.ns			IN 	A	192.33.4.12
rootsn.ns			IN 	A	128.8.10.90
rootso.ns			IN 	A	192.203.230.10
rootsr.ns			IN 	A	192.5.5.241
roottd.ns			IN 	AAAA	2001:500:2f::f
rootth.ns			IN 	A	192.112.36.4
roottl.ns			IN 	A	128.63.2.53
roottn.ns			IN 	A	192.36.148.17
roottr.ns			IN 	A	192.58.128.30
roottw.ns			IN 	A	193.0.14.129
rootua.ns			IN 	AAAA	2001:7fd::1
rootug.ns			IN 	A	199.7.83.42
rootuk.ns			IN 	A	198.41.0.4
rootun.ns			IN 	AAAA	2001:503:ba3e::2:30
rootus.ns			IN 	A	192.228.79.201
rootuy.ns			IN 	A	192.33.4.12
rootve.ns			IN 	A	128.8.10.90
rootvn.ns			IN 	A	192.203.230.10
rootws.ns			IN 	A	192.5.5.241
rootye.ns			IN 	AAAA	2001:500:2f::f
ae.ns			IN	NS	rootae.ns
af.ns			IN	NS	rootaf.ns
ar.ns			IN	NS	rootar.ns
be.ns			IN	NS	rootbe.ns
bg.ns			IN	NS	rootbg.ns
bj.ns			IN	NS	rootbj.ns
ca.ns			IN	NS	rootca.ns
ch.ns			IN	NS	rootch.ns
cl.ns			IN	NS	rootcl.ns
cn.ns			IN	NS	rootcn.ns
co.ns			IN	NS	rootco.ns
cr.ns			IN	NS	rootcr.ns
de.ns			IN	NS	rootde.ns
dj.ns			IN	NS	rootdj.ns
dk.ns			IN	NS	rootdk.ns
do.ns			IN	NS	rootdo.ns
ee.ns			IN	NS	rootee.ns
es.ns			IN	NS	rootes.ns
et.ns			IN	NS	rootet.ns
eu.ns			IN	NS	rooteu.ns
fi.ns			IN	NS	rootfi.ns
fr.ns			IN	NS	rootfr.ns
gr.ns			IN	NS	rootgr.ns
hu.ns			IN	NS	roothu.ns
id.ns			IN	NS	rootid.ns
ie.ns			IN	NS	rootie.ns
il.ns			IN	NS	rootil.ns
in.ns			IN	NS	rootin.ns
iq.ns			IN	NS	rootiq.ns
is.ns			IN	NS	rootis.ns
it.ns			IN	NS	rootit.ns
jp.ns			IN	NS	rootjp.ns
kr.ns			IN	NS	rootkr.ns
kw.ns			IN	NS	rootkw.ns
la.ns			IN	NS	rootla.ns
lb.ns			IN	NS	rootlb.ns
lt.ns			IN	NS	rootlt.ns
lu.ns			IN	NS	rootlu.ns
lv.ns			IN	NS	rootlv.ns
ly.ns			IN	NS	rootly.ns
mg.ns			IN	NS	rootmg.ns
mx.ns			IN	NS	rootmx.ns
my.ns			IN	NS	rootmy.ns
ne.ns			IN	NS	rootne.ns
ng.ns			IN	NS	rootng.ns
ni.ns			IN	NS	rootni.ns
nl.ns			IN	NS	rootnl.ns
no.ns			IN	NS	rootno.ns
pa.ns			IN	NS	rootpa.ns
pe.ns			IN	NS	rootpe.ns
ph.ns			IN	NS	rootph.ns
pk.ns			IN	NS	rootpk.ns
pl.ns			IN	NS	rootpl.ns
pr.ns			IN	NS	rootpr.ns
ps.ns			IN	NS	rootps.ns
qa.ns			IN	NS	rootqa.ns
ro.ns			IN	NS	rootro.ns
ru.ns			IN	NS	rootru.ns
rw.ns			IN	NS	rootrw.ns
sa.ns			IN	NS	rootsa.ns
sd.ns			IN	NS	rootsd.ns
se.ns			IN	NS	rootse.ns
sg.ns			IN	NS	rootsg.ns
sl.ns			IN	NS	rootsl.ns
sn.ns			IN	NS	rootsn.ns
so.ns			IN	NS	rootso.ns
sr.ns			IN	NS	rootsr.ns
td.ns			IN	NS	roottd.ns
th.ns			IN	NS	rootth.ns
tl.ns			IN	NS	roottl.ns
tn.ns			IN	NS	roottn.ns
tr.ns			IN	NS	roottr.ns
tw.ns			IN	NS	roottw.ns
ua.ns			IN	NS	rootua.ns
ug.ns			IN	NS	rootug.ns
uk.ns			IN	NS	rootuk.ns
un.ns			IN	NS	rootun.ns
us.ns			IN	NS	rootus.ns
uy.ns			IN	NS	rootuy.ns
ve.ns			IN	NS	rootve.ns
vn.ns			IN	NS	rootvn.ns
ws.ns			IN	NS	rootws.ns
ye.ns			IN	NS	rootye.ns
ENDGLUE
}
