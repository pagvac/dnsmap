# dnsmap, a simple subdomain bruteforcer

This is the project page of the new version of dnsmap which has been ported from C to python by its original author. The [old version](https://github.com/resurrecting-open-source-projects/dnsmap) should no longer be used.

See an example command below. Yup, it's that simple! 😜

dnsmap intentionally ships without command-line flags. The goal is to keep the
tool approachable for OSINT newcomers who just need a single command that works
out of the box—no option hunting, no prerequisite tuning.

Run it against any domain:

```
$ python3 dnsmap.py github.com
dnsmap 0.40 - DNS Network Mapper by github.com/pagvac
   0% [----------------------------------------------------------------------------] 0/130191 | found:0 |   0.0/s | eta:[info] scrape anubis yielded 109 labels, of which 66 are new
   3% [##-------------------------------------------------------------------] 5007/130191 | found:0 | 1509.5/s | eta:1m2[info] scrape hackertarget yielded 0 labels, of which 0 are new
   7% [#####-----------------------------------------------------------------] 10014/130191 | found:0 | 2189.7/s | eta:5[info] scrape crtsh yielded 0 labels, of which 0 are new
  23% [###############------------------------------------------------------] 30048/130225 | found:0 | 505.6/s | eta:3m1[info] scraping sources yielded 665 labels, of which 560 are new
  23% [###############------------------------------------------------------] 30216/130951 | found:0 | 508.4/s | eta:3m1[info] brute-force target count: 100735 (+28 from scraping)
  99% [#####################################################################-] 130770/130951 | found:43 | 665.8/s | eta:[tune] conc=179 p90=50ms success=212% timeouts=689% samples=1000 q=96078 timeout=0.5s
  99% [#####################################################################-] 130946/130951 | found:44 | 660.0/s | eta:[tune] conc=125 p90=1103ms success=10892% timeouts=9256% samples=1000 q=0 timeout=1.7s
 100% [######################################################################] 130951/130951 | found:44 | 659.9/s | eta:
ns2.github.com
slack.github.com
forms.github.com
unity.github.com
github.github.com
services.github.com
docs.github.com
pages.github.com
brand.github.com
desktop.github.com
learn.github.com
central.github.com
emails.github.com
cs.github.com
info.github.com
og.github.com
lfs.github.com
windows.github.com
skyline.github.com
partner.github.com
garage.github.com
action.github.com
brasil.github.com
galaxy.github.com
government.github.com
status.github.com
developer.github.com
campus.github.com
resources.github.com
next.github.com
community.github.com
uploads.github.com
universe.github.com
guides.github.com
shop.github.com
enterprise.github.com
insights.github.com
atom-installer.github.com
gist.github.com
graphql.github.com
codeql.github.com
securitylab.github.com
maintainers.github.com
cli.github.com
[stats] duration=198.43s attempted=100735 found=44 scrape_found=10 avg_per_sec=507.67
```

The progress bar, tuning messages, and scrape/AI telemetry all stay on stderr.
Only the confirmed subdomains land on stdout, so redirecting the output gives a
clean list ready for whatever tooling you use next:

```
$ python3 dnsmap.py example.com > subs.txt
```

Because the file only receives enumerated subdomains, you can feed it directly
into resolvers, HTTP fuzzers, or additional OSINT pipelines without extra
filtering.
